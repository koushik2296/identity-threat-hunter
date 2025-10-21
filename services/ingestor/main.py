from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
from typing import Dict, Any, List
import os
import json
import logging

from elasticsearch import Elasticsearch  # catch generic Exception on errors

app = FastAPI()
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ith-ingestor")

# --------------------
# Config (env vars)
# --------------------
ES_URL = os.environ.get("ELASTIC_CLOUD_URL")
ES_API_KEY = os.environ.get("ELASTIC_API_KEY")
INDEX = os.environ.get("ELASTIC_INDEX", "ith-events")

VERTEX_LOCATION = os.environ.get("VERTEX_LOCATION", "us-central1")
VERTEX_MODEL = os.environ.get("VERTEX_MODEL", "gemini-1.5-pro")
GCP_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT")  # auto-set on Cloud Run

if not ES_URL or not ES_API_KEY:
    raise RuntimeError("Set ELASTIC_CLOUD_URL and ELASTIC_API_KEY in the environment")

# Accept both encoded key and id:key format
if ":" in ES_API_KEY:
    ak_id, ak_key = ES_API_KEY.split(":", 1)
    es = Elasticsearch(ES_URL, api_key=(ak_id, ak_key), verify_certs=True)
else:
    es = Elasticsearch(ES_URL, api_key=ES_API_KEY, verify_certs=True)

# --------------------
# Health
# --------------------
@app.get("/_healthz")
def health():
    return {
        "ok": True,
        "index": INDEX,
        "vertex_model": VERTEX_MODEL,
        "vertex_location": VERTEX_LOCATION,
    }

# --------------------
# Light risk heuristics
# --------------------
_last_login: Dict[str, Dict[str, Any]] = {}
_failures: Dict[str, List[datetime]] = {}
_ip_to_users: Dict[str, List[tuple]] = {}

def _safe_float(v):
    try:
        return float(v) if v is not None else None
    except Exception:
        return None

def _ts(s: str) -> datetime:
    if not s:
        return datetime.utcnow()
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))

def haversine(lat1, lon1, lat2, lon2):
    from math import radians, sin, cos, asin, sqrt
    R = 6371.0
    phi1, phi2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi/2)**2 + cos(phi1) * cos(phi2) * sin(dlambda/2)**2
    return 2 * R * asin(sqrt(a))

def compute_risk(user_id: str, ev: Dict[str, Any]) -> (float, str):
    score, reasons = 0.0, []
    ts = _ts(ev.get("@timestamp"))
    event = ev.get("event", {})
    src = ev.get("source", {}) or ev.get("src", {})
    prev = _last_login.get(user_id)

    if event.get("action") == "login":
        lat = (src.get("geo") or {}).get("lat")
        lon = (src.get("geo") or {}).get("lon")
        asn = src.get("asn")
        ip = src.get("ip")

        # impossible travel
        if prev and prev.get("lat") is not None and lat is not None:
            try:
                dist = haversine(prev["lat"], prev["lon"], float(lat), float(lon))
                dt_h = (ts - prev["ts"]).total_seconds() / 3600.0
                if dt_h > 0 and dist / dt_h > 900:
                    score += 0.7; reasons.append("impossible_travel")
            except Exception:
                pass

        # ASN change
        if prev and prev.get("asn") and asn and prev["asn"] != asn:
            score += 0.3; reasons.append("asn_change")

        # MFA bypass (recent no-MFA after MFA)
        if prev and prev.get("mfa") and not event.get("mfa", False):
            if (ts - prev["ts"]) <= timedelta(hours=1):
                score += 0.5; reasons.append("mfa_bypass")

        # brute force (>=10 fails in 5m)
        if event.get("outcome") == "failure":
            _failures.setdefault(user_id, []).append(ts)
            _failures[user_id] = [t for t in _failures[user_id] if ts - t <= timedelta(minutes=5)]
            if len(_failures[user_id]) >= 10:
                score += 0.6; reasons.append("brute_force")
        else:
            _failures[user_id] = []

        # credential stuffing (>=10 distinct users from same IP in 5m)
        if ip:
            _ip_to_users.setdefault(ip, []).append((user_id, ts))
            _ip_to_users[ip] = [(u, t) for (u, t) in _ip_to_users[ip] if ts - t <= timedelta(minutes=5)]
            uniq = len(set(u for (u, _) in _ip_to_users[ip]))
            if uniq >= 10:
                score += 0.7; reasons.append("credential_stuffing")

        _last_login[user_id] = {
            "ts": ts, "lat": _safe_float(lat), "lon": _safe_float(lon),
            "asn": asn, "mfa": event.get("mfa", False)
        }

    # privilege escalation
    if event.get("action") == "role_change" and event.get("new_role") == "admin":
        score += 1.0; reasons.append("privilege_escalation")

    score = max(0.0, min(1.0, score))
    return score, (";".join(reasons) if reasons else "none")

# --------------------
# Vertex AI enrichment (lazy import to avoid startup crashes)
# --------------------
def enrich_with_ai(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Non-blocking enrichment with Vertex AI (Gemini).
    Lazy-imports vertexai so the app always starts; if enrichment fails,
    we still index the doc with ai.enriched=False and ai.error set.
    """
    try:
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        location = os.environ.get("VERTEX_LOCATION", "us-central1")
        model_name = os.environ.get("VERTEX_MODEL", "gemini-1.5-pro")
        if not project:
            raise RuntimeError("GOOGLE_CLOUD_PROJECT not set (Cloud Run sets this)")

        # --- Lazy import, and support both new/old import paths ---
        try:
            import vertexai
            try:
                from vertexai.generative_models import GenerativeModel
            except Exception:
                from vertexai.preview.generative_models import GenerativeModel
        except Exception as imp_err:
            raise RuntimeError(f"vertexai import failed: {imp_err}")

        vertexai.init(project=project, location=location)
        model = GenerativeModel(model_name)

        event_copy = {k: v for k, v in doc.items() if k != "@timestamp"}
        prompt = (
            "You are a SOC analyst. Summarize the risk in one short sentence and name a scenario. "
            "Return JSON with keys: summary (string), confidence (0-1), scenario (string). "
            f"Event: {json.dumps(event_copy, default=str)[:4000]}"
        )

        resp = model.generate_content(prompt)
        text = (getattr(resp, "text", None) or "").strip()

        summary, confidence, scenario = text, 0.9, "ai_enriched"
        try:
            obj = json.loads(text)
            summary = obj.get("summary", summary)
            confidence = float(obj.get("confidence", confidence))
            scenario = obj.get("scenario", scenario)
        except Exception:
            pass

        doc["ai.enriched"] = True
        doc["ai.summary"] = summary[:2000]
        doc["ai.confidence"] = max(0.0, min(1.0, confidence))
        doc.setdefault("event", {})["scenario"] = scenario
        doc["rule.explanation"] = doc["ai.summary"]

    except Exception as e:
        doc["ai.enriched"] = False
        doc["ai.error"] = str(e)
    return doc

# --------------------
# API
# --------------------
@app.post("/ingest")
async def ingest(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    events = payload if isinstance(payload, list) else [payload]
    results = []

    for ev in events:
        user_id = (ev.get("user") or {}).get("id") or (ev.get("user") or {}).get("name") or "unknown"

        # compute simple risk & reasons (kept from prior behavior)
        score, reasons = compute_risk(user_id, ev)
        ev.setdefault("event", {})
        ev["event"]["risk_score"] = score
        ev["event"]["explanation"] = reasons

        # --- AI enrichment right before indexing ---
        ev = enrich_with_ai(ev)

        # index to Elastic
        try:
            res = es.index(index=INDEX, document=ev)
            results.append({"user": user_id, "risk": score, "ai": bool(ev.get("ai.enriched")), "ok": True, "es": res})
        except Exception as ex:
            log.error("Elasticsearch index error: %s", ex)
            results.append({"user": user_id, "error": str(ex), "ok": False})

    return {"status": "ok", "results": results}
