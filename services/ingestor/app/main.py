import os, json, re, logging, httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ingestor")

def env(*names, default=None):
    for n in names:
        v = os.getenv(n)
        if v not in (None, ""):
            return v
    return default

ELASTIC_URL     = env("ELASTIC_URL", "ELASTIC_CLOUD_URL")
ELASTIC_API_KEY = env("ELASTIC_API_KEY", "ELASTIC_CLOUD_API_KEY")
INDEX_EVENTS    = env("ELASTIC_INDEX_EVENTS", "ELASTIC_INDEX", default="ith-events")
INDEX_QG        = env("ELASTIC_INDEX_QG", "QES_INDEX_NAME", default="quantum-guardian")
DUAL_WRITE      = env("QES_DUAL_WRITE", default="true").lower() == "true"

VERTEX_MODEL    = env("VERTEX_MODEL", default="publishers/google/models/gemini-2.5-flash")
VERTEX_LOCATION = env("VERTEX_LOCATION", default="us-east4")
GCP_PROJECT     = env("GCP_PROJECT", default="ith-koushik-hackathon")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*","http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "indexes": {"events": INDEX_EVENTS, "qg": INDEX_QG, "dual": DUAL_WRITE},
        "vertex": {"model": VERTEX_MODEL, "location": VERTEX_LOCATION, "project": GCP_PROJECT},
        "elastic_url_set": bool(ELASTIC_URL),
        "elastic_key_set": bool(ELASTIC_API_KEY)
    }

def vertex_prompt(e, rule_name):
    return (
        "You are a cybersecurity analyst. Produce STRICT JSON only (no code fences) with keys: "
        "title, description, severity, confidence, category, findings (array of {title,detail,indicator}), "
        "recommended_actions (array). "
        f"rule_name: {rule_name}\n"
        f"event_json: {json.dumps(e, ensure_ascii=False)}"
    )

def _extract_json(s):
    try:
        return json.loads(s)
    except:
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except:
                return {}
        return {}

def _parts_text(resp):
    t = getattr(resp, "text", None)
    if isinstance(t, str) and t.strip():
        return t
    chunks = []
    try:
        for c in getattr(resp, "candidates", []) or []:
            parts = getattr(getattr(c, "content", None), "parts", None) or []
            for p in parts:
                txt = getattr(p, "text", None)
                if isinstance(txt, str):
                    chunks.append(txt)
    except Exception as e:
        log.warning("parts_text fallback error: %s", e)
    return "".join(chunks)

def _normalize_confidence(val, default=0.6):
    try:
        if isinstance(val, (int, float)):
            f = float(val)
            return f/100.0 if f > 1.0 else f
        if isinstance(val, str):
            s = val.strip().lower()
            if not s:
                return default
            if s.endswith("%"):
                s = s[:-1].strip()
                f = float(s)
                return f/100.0
            word_map = {"very high": 0.95, "high": 0.9, "medium": 0.6, "moderate": 0.6, "low": 0.3, "very low": 0.15}
            if s in word_map:
                return word_map[s]
            f = float(s)
            return f/100.0 if f > 1.0 else f
    except Exception:
        pass
    return default

def call_vertex(text):
    try:
        from vertexai import init
        from vertexai.generative_models import GenerativeModel
        init(project=GCP_PROJECT, location=VERTEX_LOCATION)
        model = GenerativeModel(VERTEX_MODEL)
        resp = model.generate_content(text, generation_config={"temperature":0.2,"max_output_tokens":2048})
        raw = _parts_text(resp).strip()
        if not raw:
            raise ValueError("Empty Vertex response")
    except Exception as e:
        err = f"VertexAI error: {e}"
        log.error(err, exc_info=True)
        return {
            "title": "Analysis Error",
            "description": err,
            "severity": "low",
            "confidence": 0.2,
            "category": "error",
            "findings": [],
            "recommended_actions": []
        }
    data = _extract_json(raw) or {
        "title":"Analysis",
        "description":raw,
        "severity":"low",
        "confidence":0.6,
        "category":"generic",
        "findings":[],
        "recommended_actions":[]
    }
    data.setdefault("title","Analysis")
    data.setdefault("description","")
    data.setdefault("severity","low")
    data.setdefault("category","generic")
    data.setdefault("findings",[])
    data.setdefault("recommended_actions",[])
    data["confidence"] = _normalize_confidence(data.get("confidence", 0.6))
    return data

_RULE_BY_ACTION = {
    "honeypot_access": "ITH - Honey Identity Probe",
    "password_guess": "ITH - Credential Stuffing",
    "mfa_bypass": "ITH - MFA Bypass Attempt",
    "login": "ITH - AI Enriched Login",
    "impossible_travel": "ITH - Impossible Travel",
    "token_anomaly": "ITH - Suspicious Token Use",
    "geo_velocity": "ITH - Geo Velocity Spike",
    "privilege_escalation": "ITH - Privilege Escalation",
    "shared_account": "ITH - Shared Account Usage",
    "suspicious_process": "ITH - Suspicious Process Execution",
    "lateral_movement": "ITH - Lateral Movement"
}

_RULE_BY_TYPE = {
    "access": "ITH - Honey Identity Probe",
    "denied": "ITH - Credential Stuffing",
    "start": "ITH - AI Enriched Login",
    "failure": "ITH - MFA Bypass Attempt"
}

def _map_from_text(text: str) -> str:
    t = (text or "").lower()
    if not t:
        return "ITH - Unknown"
    if "impossible travel" in t:
        return "ITH - Impossible Travel"
    if "honeypot" in t or "canary" in t:
        return "ITH - Honey Identity Probe"
    if "credential stuffing" in t or "brute-force" in t or "brute force" in t:
        return "ITH - Credential Stuffing"
    if "mfa bypass" in t or "bypass mfa" in t:
        return "ITH - MFA Bypass Attempt"
    if "privilege escalation" in t:
        return "ITH - Privilege Escalation"
    if "suspicious asn" in t or "token" in t:
        return "ITH - Suspicious Token Use"
    if "rare" in t or "unusual location" in t or "geo velocity" in t:
        return "ITH - Geo Velocity Spike"
    if "lateral movement" in t:
        return "ITH - Lateral Movement"
    if "shared account" in t:
        return "ITH - Shared Account Usage"
    return "ITH - Unknown"

def infer_rule_name_initial(payload: dict, event: dict) -> str:
    for k in ("rule_name","rule.name","raw.rule.name","detection","ui_rule","ith.rule"):
        v = payload.get(k) or event.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    scen = event.get("ith.scenario") or event.get("scenario") or payload.get("ith.scenario")
    if isinstance(scen, str) and scen.strip():
        return f"ITH - {scen.strip()}" if not scen.lower().startswith("ith -") else scen.strip()
    act = event.get("event.action") or event.get("action")
    if isinstance(act, str) and act.strip().lower() in _RULE_BY_ACTION:
        return _RULE_BY_ACTION[act.strip().lower()]
    typ = event.get("event.type") or event.get("type")
    if isinstance(typ, str) and typ.strip().lower() in _RULE_BY_TYPE:
        return _RULE_BY_TYPE[typ.strip().lower()]
    return "ITH - Unknown"

async def write_elastic(doc, index_name):
    headers = {"Authorization":f"ApiKey {ELASTIC_API_KEY}","Content-Type":"application/json"}
    url = f"{ELASTIC_URL.rstrip('/')}/{index_name}/_doc"
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, headers=headers, json=doc)
        if r.is_error:
            log.error("Elastic write failed %s %s -> %s", index_name, r.status_code, r.text)
            r.raise_for_status()

@app.post("/ingest")
async def ingest(req: Request):
    try:
        if not ELASTIC_URL or not ELASTIC_API_KEY:
            return {"ok": False, "error": "Missing ELASTIC_URL/ELASTIC_API_KEY (or ELASTIC_CLOUD_URL/ELASTIC_CLOUD_API_KEY)"}
        p = await req.json()
        e = p.get("event",{}) or {}
        rule_name = infer_rule_name_initial(p, e)
        ai = call_vertex(vertex_prompt(e, rule_name))
        if rule_name == "ITH - Unknown":
            rule_name = _map_from_text(ai.get("title") or "")
        user_name  = e.get("user.name") or e.get("user",{}).get("name")
        event_act  = e.get("event.action") or e.get("event",{}).get("action")
        event_type = e.get("event.type")   or e.get("event",{}).get("type")
        if not event_act or not event_type:
            rm = {
                "ITH - Honey Identity Probe": ("honeypot_access","access"),
                "ITH - Credential Stuffing": ("password_guess","denied"),
                "ITH - MFA Bypass Attempt": ("mfa_bypass","failure"),
                "ITH - AI Enriched Login": ("login","start"),
                "ITH - Impossible Travel": ("impossible_travel","info"),
                "ITH - Suspicious Token Use": ("token_anomaly","info"),
                "ITH - Geo Velocity Spike": ("geo_velocity","info"),
                "ITH - Privilege Escalation": ("privilege_escalation","info"),
                "ITH - Shared Account Usage": ("shared_account","info"),
                "ITH - Suspicious Process Execution": ("suspicious_process","info"),
                "ITH - Lateral Movement": ("lateral_movement","info")
            }
            if rule_name in rm:
                da, dt = rm[rule_name]
                event_act = event_act or da
                event_type = event_type or dt
        src_ip     = e.get("source.ip")    or e.get("source",{}).get("ip")
        dst_ip     = e.get("destination.ip") or e.get("destination",{}).get("ip")
        geo_src    = e.get("geo.src")      or e.get("geo",{}).get("src")
        geo_prev   = e.get("geo.prev")     or e.get("geo",{}).get("prev")
        now_iso = datetime.now(timezone.utc).isoformat()
        scenario = e.get("ith.scenario") or ai.get("title") or rule_name
        doc = {
            "@timestamp": now_iso,
            "event": {
                "category": e.get("event.category","authentication"),
                "action": event_act or "unknown",
                "type": event_type or "info",
                "outcome": e.get("event.outcome","unknown"),
                "time": now_iso
            },
            "rule": {"name": rule_name},
            "user": {"name": user_name},
            "source": {"ip": src_ip},
            "destination": {"ip": dst_ip},
            "geo": {"src": geo_src, "prev": geo_prev},
            "raw": {
                "rule": {"name": rule_name},
                "event": {"action": event_act or "unknown", "type": event_type or "info"},
                "ith": {"scenario": scenario}
            },
            "ai": {
                "summary": f"{ai.get('title','')}: {ai.get('description','')}".strip(),
                "confidence": ai["confidence"],
                "summary_json": ai,
                "details": {
                    "scenario": scenario,
                    "user.name": user_name or "-",
                    "raw_event.action": event_act or "-"
                },
                "enriched": True
            },
            "raw_event": e
        }
        await write_elastic(doc, INDEX_EVENTS)
        if DUAL_WRITE:
            await write_elastic(doc, INDEX_QG)
        return {"ok": True}
    except Exception as ex:
        log.exception("Ingest failed")
        return {"ok": False, "error": str(ex)}
