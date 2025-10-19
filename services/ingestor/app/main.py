import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any

import requests
from fastapi import FastAPI, HTTPException

# --- Env
ELASTIC_CLOUD_URL = os.getenv("ELASTIC_CLOUD_URL", "").rstrip("/")
ELASTIC_API_KEY   = os.getenv("ELASTIC_API_KEY", "")
ELASTIC_INDEX     = os.getenv("ELASTIC_INDEX", "ith-events")

ES_HEADERS = {
    "Authorization": f"ApiKey {ELASTIC_API_KEY}",
    "Content-Type": "application/json",
}

app = FastAPI(title="ITH Ingestor", version="1.0.0")


def now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_timestamp(ev: Dict[str, Any]) -> None:
    # 🔒 Always set a timestamp so downstream code never KeyErrors
    ev.setdefault("@timestamp", now_z())


def es_index(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not ELASTIC_CLOUD_URL or not ELASTIC_API_KEY:
        raise RuntimeError("Elastic env not configured")

    index_url = f"{ELASTIC_CLOUD_URL}/{ELASTIC_INDEX}/_doc"
    r = requests.post(index_url, headers=ES_HEADERS, json=doc, timeout=10)

    # If index missing, try to create then retry once
    if r.status_code == 404:
        _ = requests.put(f"{ELASTIC_CLOUD_URL}/{ELASTIC_INDEX}", headers=ES_HEADERS, json={}, timeout=10)
        r = requests.post(index_url, headers=ES_HEADERS, json=doc, timeout=10)

    if r.status_code >= 300:
        raise RuntimeError(f"Elasticsearch index error {r.status_code}: {r.text}")

    return r.json()


@app.get("/healthz")
def healthz():
    return {"ok": True, "index": ELASTIC_INDEX}


@app.post("/ingest")
def ingest(event: Dict[str, Any]):
    # ✅ make sure @timestamp exists
    ensure_timestamp(event)

    uid = str(uuid.uuid4())
    score = int(event.get("risk", {}).get("score", 50))
    reason = event.get("risk", {}).get("reason", "no reason provided")

    doc = {
        "@timestamp": event["@timestamp"],
        "event": event.get("event", {}),
        "user": event.get("user", {}),
        "source": event.get("source", {}),
        "tags": event.get("tags", []),
        "message": event.get("message", event.get("event_explanation", "")),
        "risk": {"score": score, "reason": reason},
        "raw": event,
        "ingestor": {"id": uid, "received_at": now_z(), "service": "ith-ingestor"},
    }

    try:
        res = es_index(doc)
        return {"status": "ok", "id": uid, "es": res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"indexing_failed: {e}")
