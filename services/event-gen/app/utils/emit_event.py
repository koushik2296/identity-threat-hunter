from datetime import datetime, timezone
import os
import requests

ELASTIC_INGEST_URL = os.getenv("INGESTOR_URL", "http://ingestor:8080/ingest")

def emit_event(evt: dict) -> None:
    payload = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "product": "ith",
        "pipeline": "identity-threat-hunter",
        **evt,
    }
    try:
        requests.post(ELASTIC_INGEST_URL, json=payload, timeout=5)
    except Exception:
        # Do not fail demo flows
        pass
