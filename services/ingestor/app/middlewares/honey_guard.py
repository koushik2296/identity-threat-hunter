import os
from typing import Dict, Any

CANARY_PREFIX = os.getenv("HONEY_CANARY_USER_PREFIX", "canary-")
HONEY_ENABLED = os.getenv("HONEY_ENABLED", "true").lower() == "true"

def apply_honey_enrichment(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not HONEY_ENABLED:
        return payload

    user_name = (payload.get("user") or {}).get("name") or ""
    is_honey = user_name.startswith(CANARY_PREFIX) or (payload.get("event") or {}).get("category") == "honeypot"

    if is_honey:
        payload.setdefault("event", {})["category"] = "honeypot"
        tags = set(payload.get("tags") or [])
        tags.update({"honey", "canary", "high-signal"})
        payload["tags"] = sorted(list(tags))
        payload["risk"] = {"score": 99, "reason": "Honey identity interaction"}
        if "event_explanation" not in payload:
            payload["event_explanation"] = "Honey identity interaction detected."
    return payload
