from fastapi import APIRouter
from app.utils.emit_event import emit_event

router = APIRouter(prefix="/honey", tags=["honey"])

@router.post("/canary_user_probe")
def canary_user_probe(username: str = "canary-db-admin", source_ip: str = "203.0.113.10"):
    evt = {
        "event": {"category": "honeypot", "type": "auth", "action": "canary_user_login", "outcome": "failure"},
        "tags": ["honey", "canary", "high-signal"],
        "user": {"name": username, "id": username},
        "source": {"ip": source_ip},
        "risk": {"score": 99, "reason": "Canary user login attempt"},
        "event_explanation": f"Failed login to {username} (canary)."
    }
    emit_event(evt)
    return {"status": "ok", "emitted": evt}

@router.post("/canary_token_use")
def canary_token_use(token_id: str = "tok_canary_1", location_hint: str = "repo/.env", source_ip: str = "198.51.100.22"):
    evt = {
        "event": {"category": "honeypot", "type": "token_use", "action": "canary_token_used", "outcome": "success"},
        "tags": ["honey", "canary", "high-signal"],
        "token": {"id": token_id, "location_hint": location_hint},
        "source": {"ip": source_ip},
        "risk": {"score": 99, "reason": "Canary token used"},
        "event_explanation": f"Canary token {token_id} was used; planted in {location_hint}."
    }
    emit_event(evt)
    return {"status": "ok", "emitted": evt}
