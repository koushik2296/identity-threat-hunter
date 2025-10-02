def map_severity(event: dict) -> str:
    cat = ((event.get("event") or {}).get("category") or "").lower()
    if cat == "honeypot":
        return "P1"
    return "P3"
