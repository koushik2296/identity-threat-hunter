from fastapi import FastAPI, Request
from datetime import datetime, timedelta
import math, os
from elasticsearch import Elasticsearch

app = FastAPI()

# Elastic client (from env)
ES_URL = os.environ.get("ELASTIC_CLOUD_URL")
ES_API_KEY = os.environ.get("ELASTIC_API_KEY")
if ES_URL is None or ES_API_KEY is None:
    raise RuntimeError("Set ELASTIC_CLOUD_URL and ELASTIC_API_KEY in environment")

es = Elasticsearch(ES_URL, api_key=ES_API_KEY, verify_certs=True)
INDEX = os.environ.get("ELASTIC_INDEX", "ith-events")

# In-memory state
last_login = {}
failures = {}
ip_to_users = {}

def haversine(lat1, lon1, lat2, lon2):
    R=6371.0
    phi1,phi2=math.radians(lat1), math.radians(lat2)
    dphi=math.radians(lat2-lat1)
    dlambda=math.radians(lon2-lon1)
    a=math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return 2*R*math.asin(math.sqrt(a))

def compute_risk(user_id, ev):
    score, reasons = 0.0, []
    ts = datetime.fromisoformat(ev["@timestamp"].replace("Z",""))
    e, src = ev.get("event", {}), ev.get("src", {})

    prev = last_login.get(user_id)
    if e.get("action") == "login":
        lat = src.get("geo", {}).get("lat")
        lon = src.get("geo", {}).get("lon")
        asn = src.get("asn")

        if prev and prev.get("lat") is not None and lat is not None:
            dist = haversine(prev["lat"], prev["lon"], lat, lon)
            dt = (ts - prev["ts"]).total_seconds()/3600.0
            if dt > 0 and dist/dt > 900:
                score += 0.7; reasons.append("impossible_travel")

        if prev and prev.get("asn") and prev["asn"] != asn:
            score += 0.3; reasons.append("asn_change")

        if prev and prev.get("mfa") and not e.get("mfa", False):
            if (ts - prev["ts"]) < timedelta(hours=1):
                score += 0.5; reasons.append("mfa_bypass")

        if e.get("outcome") == "failure":
            failures.setdefault(user_id, []).append(ts)
            failures[user_id] = [t for t in failures[user_id] if ts - t <= timedelta(minutes=5)]
            if len(failures[user_id]) >= 10:
                score += 0.6; reasons.append("brute_force")
        else:
            failures[user_id] = []

        ip = src.get("ip")
        if ip:
            ip_to_users.setdefault(ip, []).append((user_id, ts))
            ip_to_users[ip] = [(u,t) for (u,t) in ip_to_users[ip] if ts - t <= timedelta(minutes=5)]
            if len(set(u for u,_ in ip_to_users[ip])) >= 10:
                score += 0.7; reasons.append("credential_stuffing")

        last_login[user_id] = {"ts": ts, "lat": lat, "lon": lon, "asn": asn, "mfa": e.get("mfa", False)}

    if e.get("action") == "role_change" and e.get("new_role") == "admin":
        score += 1.0; reasons.append("privilege_escalation")

    return min(score, 1.0), ";".join(reasons) if reasons else "none"

@app.post("/ingest")
async def ingest(req: Request):
    ev = await req.json()
    events = ev if isinstance(ev, list) else [ev]
    results = []
    for e in events:
        uid = e.get("user", {}).get("id", "unknown")
        s, reason = compute_risk(uid, e)
        e.setdefault("event", {})["risk_score"] = s
        e["event"]["explanation"] = reason
        try:
            es.index(index=INDEX, document=e)
            results.append({"user": uid, "risk": s, "reason": reason})
        except Exception as err:
            results.append({"user": uid, "error": str(err)})
    return {"results": results}
