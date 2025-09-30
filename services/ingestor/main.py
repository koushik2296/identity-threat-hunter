import os, math, time
from typing import Optional
from fastapi import FastAPI, Request
import httpx

ELASTIC_CLOUD_URL = os.environ.get("ELASTIC_CLOUD_URL", "")
ELASTIC_API_KEY = os.environ.get("ELASTIC_API_KEY", "")
ELASTIC_INDEX = os.environ.get("ELASTIC_INDEX", "ith-events")

app = FastAPI(title="ITH Ingestor")

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    p = math.pi/180
    dlat = (lat2-lat1)*p
    dlon = (lon2-lon1)*p
    a = 0.5 - math.cos(dlat)/2 + math.cos(lat1*p)*math.cos(lat2*p)*(1-math.cos(dlon))/2
    return 2*R*math.asin(math.sqrt(a))

_last_login = {}

@app.post("/ingest")
async def ingest(event: dict):
    # Basic risk scoring for demo
    user = (event.get("user") or {}).get("id", "unknown")
    ts = event.get("@timestamp")
    geo = (((event.get("src") or {}).get("geo")) or {})
    lat, lon = geo.get("lat"), geo.get("lon")

    risk = 0.0
    expl = []

    prev = _last_login.get(user)
    if prev and lat is not None and lon is not None:
        dist_km = haversine(prev["lat"], prev["lon"], lat, lon)
        # Assume 1 hour between events if timestamps equal/missing
        time_h = max((prev["t"] and ts and ( (parse_ts(ts)-prev["t"])/3600.0 )) or 1.0, 0.01)
        speed = dist_km / time_h
        if dist_km > 800 and time_h < 2 or speed > 900:
            risk += 0.8
            expl.append(f"Impossible travel: {dist_km:.0f} km in {time_h:.2f} h (≈{speed:.0f} km/h)")

    if lat is not None and lon is not None:
        _last_login[user] = {"lat": lat, "lon": lon, "t": parse_ts(ts) if ts else time.time()}

    event.setdefault("event", {}).update({"risk_score": risk, "explanation": "; ".join(expl)})
    # index into Elastic
    async with httpx.AsyncClient(timeout=10) as client:
        url = f"{ELASTIC_CLOUD_URL}/{ELASTIC_INDEX}/_doc"
        headers = {"Authorization": f"ApiKey {ELASTIC_API_KEY}"}
        r = await client.post(url, headers=headers, json=event)
        r.raise_for_status()
    return {"ok": True, "risk_score": risk, "explanation": event["event"]["explanation"]}

def parse_ts(ts: Optional[str]) -> float:
    # naive ISO8601 parser for Z timestamps
    if not ts:
        return time.time()
    try:
        from datetime import datetime, timezone
        return datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
    except Exception:
        return time.time()
