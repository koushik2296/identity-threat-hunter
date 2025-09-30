import os, json, random, time
from fastapi import FastAPI
import httpx

INGEST_URL = os.environ.get("INGEST_URL", "")
app = FastAPI(title="ITH Event Generator")

LOCATIONS = [
    {"city":"New York","country":"US","lat":40.7128,"lon":-74.0060,"ip":"8.8.8.8","asn":15169},
    {"city":"London","country":"GB","lat":51.5074,"lon":-0.1278,"ip":"1.1.1.1","asn":13335},
    {"city":"Bangalore","country":"IN","lat":12.9716,"lon":77.5946,"ip":"8.8.4.4","asn":15169}
]

@app.post("/burst")
async def burst(user: str = "alice", n: int = 5, seconds: int = 30):
    async with httpx.AsyncClient(timeout=10) as client:
        for i in range(n):
            loc = random.choice(LOCATIONS)
            evt = {
                "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "user": {"id": user, "name": user.title()},
                "src": {"ip": loc["ip"], "geo": {"lat": loc["lat"], "lon": loc["lon"], "country": loc["country"], "city": loc["city"]}},
                "device": {"fingerprint": "fp-123"},
                "asn": loc["asn"],
                "event": {"kind":"authentication","action":"login"}
            }
            r = await client.post(f"{INGEST_URL}/ingest", json=evt)
            r.raise_for_status()
            time.sleep(max(1, seconds//max(1,n)))
    return {"ok": True, "sent": n}
