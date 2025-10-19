from fastapi import FastAPI
from datetime import datetime, timedelta
import random, requests

app = FastAPI()

# Simple IP -> geo/asn mapping
LOCATIONS = {
    "NYC": {"ip":"1.1.1.1","geo":{"country":"US","city":"New York","lat":40.7128,"lon":-74.0060},"asn":15169},
    "LON": {"ip":"2.2.2.2","geo":{"country":"GB","city":"London","lat":51.5074,"lon":-0.1278},"asn":32613},
    "VPN": {"ip":"3.3.3.3","geo":{"country":"NL","city":"Amsterdam","lat":52.3702,"lon":4.8952},"asn":56041},
    "IND": {"ip":"5.5.5.5","geo":{"country":"IN","city":"Delhi","lat":28.7041,"lon":77.1025},"asn":55836}
}

def post_event(ingest_url, payload):
    try:
        r = requests.post(ingest_url.rstrip('/') + "/ingest", json=payload, timeout=10)
        return {"status": r.status_code, "resp": r.text}
    except Exception as e:
        return {"status": None, "resp": str(e)}

def make_login(user, loc, ts, mfa=False, outcome="success"):
    return {
        "@timestamp": ts.isoformat() + "Z",
        "user": {"id": user, "name": user},
        "event": {"action":"login", "outcome": outcome, "mfa": mfa},
        "src": {"ip": loc["ip"], "geo": loc["geo"], "asn": loc["asn"]},
        "device": {"fingerprint": f"dev-{random.randint(1,9999)}"}
    }

def make_role_change(user, ts, prev_role="user", new_role="admin"):
    return {
        "@timestamp": ts.isoformat() + "Z",
        "user": {"id": user, "name": user},
        "event": {"action":"role_change", "previous_role": prev_role, "new_role": new_role}
    }

@app.post("/burst_scenario")
def burst_scenario(scenario: str, user: str = "alice", n: int = 5, ingest_url: str = ""):
    now = datetime.utcnow()
    results = []

    if scenario == "impossible_travel":
        results.append(post_event(ingest_url, make_login(user, LOCATIONS["NYC"], now, mfa=True)))
        results.append(post_event(ingest_url, make_login(user, LOCATIONS["LON"], now + timedelta(minutes=2), mfa=True)))
    elif scenario == "mfa_bypass":
        results.append(post_event(ingest_url, make_login(user, LOCATIONS["NYC"], now, mfa=True)))
        results.append(post_event(ingest_url, make_login(user, LOCATIONS["NYC"], now + timedelta(minutes=10), mfa=False)))
    elif scenario == "brute_force_then_success":
        for i in range(n):
            results.append(post_event(ingest_url, make_login(user, LOCATIONS["NYC"], now + timedelta(seconds=i*5), outcome="failure")))
        results.append(post_event(ingest_url, make_login(user, LOCATIONS["NYC"], now + timedelta(seconds=n*5+2), outcome="success")))
    elif scenario == "privilege_escalation":
        results.append(post_event(ingest_url, make_role_change(user, now, prev_role="user", new_role="admin")))
    elif scenario == "rare_country":
        results.append(post_event(ingest_url, make_login(user, LOCATIONS["NYC"], now - timedelta(days=30))))
        results.append(post_event(ingest_url, make_login(user, LOCATIONS["IND"], now)))
    elif scenario == "credential_stuffing":
        for i in range(n):
            u = f"user{i}"
            results.append(post_event(ingest_url, make_login(u, LOCATIONS["VPN"], now + timedelta(seconds=i))))
    elif scenario == "asn_change":
        results.append(post_event(ingest_url, make_login(user, LOCATIONS["NYC"], now)))
        e2 = make_login(user, LOCATIONS["NYC"], now + timedelta(minutes=1))
        e2["src"]["asn"] = LOCATIONS["VPN"]["asn"]
        results.append(post_event(ingest_url, e2))
    else:
        return {"error": "unknown scenario"}

    return {"ok": True, "results": results}
