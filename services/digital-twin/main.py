from datetime import datetime, timedelta, timezone
from math import radians, sin, cos, asin, sqrt
from typing import Dict, Any, List, Optional
import os

from fastapi import FastAPI, Query, HTTPException
from functools import lru_cache
from elasticsearch import Elasticsearch

# ---------- Config ----------
ES_URL = os.getenv("ELASTIC_CLOUD_URL")
ES_API_KEY = os.getenv("ELASTIC_API_KEY")
EVENTS_INDEX = os.getenv("EVENTS_INDEX", "ith-events")
PROFILE_INDEX = os.getenv("PROFILE_INDEX", "ith-users-profile")
ENRICHED_INDEX = os.getenv("ENRICHED_INDEX", "ith-events-enriched")
ALPHA = float(os.getenv("PROFILE_ALPHA", "0.1"))

app = FastAPI(title="ITH Digital Twin Service")

# ---------- Utilities ----------
def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    dlat, dlon = radians(lat2-lat1), radians(lon2-lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1))*cos(radians(lat2))*sin(dlon/2)**2
    return 2*R*asin(sqrt(a))

def ema(old: Optional[float], new: float, alpha: float = ALPHA):
    if old is None:
        return new
    return (1-alpha)*old + alpha*new

def incr_count(d: Dict[str,float], key: str, alpha: float = ALPHA):
    # exponential decay + add/update key
    for k in list(d.keys()):
        d[k] = (1-alpha)*d[k]
        if d[k] < 1e-3:
            d.pop(k, None)
    d[key] = d.get(key, 0.0) + alpha

@lru_cache(maxsize=1)
def get_es():
    if not ES_URL or not ES_API_KEY:
        raise HTTPException(status_code=500, detail="Elastic env vars not set")
    return Elasticsearch(ES_URL, api_key=ES_API_KEY)

# ---------- Profile helpers ----------
def fresh_profile(user_id: str) -> Dict[str,Any]:
    return {
        "user_id": user_id,
        "profile_version": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "geo": {"centroid": None, "radius_km_p95": 50.0, "country_counts": {}},
        "network": {"asn_counts": {}, "asn_churn_rate": 0.0},
        "device": {"ua_family_counts": {}, "os_family_counts": {}, "fp_hash_counts": {}},
        "time": {"hour_hist_24": [1]*24, "weekday_hist_7": [1]*7},
        "auth": {"mfa_ratio": 0.0, "fail_ratio": 0.0},
    }

def get_profile(user_id: str) -> Optional[Dict[str,Any]]:
    res = get_es().get(index=PROFILE_INDEX, id=user_id, ignore=[404])
    if res and res.get("found"):
        return res["_source"]
    return None

def put_profile(user_id: str, profile: Dict[str,Any]):
    profile["updated_at"] = datetime.now(timezone.utc).isoformat()
    get_es().index(index=PROFILE_INDEX, id=user_id, document=profile, refresh=False)

def update_profile_from_event(profile: Dict[str,Any], evt: Dict[str,Any]) -> Dict[str,Any]:
    if not profile:
        profile = fresh_profile(evt["user"]["id"])

    # Geo centroid + country
    lat = evt.get("src",{}).get("geo",{}).get("lat")
    lon = evt.get("src",{}).get("geo",{}).get("lon")
    if isinstance(lat,(int,float)) and isinstance(lon,(int,float)):
        c = profile["geo"].get("centroid")
        if c:
            profile["geo"]["centroid"]["lat"] = ema(c["lat"], float(lat))
            profile["geo"]["centroid"]["lon"] = ema(c["lon"], float(lon))
        else:
            profile["geo"]["centroid"] = {"lat": float(lat), "lon": float(lon)}
    country = evt.get("src",{}).get("geo",{}).get("country")
    if country:
        incr_count(profile["geo"]["country_counts"], str(country))

    # ASN popularity
    asn = evt.get("src",{}).get("asn")
    if asn is not None:
        incr_count(profile["network"]["asn_counts"], str(asn))

    # Time histograms
    ts = evt.get("@timestamp")
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z","")).replace(tzinfo=timezone.utc)
            profile["time"]["hour_hist_24"][dt.hour] += 1
            profile["time"]["weekday_hist_7"][dt.weekday()] += 1
        except Exception:
            pass

    # Device UA
    ua_family = evt.get("user_agent",{}).get("family")
    if ua_family:
        incr_count(profile["device"]["ua_family_counts"], str(ua_family))

    # Auth posture
    mfa = bool(evt.get("event",{}).get("mfa", False))
    outcome = evt.get("event",{}).get("outcome")
    profile["auth"]["mfa_ratio"] = ema(profile["auth"]["mfa_ratio"], 1.0 if mfa else 0.0)
    profile["auth"]["fail_ratio"] = ema(profile["auth"]["fail_ratio"], 1.0 if outcome=="failure" else 0.0)
    return profile

def score_against_profile(evt: Dict[str,Any], profile: Optional[Dict[str,Any]]) -> float:
    if not profile:
        return 0.4  # neutral-ish risk if no profile yet

    lat = evt.get("src",{}).get("geo",{}).get("lat")
    lon = evt.get("src",{}).get("geo",{}).get("lon")
    asn = evt.get("src",{}).get("asn")
    ua_family = evt.get("user_agent",{}).get("family")
    mfa = bool(evt.get("event",{}).get("mfa", False))

    # Geo deviation
    centroid = profile.get("geo",{}).get("centroid")
    p95 = max(5.0, float(profile.get("geo",{}).get("radius_km_p95", 50.0)))
    if centroid and isinstance(lat,(int,float)) and isinstance(lon,(int,float)):
        dist = haversine_km(float(lat), float(lon), float(centroid["lat"]), float(centroid["lon"]))
        geo_dev = min(1.0, dist / p95)
    else:
        geo_dev = 0.3

    # ASN deviation by popularity rank
    asn_counts = profile.get("network",{}).get("asn_counts",{})
    rank = 999
    if asn is not None:
        sorted_asn = sorted(asn_counts.items(), key=lambda kv: kv[1], reverse=True)
        for i,(k,_) in enumerate(sorted_asn):
            if str(k) == str(asn):
                rank = i+1
                break
    asn_dev = 0.0 if rank <= 3 else (0.5 if rank <= 10 else 1.0)

    # Time-of-day deviation
    try:
        hour = datetime.fromisoformat(evt["@timestamp"].replace("Z","")).hour
    except Exception:
        hour = 12
    hour_hist = profile.get("time",{}).get("hour_hist_24", [1]*24)
    maxp = max(hour_hist) if hour_hist else 1
    p_hour = hour_hist[hour] / maxp if maxp else 0
    time_dev = 1 - p_hour

    # Device familiarity
    ua_counts = profile.get("device",{}).get("ua_family_counts",{})
    device_dev = 0.0 if (ua_family and ua_family in ua_counts) else 1.0

    # MFA expectation deviation
    mfa_ratio = profile.get("auth",{}).get("mfa_ratio", 0.0)
    mfa_dev = 1.0 if (mfa_ratio >= 0.8 and not mfa) else 0.0

    profile_dev = (0.35*geo_dev + 0.20*asn_dev + 0.20*time_dev + 0.15*device_dev + 0.10*mfa_dev)
    return max(0.0, min(1.0, profile_dev))

def search_events_since(minutes: int) -> List[Dict[str,Any]]:
    gte = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    body = {"size":2000,"sort":[{"@timestamp":{"order":"asc"}}],"query":{"range":{"@timestamp":{"gte":gte}}}}
    res = get_es().search(index=EVENTS_INDEX, body=body)
    return [hit["_source"] for hit in res.get("hits",{}).get("hits", [])]

# ---------- Routes ----------
@app.get("/")
def root():
    return {"ok": True, "service": "digital-twin"}

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/healthz/")
def healthz_slash():
    return {"status": "ok"}

@app.post("/build_profiles")
def build_profiles(minutes: int = Query(default=1440, ge=5, le=43200)):
    evts = search_events_since(minutes)
    by_user: Dict[str,List[Dict[str,Any]]] = {}
    for e in evts:
        uid = e.get("user",{}).get("id")
        if not uid:
            continue
        by_user.setdefault(uid, []).append(e)

    updated = 0
    for uid, items in by_user.items():
        prof = get_profile(uid) or fresh_profile(uid)
        for evt in items:
            prof = update_profile_from_event(prof, evt)
        put_profile(uid, prof)
        updated += 1
    return {"profiles_updated": updated}

@app.post("/enrich_recent")
def enrich_recent(minutes: int = Query(default=60, ge=5, le=1440)):
    evts = search_events_since(minutes)
    written = 0
    for e in evts:
        uid = e.get("user",{}).get("id")
        if not uid:
            continue
        prof = get_profile(uid)
        pdev = score_against_profile(e, prof)
        e.setdefault("event",{})["profile_dev"] = pdev
        rs = float(e.get("event",{}).get("risk_score", 0.0))
        blended = 1 - (1 - rs)*(1 - float(pdev))
        e["event"]["risk_score"] = max(0.0, min(1.0, blended))
        get_es().index(index=ENRICHED_INDEX, document=e, refresh=False)
        written += 1
    return {"events_enriched": written}
