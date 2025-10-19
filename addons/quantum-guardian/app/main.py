from fastapi import FastAPI, Body
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import os, math, json
from elasticsearch import Elasticsearch

app = FastAPI(title="IDEA-3 Quantum Guardian")

ES_URL = os.getenv("ELASTIC_CLOUD_URL")
ES_API = os.getenv("ELASTIC_API_KEY")
ES_INDEX = os.getenv("ELASTIC_INDEX_TARGET", "ith-idea3-quantum")

W_AGE = float(os.getenv("W_AGE", 8))
W_ALG = float(os.getenv("W_ALG", 22))
W_SCOPE = float(os.getenv("W_SCOPE", 28))
W_DEVICE = float(os.getenv("W_DEVICE", 18))
W_ROT = float(os.getenv("W_ROT", 14))
W_POLICY = float(os.getenv("W_POLICY", 10))

es = None
if ES_URL and ES_API:
    es = Elasticsearch(ES_URL, api_key=ES_API, request_timeout=30)

# === Models ===
class TokenMeta(BaseModel):
    alg: str = Field(..., description="JWT alg, e.g., RS256, ES256, PS256")
    key_bits: Optional[int] = Field(None, description="RSA modulus size in bits, if applicable")
    curve: Optional[str] = Field(None, description="ECDSA curve, e.g., P-256")
    issued_at: datetime
    expires_at: datetime
    rotation_days: Optional[int] = Field(7, description="Token/refresh rotation cadence in days")
    device_bound: bool = Field(False, description="Is token bound to device key/TPM?")
    scopes: List[str] = Field(default_factory=list)

class IdentityMeta(BaseModel):
    user: Optional[str] = None
    issuer: Optional[str] = None
    session_id: Optional[str] = None

class PolicyMeta(BaseModel):
    issuer_policy_gap: Optional[float] = Field(0.0, description="0-2 scale: 0 means strict modern policy, 2 means weak/legacy")

class ScoreRequest(BaseModel):
    identity: IdentityMeta
    token: TokenMeta
    policy: Optional[PolicyMeta] = PolicyMeta()

# === Helpers ===
ALG_RISK_TABLE = {
    # Relative ordinal 1 (low) .. 5 (high). Configure with your cryptography team.
    "RS256": lambda bits: 3 if (bits or 2048) >= 2048 else 4,
    "RS384": lambda bits: 3,
    "RS512": lambda bits: 3,
    "PS256": lambda bits: 3,
    "PS384": lambda bits: 3,
    "PS512": lambda bits: 3,
    "ES256": lambda curve: 2,
    "ES384": lambda curve: 2,
    "ES512": lambda curve: 2,
    # Fallback for unknown/legacy
}

def algorithm_risk(token: TokenMeta) -> int:
    alg = (token.alg or "").upper()
    if alg.startswith("RS"):
        return ALG_RISK_TABLE.get(alg, lambda bits: 3)(token.key_bits)
    if alg.startswith("PS"):
        return ALG_RISK_TABLE.get(alg, lambda bits: 3)(token.key_bits)
    if alg.startswith("ES"):
        return ALG_RISK_TABLE.get(alg, lambda curve: 2)(token.curve)
    # Unknown/legacy: be conservative
    return 4

def scope_sensitivity(scopes: List[str]) -> float:
    if not scopes:
        return 0.5
    s = 0.0
    for sc in scopes:
        sc_l = sc.lower()
        if "admin" in sc_l or "write" in sc_l or "privileged" in sc_l:
            s += 1.0
        elif "read" in sc_l or "view" in sc_l:
            s += 0.4
        else:
            s += 0.6
    # normalize roughly into 0..4
    return min(4.0, 0.8 * s)

def normalize_age(issued_at: datetime, expires_at: datetime) -> float:
    now = datetime.now(timezone.utc)
    ttl = max(1.0, (expires_at - issued_at).total_seconds() / 86400.0)  # days
    age = max(0.0, (now - issued_at).total_seconds() / 86400.0)
    return min(1.0, age / ttl)  # 0..1

def rotation_penalty(days: Optional[int]) -> float:
    if days is None:
        return 1.0
    if days <= 7:
        return 0.2
    if days <= 30:
        return 0.6
    return 1.2

def device_binding_gap(bound: bool) -> float:
    return 0.0 if bound else 1.0

def compute_qes(req: ScoreRequest) -> Dict[str, Any]:
    f_age = normalize_age(req.token.issued_at, req.token.expires_at)
    f_alg = float(algorithm_risk(req.token))
    f_scope = scope_sensitivity(req.token.scopes)
    f_device = device_binding_gap(req.token.device_bound)
    f_rot = rotation_penalty(req.token.rotation_days)
    f_policy = float(req.policy.issuer_policy_gap or 0.0)

    score = (W_AGE * f_age + W_ALG * f_alg + W_SCOPE * f_scope +
             W_DEVICE * f_device + W_ROT * f_rot + W_POLICY * f_policy)

    return {
        "qes": {
            "score": round(score, 2),
            "factors": {
                "token_age_days": round(f_age, 3),
                "algorithm_risk": round(f_alg, 3),
                "scope_sensitivity": round(f_scope, 3),
                "device_binding_gap": round(f_device, 3),
                "rotation_gap": round(f_rot, 3),
                "issuer_policy_gap": round(f_policy, 3),
            },
            "weights": {
                "w_age": W_AGE, "w_alg": W_ALG, "w_scope": W_SCOPE,
                "w_device": W_DEVICE, "w_rot": W_ROT, "w_policy": W_POLICY
            }
        },
        "crypto_profile": {
            "alg_family": req.token.alg[:2].upper(),
            "algorithm_risk": int(f_alg),
            "notes": [
                "device_bound" if req.token.device_bound else "not_device_bound"
            ]
        }
    }

def index_doc(doc: Dict[str, Any]) -> Optional[str]:
    if not es:
        return None
    res = es.index(index=ES_INDEX, document=doc)
    return res.get("_id")

# === Endpoints ===
@app.post("/score-token")
def score_token(req: ScoreRequest):
    base_doc = {
        "event": {"module": "idea3", "type": "token_crypto_risk", "time": datetime.now(timezone.utc).isoformat()},
        "identity": req.identity.dict(),
        "token": req.token.dict(),
    }
    enrich = compute_qes(req)
    doc = {**base_doc, **enrich}
    _id = index_doc(doc)
    return {"indexed_id": _id, "doc": doc}

class BatchRequest(BaseModel):
    items: List[ScoreRequest]

@app.post("/score-batch")
def score_batch(req: BatchRequest):
    results = []
    for item in req.items:
        results.append(score_token(item))
    return results

# Optional backfill (requires SOURCE_INDEX env and ES perms)
class BackfillRequest(BaseModel):
    query: str = Field(..., description="ES query DSL or KQL string for source index")

@app.post("/es/backfill")
def es_backfill(payload: BackfillRequest):
    source_index = os.getenv("SOURCE_INDEX")
    if not es or not source_index:
        return {"ok": False, "reason": "Elasticsearch not configured or SOURCE_INDEX missing"}
    # Simple KQL wrapper: you can adapt to ES|QL as needed
    body = {"query": {"query_string": {"query": payload.query}}}
    resp = es.search(index=source_index, body=body, size=1000)
    count = 0
    for hit in resp["hits"]["hits"]:
        # Map minimal fields; customize as per your source docs
        src = hit["_source"]
        token_meta = TokenMeta(
            alg=src.get("token", {}).get("alg", "RS256"),
            key_bits=src.get("token", {}).get("key_bits", 2048),
            curve=src.get("token", {}).get("curve"),
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
            rotation_days=src.get("token", {}).get("rotation_days", 30),
            device_bound=bool(src.get("token", {}).get("device_bound", False)),
            scopes=src.get("token", {}).get("scopes", []),
        )
        req = ScoreRequest(identity=IdentityMeta(user=src.get("user")), token=token_meta, policy=PolicyMeta())
        score_token(req)
        count += 1
    return {"ok": True, "indexed": count}
