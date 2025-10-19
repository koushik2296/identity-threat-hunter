# IDEA-3 Add-On: Quantum Guardian (Token Cryptographic Risk Enricher)

**Do not modify existing services.** This add-on runs alongside the Identity Threat Hunter (ITH) stack and writes to its own index. It evaluates **token cryptographic risk** with a forward-looking lens (e.g., harvest-now-decrypt-later exposure) and produces a risk score to help prioritize alerts.

## What this module does
- Accepts token/session metadata (algorithm, key size/curve, issue/expiry times, scopes, issuer, device binding, rotation cadence).
- Computes a **Quantum Exposure Score (QES)** using configurable weights.
- Indexes scored documents into **`ith-idea3-quantum`** in Elastic Cloud.
- (Optional) Exposes a **/es/backfill** endpoint to score historical events by querying your existing ITH index (read-only). This is off by default and requires an explicit query to avoid coupling.

No changes are required to: `ingestor`, `event-gen`, `alert-webhook`, or `analyst-ui`.

## Data model
Target index: `ith-idea3-quantum`

Document shape (simplified):
```json
{
  "event": {
    "module": "idea3",
    "type": "token_crypto_risk",
    "time": "..."
  },
  "identity": { "user": "alice@example.com", "issuer": "okta", "session_id": "..." },
  "token": {
    "alg": "RS256",
    "key_bits": 2048,
    "curve": null,
    "issued_at": "2025-10-02T20:15:00Z",
    "expires_at": "2025-10-03T20:15:00Z",
    "rotation_days": 7,
    "device_bound": false,
    "scopes": ["admin", "read:all"]
  },
  "crypto_profile": {
    "alg_family": "RSA",
    "algorithm_risk": 3,
    "notes": ["asymmetric signature", "no device binding"]
  },
  "qes": {
    "score": 78.5,
    "factors": {
      "token_age_days": 1.0,
      "algorithm_risk": 3.0,
      "scope_sensitivity": 4.0,
      "device_binding_gap": 1.0,
      "rotation_gap": 2.0,
      "issuer_policy_gap": 1.5
    },
    "weights": { "w_age": 8, "w_alg": 22, "w_scope": 28, "w_device": 18, "w_rot": 14, "w_policy": 10 }
  }
}
```

> **Note:** `algorithm_risk` is a relative, configurable ordinal (1–5) to represent current + projected cryptographic exposure. Administrators should set these values with their crypto team. This module does **not** claim a real break—it's a prioritization aid.

## Risk model (configurable)
Displayed in LaTeX-friendly form for your Devpost story:

$$
QES = w_{age}\cdot f_{age} + w_{alg}\cdot f_{alg} + w_{scope}\cdot f_{scope} + w_{device}\cdot f_{device} + w_{rot}\cdot f_{rot} + w_{policy}\cdot f_{policy}
$$

- \(f_{age}\): normalized token age / TTL.  
- \(f_{alg}\): **algorithm_risk** (1–5), derived from alg + key size/curve.  
- \(f_{scope}\): sensitivity of scopes (e.g., admin > read).  
- \(f_{device}\): 1 if not device-bound, 0 if bound (configurable scale).  
- \(f_{rot}\): rotation frequency penalty.  
- \(f_{policy}\): issuer policy gap (e.g., long-lived refresh tokens).

Weights default in `.env.example` and can be tuned.

## REST API
- `POST /score-token` — score a single token metadata JSON (returns doc + ES index id).
- `POST /score-batch` — score an array of token metadata objects.
- `POST /es/backfill` — (optional) run a one-off ES query to transform historical docs into `ith-idea3-quantum` (requires `SOURCE_INDEX` and a KQL/ES|QL).

## Elastic detection examples
**KQL (alert high QES):**
```
index = "ith-idea3-quantum" and qes.score >= 80
```

**KQL (risky alg + long-lived tokens):**
```
index = "ith-idea3-quantum" and crypto_profile.algorithm_risk >= 4 and token.rotation_days > 30
```

**ES|QL (surface admin scopes):**
```
from index:"ith-idea3-quantum"
| where qes.score >= 70
| where array_contains(token.scopes, "admin") == true
```

## Run locally (no changes to core project)
```bash
# From repo root (or anywhere)
cd addons/idea3-quantum-guardian

# 1) Create and edit .env
cp .env.example .env

# 2) Python virtualenv (optional)
python -m venv .venv && source .venv/bin/activate
pip install -r app/requirements.txt

# 3) Run service
uvicorn app.main:app --host 0.0.0.0 --port 8090 --reload

# 4) Send sample events
python scripts/generate_samples.py
```

## Docker
```bash
docker build -t idea3-quantum-guardian:latest .
docker run -it --rm --env-file .env -p 8090:8090 idea3-quantum-guardian:latest
```

## Environment
```
ELASTIC_CLOUD_URL=https://<your-elastic-endpoint>
ELASTIC_API_KEY=<your-api-key>
ELASTIC_INDEX_TARGET=ith-idea3-quantum
# Optional: read-only backfill source
SOURCE_INDEX=ith-events-enriched

# Weights (tune to your program)
W_AGE=8
W_ALG=22
W_SCOPE=28
W_DEVICE=18
W_ROT=14
W_POLICY=10
```

## Demo flow (recording guide)
1. Start service (`uvicorn ...`).
2. Show `.env` with Elastic target index.
3. Run `python scripts/generate_samples.py` to push example tokens (admin vs read-only, device-bound vs not).
4. In Kibana, create a data view for `ith-idea3-quantum`. Verify docs.
5. Add a rule: `qes.score >= 80`. Trigger, show alert. (Webhook to your existing alert service is optional; no code changes here.)
6. Explain future tunings (weights/algorithm_risk mapping).

## Security notes
- Treat this as a **risk scoring aid**, not as cryptographic proof.
- Keep mappings under version control and validated by your crypto/security team.
