import os, requests, json, datetime

SERVICE = os.getenv("SERVICE_URL", "http://localhost:8090")

def send(item):
    r = requests.post(f"{SERVICE}/score-token", json=item, timeout=10)
    print(r.status_code, r.json().get("doc", {}).get("qes", {}))

def main():
    now = datetime.datetime.utcnow()
    cases = [
        {
            "identity": {"user": "admin@example.com", "issuer": "okta", "session_id": "A1"},
            "token": {
                "alg": "RS256", "key_bits": 2048, "curve": None,
                "issued_at": now.isoformat() + "Z",
                "expires_at": (now + datetime.timedelta(hours=12)).isoformat() + "Z",
                "rotation_days": 45, "device_bound": False,
                "scopes": ["admin", "write:all"]
            },
            "policy": {"issuer_policy_gap": 1.5}
        },
        {
            "identity": {"user": "analyst@example.com", "issuer": "okta", "session_id": "B2"},
            "token": {
                "alg": "ES256", "key_bits": None, "curve": "P-256",
                "issued_at": now.isoformat() + "Z",
                "expires_at": (now + datetime.timedelta(hours=1)).isoformat() + "Z",
                "rotation_days": 7, "device_bound": True,
                "scopes": ["read:reports"]
            },
            "policy": {"issuer_policy_gap": 0.2}
        }
    ]
    for c in cases:
        send(c)

if __name__ == "__main__":
    main()
