# Identity Threat Hunter (ITH) — Judge Instructions

Evaluation and testing guide for hackathon judges.

---

## Overview

Identity Threat Hunter (ITH) demonstrates end‑to‑end identity threat detection using Google Cloud Run and Elastic Security.
All detections originate from simulated attack scenarios executed through the Analyst UI.

---

## Access

| Component | URL | Credentials |
|------------|-----|-------------|
| Analyst UI | https://ith-ui-1054075376433.us-central1.run.app | — |
| Ingestor API | Backend endpoint (used internally by Analyst UI) | — |
| Quantum Guardian | Backend API endpoint (used for Quantum Risk Check trigger) | — |
| **Kibana – Elastic Security (Default Space)** | https://4e09aacaaf5546ea985fe43d16a0a09d.us-central1.gcp.cloud.es.io/app/security/alerts | **Username:** `ith_judge`  •  **Password:** `Hackathon2025` |

### Judge Kibana Access
1. Click the Kibana link above to open Elastic Security.
2. Log in using the provided credentials.
3. You will land directly on **Security → Alerts** in the default space.
4. You can switch to **Discover** to view the raw event documents (`ith-events*` and `quantum-guardian*`).
5. Both Alerts and Discover views are read‑only.

---

## Steps to Test

1. Open the **Analyst UI** in a browser.
2. Click a scenario button (e.g., Impossible Travel) or use **Trigger All**.
3. Wait ~1 minute and open **Kibana → Security → Alerts**.
4. Confirm alerts corresponding to the scenario appear.
5. Optionally open **Discover** to inspect raw documents.

---

## Available Triggers

| Type | Buttons / Endpoint | Purpose |
|------|--------------------|----------|
| Baseline Scenarios | Impossible Travel, MFA Bypass, Brute Force Then Success, Rare Country, Credential Stuffing, ASN / ISP Change, Privilege Escalation | Generates synthetic authentication events with distinct risk scores and `event.scenario`. |
| Honey Identity | Canary User Probe, Canary Token Use | Produces honeypot events (`event.category: honeypot`) representing decoy identity usage. |
| Quantum Guardian | Quantum Risk Check | Creates cryptographic risk evaluation events (QES). |

---

## Detection Rule Definitions

| Rule | Definition | Severity | Context |
|------|-------------|-----------|----------|
| Impossible Travel | Detects logins from distant geolocations within a short time interval. | High | Indicates compromised credentials. |
| MFA Bypass | Detects successful logins missing expected MFA data. | High | Potential token theft or session replay. |
| Brute Force Then Success | Detects multiple failed attempts followed by a success. | High | Password spray or brute force. |
| Rare Country Login | Detects logins from infrequent geographic origins. | Medium | Unusual travel or remote attacker. |
| Credential Stuffing | Detects high login volume from one source across users. | High | Automated credential reuse. |
| ASN / ISP Change | Detects ISP or ASN variation between sessions. | Medium | Proxy, VPN, or anonymizer usage. |
| Privilege Escalation | Detects rapid privilege elevation after login. | High | Post‑compromise privilege abuse. |
| Honey Identity | Detects access to canary users or tokens. | Critical | High‑fidelity alert of malicious reconnaissance. |
| Quantum Guardian | Detects tokens with high quantum‑exposure score (QES ≥ 80). | High | Evaluates long‑term cryptographic exposure. |

---

## Expected Results

- Each triggered scenario produces a document in `ith-events*`.
- Corresponding alert appears in Kibana within one minute.
- Honey triggers raise honeypot alerts.
- Quantum trigger produces entries under `quantum-guardian*` with QES field.

---

## Evaluation Checklist

- All eight detections (seven baseline + Honey + Quantum) validated.
- UI operational and responsive.
- Elastic alerts visible and labeled by `raw.rule.name`.
- Endpoints are public and functioning.
- System demonstrates complete ingestion → detection → alert workflow.
