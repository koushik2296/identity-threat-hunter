# Identity Threat Hunter (ITH) — Judge Instructions

Evaluation and testing guide for hackathon judges.
Live Website: https://koushik2296.github.io/identity-threat-hunter/
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



## Detection Rule Definitions (Full List)

| Rule | What it detects | Severity |
|---|---|---|
| ITH – Rare Country Login | Detects logins originating from unusual or first‑seen countries. | Medium |
| ITH – Privilege Escalation | Detects post‑login privilege or role elevation events. | High |
| ITH – ASN / ISP Change | ITH – ASN / ISP Change | High |
| ITH – MFA Bypass | Detects successful authentications that appear to bypass expected MFA. | High |
| ITH – Credential Stuffing | Detects many login attempts across multiple accounts from a single source. | High |
| ITH – Brute Force Then Success | Detects multiple failures followed by a success from the same source. | High |
| ITH – All Scenarios (Judge Demo) | See Elastic rule for full detection logic. | High |
| ITH - First Seen Admin Tool on Host | Flags the first observed execution of selected admin tools per host in ITH indices. | Medium |
| ITH – Impossible Travel | Detects logins from geographically distant locations within a short time window. | High |
| ITH Honey-Identity Trap Detection | Detects honeypot/canary events from Identity Threat Hunter. | Critical |
| ITH – Quantum Adaptive Response | Triggers adaptive live OSquery investigation when a high-risk identity event is detected. | Low |
| Suspicious PowerShell (AutoTriage) | Suspicious PowerShell (AutoTriage) | High |
| ITH - Quantum Guardian High-Risk Finding | Surfaces high/critical Quantum Guardian findings or risk_score >= 70. | High |
| ITH High Risk Score (>= 90) | Any event with risk.score >= 90. | High |
| ITH Impossible Travel | ITH Impossible Travel | Critical |
| ITH Canary Username Touched | Any event involving a canary user (user.name starts with canary-). | Critical |
| ITH - Possible Brute-Force (source.ip + user.name) | Counts failed authentications per source.ip and user.name over the interval in ITH indices. | Medium |
| ITH – Impossible Travel (Custom, with Response Actions) | Custom clone for hackathon demo. Detects impossible travel or high-risk authentication, then automatically runs an OSquery sweep and isolates the host via Elastic Defend. | High |
| Quantum Guardian – High QES | Quantum Guardian – High QES | Low |
| ITH Honey Token Used | Detects canary token usage events. | Critical |
| ITH - VSS Deleted via vssadmin | Detects deletion of Volume Shadow Copies via vssadmin delete shadows in ITH indices. | Critical |
| ITH Canary User Login Attempt (Failure) | Detects canary user login attempts that failed. | Critical |
| ITH – Smoke Test (mfa_bypass) | ITH – Smoke Test (mfa_bypass) | Low |
| ITH Suspicious Test IP Ranges (Demo) | Matches RFC5737 example IPs used in demo honey events. | Medium |
| ITH Alert Webhook | See Elastic rule for full detection logic. | — |


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
