
# Identity Threat Hunter (ITH) — Judge Instructions

Evaluation and testing guide for hackathon judges.  
Live Website: https://koushik2296.github.io/identity-threat-hunter/

---

## Overview

Identity Threat Hunter (ITH) demonstrates end‑to‑end identity threat detection using **Google Cloud Run + Elastic Security** with **Vertex AI** enrichment. All detections originate from simulated scenarios executed through the Analyst UI.

---

## Access

| Component | URL | Credentials |
|---|---|---|
| Analyst UI | https://ith-ui-1054075376433.us-central1.run.app | — |
| Ingestor API | Backend endpoint (used by Analyst UI) | — |
| Quantum Guardian | Backend API (used by Quantum trigger) | — |
| **Kibana – Elastic Security (Default Space)** | https://4e09aacaaf5546ea985fe43d16a0a09d.us-central1.gcp.cloud.es.io/app/security/alerts | **Username:** `ith_judge` • **Password:** `Hackathon2025` |

### Judge Kibana Access
1. Open the Kibana link above and log in with the provided credentials.
2. Land on **Security → Alerts** (default space).
3. Use **Discover** to view raw documents in `ith-events*` and `quantum-guardian*`.

---

## Steps to Test

1. Open the **Analyst UI** in a browser.
2. Click any scenario (e.g., **Impossible Travel**) or **Trigger All**.
3. Wait ~1 minute and open **Kibana → Security → Alerts**.
4. Click an alert and confirm the **AI explanation** in `rule.explanation`.
5. Go to **Discover**, select `ith-events*`, and filter `ai.enriched:true`.
6. Verify `ai.summary`, `ai.confidence`, and `event.scenario` on recent events.

---

## Available Triggers

| Type | Buttons / Endpoint | Purpose |
|---|---|---|
| Baseline Scenarios | Impossible Travel, MFA Bypass, Brute Force Then Success, Rare Country, Credential Stuffing, ASN / ISP Change, Privilege Escalation | Generates distinct authentication events with risk and scenario labels. |
| Honey Identity | Canary User Probe, Canary Token Use | Honeypot/canary identity activity. |
| Quantum Guardian | Quantum Risk Check | Produces QES findings in `quantum-guardian*`. |

---

## Detection Rule Definitions (Subset)

| Rule | What it detects | Severity |
|---|---|---|
| ITH – Rare Country Login | Unusual country authentication | Medium |
| ITH – Privilege Escalation | Role/permission elevation after login | High |
| ITH – ASN / ISP Change | Provider change across sessions | High |
| ITH – MFA Bypass | Success without expected MFA | High |
| ITH – Credential Stuffing | Many attempts across accounts | High |
| ITH – Brute Force Then Success | Failures then success from same source | High |
| ITH – Impossible Travel | Distant locations in short time | Critical |
| ITH Honey‑Identity Trap | Decoy identity interaction | Critical |
| ITH – Quantum Adaptive Response | Auto‑investigation when high risk | Medium |
| ITH – Quantum Guardian High‑Risk | QES ≥ 70 | High |

---

## What to Look For

- Alerts contain **`rule.explanation`** summarizing AI‑assisted context.
- Raw documents contain **`ai.summary`**, **`ai.confidence`**, **`ai.enriched:true`**, and **`event.scenario`**.
- Elastic views are responsive and read‑only for the judge account.

---

## Evaluation Checklist

- [ ] Scenarios trigger within ~1 minute.
- [ ] Alerts visible with AI explanations.
- [ ] `ai.*` fields present in `ith-events*`.
- [ ] Quantum Guardian entries visible when triggered.
- [ ] End‑to‑end flow (UI → Ingest → AI → Elastic → Alerts) demonstrated.
