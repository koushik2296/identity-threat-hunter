# Identity Threat Hunter (ITH)

Identity Threat Hunter (ITH) is a cloud‑native identity‑security analytics platform built on **Google Cloud Run** and **Elastic Cloud**. 
It ingests authentication events, enriches them with contextual and behavioral intelligence, and generates real‑time alerts for identity‑based threat scenarios. 

---

## Architecture Overview

```
[User / Judge] → ith‑ui (Analyst UI)
                  │
                  ├──> ith‑event‑gen → ith‑ingestor → Elastic Cloud (ith‑events)
                  │                                   │
                  │                                   ├─ Digital Twin
                  │                                   ├─ Honey Identity
                  │                                   ├─ Quantum Guardian
                  │                                   └─ Kibana Alerts
                  │
                  └──> ith‑alert (Webhook Integration)
```

---

## Services

| Service | Purpose | Deployment |
|----------|----------|------------|
| ith‑ui | Analyst interface for scenario triggers and demonstrations. | https://ith-ui-1054075376433.us-central1.run.app |
| ith‑ingestor | FastAPI endpoint receiving events and indexing to Elastic. | https://ith-ingestor-wcax3xalza-uc.a.run.app/ingest |
| ith‑event‑gen | Synthetic event generator for identity‑based attack simulations. | https://ith-event-gen-wcax3xalza-uc.a.run.app |
| ith‑digital‑twin | Behavioral modeling and deviation scoring. | Cloud Run: ith-digital-twin |
| ith‑alert | Alert webhook receiver and optional Slack forwarder. | Cloud Run: ith-alert |
| quantum‑guardian | Evaluates cryptographic exposure risk (Quantum Exposure Score – QES). | https://quantum-guardian-1054075376433.us-central1.run.app |

---

## Key Capabilities

- Baseline seven detection rules covering major identity attack vectors.  
- Digital Twin enrichment for user‑behavior baselines.  
- Honey Identity traps for decoy user and token monitoring.  
- Quantum Guardian module for token cryptographic risk.  
- Centralized dashboards and rule‑based alerts via Elastic Security.

---

## Technology Stack

- Compute: Google Cloud Run (FastAPI, Next.js)  
- Data: Elastic Cloud (Elasticsearch + Kibana)  
- Language: Python 3.10 / Node.js 20  
- CI/CD: Google Cloud Build  
- Observability: Cloud Logging, Elastic dashboards

---

## Documentation

- [README_RUNBOOK.md](README_RUNBOOK.md) – Deployment and operations guide  
- [INSTRUCTIONS_FOR_JUDGES.md](INSTRUCTIONS_FOR_JUDGES.md) – Judge testing guide

---

### Judge Access
To view live detections:

- **Kibana URL:** [https://4e09aacaaf5546ea985fe43d16a0a09d.us-central1.gcp.cloud.es.io/app/security/alerts](https://4e09aacaaf5546ea985fe43d16a0a09d.us-central1.gcp.cloud.es.io/app/security/alerts)
- **Username:** `ith_judge`
- **Password:** `Hackathon2025`
- **Access Level:** Read-only (Security → Alerts, Discover)

---

## License

Apache‑2.0
