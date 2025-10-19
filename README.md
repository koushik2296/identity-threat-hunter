# Identity Threat Hunter (ITH)
Live Website: https://koushik2296.github.io/identity-threat-hunter/

Identity Threat Hunter (ITH) is a professional, cloud-native identity-security analytics platform built on **Google Cloud Run** and **Elastic Cloud**. It ingests authentication events, enriches them with contextual and behavioral intelligence, and generates real-time alerts for identity-based threat scenarios.

---

## Architecture Overview

```
[User / Judge] → ith-ui (Analyst UI)
                  │
                  ├──> ith-event-gen → ith-ingestor → Elastic Cloud (ith-events)
                  │                                   │
                  │                                   ├─ Digital Twin
                  │                                   ├─ Honey Identity
                  │                                   ├─ Quantum Guardian
                  │                                   └─ Kibana Alerts
                  │
                  └──> ith-alert (Webhook Integration)
```

---

## Services

| Service | Purpose | Deployment |
|----------|----------|------------|
| **ith-ui** | Analyst interface for scenario triggers and demonstrations. | https://ith-ui-1054075376433.us-central1.run.app |
| **ith-ingestor** | FastAPI endpoint receiving events and indexing to Elastic. | https://ith-ingestor-wcax3xalza-uc.a.run.app/ingest |
| **ith-event-gen** | Synthetic event generator for identity-based attack simulations. | https://ith-event-gen-wcax3xalza-uc.a.run.app |
| **ith-digital-twin** | Behavioral modeling and deviation scoring. | Cloud Run: ith-digital-twin |
| **ith-alert** | Alert webhook receiver and optional Slack forwarder. | Cloud Run: ith-alert |
| **quantum-guardian** | Evaluates cryptographic exposure risk (Quantum Exposure Score – QES). | https://quantum-guardian-1054075376433.us-central1.run.app |

---

## Key Capabilities

- Seven detection rules covering major identity attack vectors.
- Digital Twin enrichment for user-behavior baselines.
- Honey Identity traps for decoy user and token monitoring.
- Quantum Guardian module for token cryptographic risk.
- Centralized dashboards and rule-based alerts via Elastic Security.

---

## Technology Stack

- **Compute:** Google Cloud Run (FastAPI, Next.js)
- **Data:** Elastic Cloud (Elasticsearch + Kibana)
- **Language:** Python 3.10 / Node.js 20
- **CI/CD:** Google Cloud Build
- **Observability:** Cloud Logging, Elastic Dashboards

---

## Judge Access (Read-Only)

| Resource | Link |
|-----------|------|
| **Kibana Alerts (Default Space)** | [https://4e09aacaaf5546ea985fe43d16a0a09d.us-central1.gcp.cloud.es.io/app/security/alerts](https://4e09aacaaf5546ea985fe43d16a0a09d.us-central1.gcp.cloud.es.io/app/security/alerts) |
| **ITH UI (Cloud Run)** | https://ith-ui-1054075376433.us-central1.run.app |

**Judge Credentials**  
Username: `ith_judge`  
Password: `Hackathon2025`  
Access: Read-only (Security → Alerts, Discover)  

---

## Quick Start (Deployment Guide)

### Prerequisites
- Active Google Cloud Project (billing enabled)
- Elastic Cloud deployment (Elasticsearch + Kibana)
- API Key for Elastic Cloud
- gcloud CLI installed and authenticated

### Deployment Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/koushik2296/identity-threat-hunter.git
   cd identity-threat-hunter
   ```

2. **Deploy Ingestor Service**
   ```bash
   gcloud run deploy ith-ingestor \
     --project <YOUR_GCP_PROJECT> \
     --region us-central1 \
     --source ./services/ingestor \
     --allow-unauthenticated \
     --set-env-vars ELASTIC_CLOUD_URL=<ELASTIC_URL>,ELASTIC_API_KEY=<API_KEY>,ELASTIC_INDEX=ith-events
   ```

3. **Deploy Event Generator**
   ```bash
   gcloud run deploy ith-event-gen \
     --project <YOUR_GCP_PROJECT> \
     --region us-central1 \
     --source ./services/event-gen \
     --allow-unauthenticated \
     --set-env-vars INGEST_URL=<ITH_INGESTOR_URL>/ingest
   ```

4. **Deploy Optional Services** (`ith-ui`, `ith-alert`, `quantum-guardian`, `ith-digital-twin`)
   ```bash
   gcloud run deploy ith-ui --project <YOUR_GCP_PROJECT> --region us-central1 --source ./services/ith-ui --allow-unauthenticated
   ```

5. **Configure Kibana Data View**
   - Go to *Kibana → Stack Management → Data Views*
   - Add `ith-events*` with `@timestamp`

6. **Import Detection Rules**
   - *Kibana → Security → Rules → Import →* select the provided `rules.json`
   - Enable all rules.

---

## Demonstration (Synthetic Alert Burst)

Use the **Burst Trigger** PowerShell script to generate test alerts.

```powershell
$IngestUrl = "https://ith-ingestor-wcax3xalza-uc.a.run.app/ingest"
.\scripts\ITH_Burst_Trigger.ps1 -Mode ingestor -IngestUrl $IngestUrl -BurstSeconds 60
```

Expected alerts:
- Credential stuffing
- Impossible travel
- VSS shadow tampering
- Honey Identity activity

> Verify detections under **Security → Alerts** in Kibana.

---

## Repository Structure

```
/services
  /ingestor           - Cloud Run: Receives JSON events and writes to Elastic
  /event-gen          - Cloud Run: Generates synthetic identity events
  /alert-webhook      - Cloud Run: Handles rule response actions
  /ith-ui             - Cloud Run: Web interface for judges
/rules                - Elastic detection rules (JSON)
/scripts              - PowerShell trigger scripts
/runbook              - Judge runbook and instructions
```

---

## Troubleshooting

- **Events visible but no alerts:** Verify rule index pattern and scheduling.
- **Kibana session errors:** Use Chrome Incognito or clear cookies for the Elastic domain.
- **Slow push or Git errors:** Large binaries were removed; keep them out via `.gitignore`.

---

## License

Apache-2.0

_Last updated: 2025-10-18_
