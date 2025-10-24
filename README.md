# Identity Threat Hunter (ITH)

Live Website: https://koushik2296.github.io/identity-threat-hunter/

Identity Threat Hunter (ITH) is a cloud‑native identity‑security analytics platform built on **Google Cloud Run** and **Elastic Cloud** with **Vertex AI** enrichment. It ingests authentication events, enriches them with AI‑generated context and scenarios, and generates real‑time alerts for identity‑driven threats.

---

## Architecture Overview

*Architecture diagram is placed directly below this Overview, matching the live site layout.*

```
[User / Judge] → ith-ui (Analyst UI, Cloud Run)
                  │
                  ├──> ith-event-gen → ith-ingestor ──► Elastic Cloud (ith-events*)
                  │                        │
                  │                        └─► Vertex AI (Gemini) ⇢ ai.summary / ai.confidence / event.scenario
                  │
                  ├──> quantum-guardian ──► Elastic (quantum-guardian*)
                  └──> Kibana (Rules & Alerts)
```

---

## Services

| Service | Purpose | Deployment |
|---|---|---|
| **ith-ui** | Analyst interface for scenario triggers and demonstrations. | https://ith-ui-1054075376433.us-central1.run.app/ |
| **ith-ingestor** | Receives events, calls Vertex AI to enrich, indexes to Elastic. | https://ith-ingestor-wcax3xalza-uc.a.run.app/ingest |
| **ith-event-gen** | Synthetic event generator for attack simulations. | https://ith-event-gen-wcax3xalza-uc.a.run.app |
| **quantum-guardian** | Produces cryptographic exposure findings (QES). | https://quantum-guardian-1054075376433.us-east4.run.app |
| **ith-alert** | Optional webhook receiver for alert actions. | Cloud Run: ith-alert |

---

## AI Module (Vertex AI Enrichment)

- **Model:** Gemini via Vertex AI (Google Cloud only — compliant with hackathon AI rules).
- **Fields added to events:**

```json
{
  "ai.enriched": true,
  "ai.summary": "Detected impossible travel with inconsistent MFA patterns",
  "ai.confidence": 0.9,
  "event.scenario": "impossible_travel",
  "rule.explanation": "AI fusion: correlated geo anomaly and password spraying indicators"
}
```

---

## Key Capabilities

- Seven baseline identity detections + Honey Identity traps.
- AI‑generated risk explanations on alerts (<code>rule.explanation</code>).
- Quantum Guardian module (QES scoring) as an add‑on.
- Dashboards and rule‑based alerts via Elastic Security.

---

## Technology Stack

- **Compute:** Google Cloud Run (FastAPI / Node.js)
- **AI:** Vertex AI (Gemini) — no non‑Google AI services used
- **Data:** Elastic Cloud (Elasticsearch + Kibana)
- **CI/CD:** Google Cloud Build
- **Observability:** Cloud Logging, Elastic Dashboards

---

## Judge Access (Read‑Only)

| Resource | Link |
|---|---|
| **Kibana Alerts (Default Space)** | https://4e09aacaaf5546ea985fe43d16a0a09d.us-east4.gcp.cloud.es.io/app/security/alerts |
| **ITH UI (Cloud Run)** | hhttps://ith-ui-1054075376433.us-central1.run.app/ |

**Judge Credentials**  
Username: `ith_judge`  
Password: `Hackathon2025`  
Access: Read‑only (Security → Alerts, Discover)

---

## Quick Start (Deployment Guide)

**Need a technical deep‑dive or assistance? See the detailed [README_RUNBOOK.md](README_RUNBOOK.md).**

### Prerequisites
- Active Google Cloud Project (billing enabled)
- Enable APIs: Cloud Build, Cloud Run, IAM, Secret Manager, **Vertex AI**
- Elastic Cloud deployment (Elasticsearch + Kibana)
- Elastic API Key
- gcloud CLI authenticated

### Deployment Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/koushik2296/identity-threat-hunter.git
   cd identity-threat-hunter
   ```

2. **Set environment**
   ```bash
   export PROJECT="<YOUR_GCP_PROJECT>"
   export REGION="us-east4"
   export ELASTIC_CLOUD_URL="<ELASTIC_URL>"
   export ELASTIC_API_KEY="<ELASTIC_API_KEY>"
   export VERTEX_LOCATION="us-east4"
   export VERTEX_MODEL="gemini-2.5-flash"   
   ```

3. **Deploy Ingestor (AI‑enriched)**
   ```bash
   gcloud run deploy ith-ingestor      --project $PROJECT      --region $REGION      --source ./services/ingestor      --allow-unauthenticated      --set-env-vars ELASTIC_CLOUD_URL=$ELASTIC_CLOUD_URL,ELASTIC_API_KEY=$ELASTIC_API_KEY,ELASTIC_INDEX=ith-events,VERTEX_LOCATION=$VERTEX_LOCATION,VERTEX_MODEL=$VERTEX_MODEL
   ```

4. **Deploy Event Generator**
   ```bash
   gcloud run deploy ith-event-gen      --project $PROJECT      --region $REGION      --source ./services/event-gen      --allow-unauthenticated      --set-env-vars INGEST_URL=$(gcloud run services describe ith-ingestor --region $REGION --format="value(status.url)")/ingest
   ```

5. **Deploy Optional Services** (`ith-ui`, `quantum-guardian`, `ith-alert`)
   ```bash
   gcloud run deploy ith-ui --project $PROJECT --region $REGION --source ./services/ith-ui --allow-unauthenticated
   gcloud run deploy quantum-guardian --project $PROJECT --region $REGION --source ./addons/quantum-guardian --allow-unauthenticated
   ```

6. **Kibana Data Views**
   - *Stack Management → Data Views* — add `ith-events*` and `quantum-guardian*` with `@timestamp`

7. **Import Detection Rules**
   - *Security → Rules → Import* — import `rules.json` and enable all

---

## Synthetic Alert Burst (Demo)

```powershell
$IngestUrl = "<ITH_INGESTOR_URL>/ingest"
.\scripts\ITH_Burst_Trigger.ps1 -Mode ingestor -IngestUrl $IngestUrl -BurstSeconds 60
```

Expected AI fields in **Discover** on `ith-events*`:
- `ai.enriched:true`, `ai.summary`, `ai.confidence`, `event.scenario`
- Alerts show `rule.explanation`

---

## Troubleshooting

- **Events but no alerts:** Check rule index pattern and schedule.
- **Missing AI fields:** Ensure `VERTEX_MODEL`/`VERTEX_LOCATION` are set and service account has `roles/aiplatform.user`.
- **Kibana session errors:** Use Chrome Incognito or clear cookies for the Elastic domain.

---

## License

Apache‑2.0

_Last updated: 2025‑10‑21_



## System Update Summary (October 23, 2025)
- **AI Model:** Upgraded to Vertex AI `gemini-2.5-flash` for advanced contextual summaries.
- **Indices:** Now dual-ingest into `ith-events` (primary) and `quantum-guardian` (AI-extended findings).
- **Rules:** Introduced 30 strict-match rules ensuring alerts trigger only for intended detections.
- **Correlation ID:** Each event includes a `correlation_id` for linked multi-stage identity detections.

### Endpoint Reference
| Component | Purpose | URL |
|------------|----------|-----|
| Analyst UI | Frontend for detections | https://ith-ui-1054075376433.us-central1.run.app/ |
| ITH Ingestor API | Cloud Run enrichment service | https://ith-ingestor-1054075376433.us-central1.run.app/ingest |
| Elastic Cloud | Detection and analytics backend | https://f5df49d7c58f4beeafe303718a943a44.us-central1.gcp.cloud.es.io |
| Quantum Guardian | Internal AI add-on index | (Integrated module) |

