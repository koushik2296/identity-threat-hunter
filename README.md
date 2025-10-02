# Identity Threat Hunter

Identity Threat Hunter is a prototype security analytics pipeline built on **Google Cloud Run** and **Elastic Cloud**.  
It ingests synthetic and real login events, applies advanced risk scoring, and generates alerts for common identity-related attack scenarios.  
A lightweight UI and webhook handler are included for analysts and integrations.

---

## Key Features

- **Event ingestion**  
  - FastAPI-based service receives login events and enriches them with risk scoring.  
  - Supports custom index templates in Elasticsearch.  

- **Synthetic event generation**  
  - FastAPI-based generator simulates realistic scenarios:
    - Impossible Travel  
    - MFA Bypass  
    - Brute Force (multiple failures then success)  
    - Privilege Escalation  
    - Rare Country login  
    - Credential Stuffing  
    - ASN / ISP Change  

- **Risk scoring**  
  - Ingestor computes `event.risk_score` and adds `event.explanation` with reasons (e.g. `Impossible travel`, `mfa_bypass`).  
  - Uses geo distance, ASN, MFA flags, and failure counts.  

- **Digital Twin Add-On**  
  - New service that builds **per-user behavioral profiles** from historical login events.  
  - Provides additional deviation metrics (`event.profile_dev`) and blended risk scoring.  
  - Writes enriched results to a separate index `ith-events-enriched`.  
  - Useful for detecting **unusual behavior** that doesn’t match historical norms.  

- **Dashboards & detection rules**  
  - Kibana dashboards visualize both raw and enriched events.  
  - Detection rules trigger alerts via Webhook connector for all scenarios.  

- **Alerting & integration**  
  - Webhook service receives JSON alerts from Kibana rules.  
  - Optionally forwards alerts to Slack.  

- **Analyst UI**  
  - Minimal Next.js front-end for analysts.  

---

## Architecture

```
[Event Generator] → [Ingestor] → [Elastic Cloud] ← [Analyst UI]
                                    │
                                    ├→ [Digital Twin] → [ith-events-enriched]
                                    │
                                    └→ [Alert Webhook] → (Slack, other SIEMs)
```

- **Ingestor**: FastAPI, enriches and indexes events into Elastic.  
- **Event Generator**: FastAPI, simulates attack scenarios.  
- **Alert Webhook**: FastAPI, receives alert POSTs from Elastic rules.  
- **Analyst UI**: Next.js scaffold for visual inspection.  
- **Digital Twin**: FastAPI, builds profiles and enriches recent events.  
- **Elastic Cloud**: Data store, dashboards, and rules engine.  

---

## Setup

### Prerequisites
- Google Cloud project with billing enabled  
- Elastic Cloud deployment + API key  
- `gcloud` CLI installed and authenticated  

### 1. Create Elasticsearch index template
```bash
curl -X PUT "$ELASTIC_CLOUD_URL/_index_template/ith-template"   -H "Authorization: ApiKey $ELASTIC_API_KEY"   -H "Content-Type: application/json"   --data-binary @elastic/index_template.json
```

### 2. Deploy services to Cloud Run
Replace placeholders with your own project ID, URLs, and keys.

```bash
# Ingestor
gcloud builds submit services/ingestor --tag gcr.io/$PROJECT_ID/ith-ingestor
gcloud run deploy ith-ingestor   --image gcr.io/$PROJECT_ID/ith-ingestor   --region=us-central1 --allow-unauthenticated   --set-env-vars=ELASTIC_CLOUD_URL=<ELASTIC_URL>,ELASTIC_API_KEY=<ELASTIC_KEY>,ELASTIC_INDEX=ith-events

# Event Generator
gcloud builds submit services/event-gen --tag gcr.io/$PROJECT_ID/ith-event-gen
gcloud run deploy ith-event-gen   --image gcr.io/$PROJECT_ID/ith-event-gen   --region=us-central1 --allow-unauthenticated   --set-env-vars=INGEST_URL=<INGESTOR_URL>

# Alert Webhook
gcloud builds submit services/alert-webhook --tag gcr.io/$PROJECT_ID/ith-alert
gcloud run deploy ith-alert   --image gcr.io/$PROJECT_ID/ith-alert   --region=us-central1 --allow-unauthenticated   --set-env-vars=SLACK_WEBHOOK_URL=<optional>

# Analyst UI
gcloud builds submit services/analyst-ui --tag gcr.io/$PROJECT_ID/ith-ui
gcloud run deploy ith-ui   --image gcr.io/$PROJECT_ID/ith-ui   --region=us-central1 --allow-unauthenticated

# Digital Twin
gcloud builds submit services/digital-twin --tag gcr.io/$PROJECT_ID/ith-digital-twin
gcloud run deploy ith-digital-twin   --image gcr.io/$PROJECT_ID/ith-digital-twin   --region=us-central1 --allow-unauthenticated   --set-env-vars=ELASTIC_CLOUD_URL=<ELASTIC_URL>,ELASTIC_API_KEY=<ELASTIC_KEY>,EVENTS_INDEX=ith-events,PROFILE_INDEX=ith-users-profile,ENRICHED_INDEX=ith-events-enriched,PROFILE_ALPHA=0.1
```

---

## Usage

### Generate test scenarios
```powershell
$EG = "<EVENT_GEN_URL>"
$IG = "<INGESTOR_URL>"
$encIG = [uri]::EscapeDataString($IG)

# Impossible travel
Invoke-RestMethod -Uri "$EG/burst_scenario?scenario=impossible_travel&ingest_url=$encIG" -Method POST
```

Repeat with `mfa_bypass`, `brute_force_then_success`, `privilege_escalation`, `rare_country`, `credential_stuffing`, `asn_change`.

### Build profiles and enrich events
```powershell
$DT = "<DIGITAL_TWIN_URL>"

# Build profiles (last 7 days)
Invoke-RestMethod -Uri "$DT/build_profiles?minutes=10080" -Method POST

# Enrich recent events (last 3 hours)
Invoke-RestMethod -Uri "$DT/enrich_recent?minutes=180" -Method POST
```

### View in Kibana
1. Create data view for `ith-events*` with `@timestamp`.  
2. Create data view for `ith-events-enriched*` with `@timestamp`.  
3. Switch between raw and enriched views in Discover.  
4. Verify enriched fields like `event.profile_dev`, `event.risk_score`, `event.explanation`.  

### Rules & Alerts
- Rules created for all scenarios, including profile-deviation anomalies.  
- Connector posts to `<ALERT_URL>/alert`.  
- Alerts visible in Kibana and forwarded to Slack if configured.  

---

## Improvements Made

- Added **Digital Twin add-on** with profile-based enrichment.  
- Implemented `/build_profiles` and `/enrich_recent` APIs.  
- Fixed PowerShell JSON quoting issues by using `--data-binary`.  
- Corrected Cloud Run env var syntax (comma separation + expansion).  
- Validated health checks with `/healthz/`.  
- Confirmed event flow end-to-end for both raw and enriched indices.  
- Added `.gitignore` to exclude secrets and build artifacts.  
- README now includes Digital Twin instructions, placeholders only (no sensitive values).  

---

## Repository Layout
```
services/
  ingestor/        # FastAPI: enrich & index events
  event-gen/       # FastAPI: simulate attack scenarios
  alert-webhook/   # FastAPI: webhook endpoint (optionally Slack)
  analyst-ui/      # Next.js UI scaffold
  digital-twin/    # FastAPI: profile builder & enrichment
elastic/           # index template, saved searches, dashboards
```

---

## License
Apache-2.0
