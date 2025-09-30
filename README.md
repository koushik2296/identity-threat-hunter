# Identity Threat Hunter

Identity Threat Hunter is a prototype security analytics pipeline built on **Google Cloud Run** and **Elastic Cloud**. It ingests login events, applies basic risk scoring (e.g. impossible travel detection), and exposes dashboards, alerts, and a minimal analyst UI.

---

## Architecture

- **Ingestor (FastAPI)**  
  Receives login events → indexes them into Elastic (`ith-events*` index).
- **Event Generator (FastAPI)**  
  Generates synthetic login events for testing.
- **Alert Webhook (FastAPI)**  
  Receives alert actions from Elastic rules → logs them (optional forward to Slack).
- **Analyst UI (Next.js)**  
  Lightweight Cloud Run UI scaffold for analysts.
- **Elastic Cloud**  
  Stores data, dashboards, and runs detection rules.

```
[Event Generator] → [Ingestor] → [Elastic] ← [Analyst UI]
                                    │
                                    └→ [Alert Webhook] → (optional Slack)
```

---

## Features

- **Impossible Travel Detection**  
  Flags logins where speed/distance between sequential logins is unrealistic.
- **Risk Scoring**  
  Events enriched with `event.risk_score` and explanation fields.
- **Dashboards**  
  Kibana dashboards show user login activity and risky sign-ins.
- **Alerts**  
  Elastic detection rule triggers webhook calls for suspicious activity.

---

## Live Demo (Cloud Run)

- Ingestor: `<INGESTOR_URL>`
- Event Generator: `<EVENT_GEN_URL>`
- Alert Webhook: `<ALERT_URL>`
- Analyst UI: `<UI_URL>`

---

## Setup

### 1. Prerequisites
- Google Cloud project with billing enabled
- Elastic Cloud deployment and API key
- gcloud CLI installed

### 2. Create Elastic index template
```bash
curl -X PUT "$ELASTIC_CLOUD_URL/_index_template/ith-template"   -H "Authorization: ApiKey $ELASTIC_API_KEY"   -H "Content-Type: application/json"   --data-binary @elastic/index_template.json
```

### 3. Deploy services to Cloud Run
```bash
# Ingestor
gcloud builds submit services/ingestor --tag gcr.io/$PROJECT_ID/ith-ingestor
gcloud run deploy ith-ingestor --image gcr.io/$PROJECT_ID/ith-ingestor   --region=us-central1 --allow-unauthenticated   --set-env-vars=ELASTIC_CLOUD_URL=$ELASTIC_CLOUD_URL,ELASTIC_API_KEY=$ELASTIC_API_KEY,ELASTIC_INDEX=ith-events

# Event Generator
gcloud builds submit services/event-gen --tag gcr.io/$PROJECT_ID/ith-event-gen
gcloud run deploy ith-event-gen --image gcr.io/$PROJECT_ID/ith-event-gen   --region=us-central1 --allow-unauthenticated   --set-env-vars=INGEST_URL=<INGESTOR_URL>

# Alert Webhook
gcloud builds submit services/alert-webhook --tag gcr.io/$PROJECT_ID/ith-alert
gcloud run deploy ith-alert --image gcr.io/$PROJECT_ID/ith-alert   --region=us-central1 --allow-unauthenticated   --set-env-vars=SLACK_WEBHOOK_URL=<optional>

# Analyst UI
gcloud builds submit services/analyst-ui --tag gcr.io/$PROJECT_ID/ith-ui
gcloud run deploy ith-ui --image gcr.io/$PROJECT_ID/ith-ui   --region=us-central1 --allow-unauthenticated
```

---

## Usage

### Generate events
```bash
curl -X POST "<EVENT_GEN_URL>/burst?user=alice&n=5&seconds=30"
```

### View in Kibana
1. Create a data view for `ith-events*` with `@timestamp`.  
2. Open **Discover** to see login events.  
3. Import `elastic/sample_dashboards.ndjson` for visualizations.

### Create a detection rule
1. Kibana → **Stack Management → Rules**.  
2. Create a rule (KQL query):  
   ```
   event.risk_score > 0.7 AND event.action: login
   ```  
3. Schedule: every 1 minute.  
4. Add **Webhook action** pointing to:  
   ```
   <ALERT_URL>/alert
   ```

---

## Repository Layout
```
services/
  ingestor/       # FastAPI: receives events → Elastic
  event-gen/      # FastAPI: generates synthetic events
  alert-webhook/  # FastAPI: receives Elastic alerts → logs/Slack
  analyst-ui/     # Next.js UI
elastic/          # index template, dashboards, rules
data/             # sample events
```

---

## License
Apache-2.0
