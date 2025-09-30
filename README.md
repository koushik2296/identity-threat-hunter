# Identity Threat Hunter

Identity Threat Hunter is a prototype system that detects risky sign-ins such as impossible travel, lateral movement, and suspicious geo/ASN/device patterns. Events are indexed in Elastic and can be explored through Kibana dashboards and a minimal analyst UI. All components are containerized and deployable on Google Cloud Run.

---

## Architecture

- **Analyst UI (Next.js)** on Cloud Run  
- **Event Ingestor (FastAPI)** → writes events to Elastic  
- **Event Generator (FastAPI)** → emits synthetic login events  
- **Alert Webhook (FastAPI)** → receives Elastic rule actions and forwards notifications (e.g., Slack)  
- **Elastic Cloud** for storage, search, dashboards, and detection rules  

```
[Browser UI] → [Cloud Run: analyst-ui] → [Elastic]

[Cloud Scheduler] → [Cloud Run: event-gen] → [Cloud Run: ingestor] → [Elastic]

[Elastic Rule] → [Cloud Run: alert-webhook] → [Slack/Email]
```

### Core detections
- **Impossible travel**: suspicious speed/distance between sequential logins per user  
- **Lateral movement burst**: access to many assets in a short window  
- **Risky login**: unusual country/ASN/device, off-hours activity, TOR/VPN presence  

---

## Quickstart (Google Cloud Run)

**Prerequisites**:  
- Google Cloud project with `gcloud` CLI configured  
- Elastic Cloud deployment and API key  
- Docker or Cloud Build enabled  

1. Enable required APIs:
   ```bash
   gcloud services enable run.googleapis.com pubsub.googleapis.com secretmanager.googleapis.com
   ```

2. Configure environment variables (`.env` file or Secret Manager), see `.env.example`.

3. Create the Elastic index template:
   ```bash
   curl -X PUT "$ELASTIC_CLOUD_URL/_index_template/ith-template"      -H "Authorization: ApiKey $ELASTIC_API_KEY" -H "Content-Type: application/json"      --data-binary @elastic/index_template.json
   ```

4. Build and deploy services:
   ```bash
   # Ingestor
   gcloud builds submit services/ingestor --tag gcr.io/$GCP_PROJECT_ID/ith-ingestor
   gcloud run deploy ith-ingestor --image gcr.io/$GCP_PROJECT_ID/ith-ingestor --allow-unauthenticated --region=$GCP_LOCATION

   # Event generator
   gcloud builds submit services/event-gen --tag gcr.io/$GCP_PROJECT_ID/ith-event-gen
   gcloud run deploy ith-event-gen --image gcr.io/$GCP_PROJECT_ID/ith-event-gen --allow-unauthenticated --region=$GCP_LOCATION

   # Alert webhook
   gcloud builds submit services/alert-webhook --tag gcr.io/$GCP_PROJECT_ID/ith-alert
   gcloud run deploy ith-alert --image gcr.io/$GCP_PROJECT_ID/ith-alert --allow-unauthenticated --region=$GCP_LOCATION

   # Analyst UI
   gcloud builds submit services/analyst-ui --tag gcr.io/$GCP_PROJECT_ID/ith-ui
   gcloud run deploy ith-ui --image gcr.io/$GCP_PROJECT_ID/ith-ui --allow-unauthenticated --region=$GCP_LOCATION
   ```

5. Import Kibana assets:  
   - Dashboards: `elastic/sample_dashboards.ndjson`  
   - Detection rules: `elastic/detection_kuery.ndjson` (point action to your `ith-alert` URL)

6. Generate events by:
   - Calling the event generator `/burst` endpoint  
   - Or posting sample lines from `data/sample_events.jsonl` to the ingestor `/ingest`  

---

## Local development

- Copy `.env.example` → `.env`  
- Python services can run locally with `uvicorn main:app --reload`  
- Analyst UI runs with `npm run dev`  

---

## Repository layout

```
infra/              # Infra scripts
services/
  ingestor/         # FastAPI: receive events → Elastic
  event-gen/        # FastAPI: synthetic events
  alert-webhook/    # FastAPI: alerts → notifications
  analyst-ui/       # Next.js UI
elastic/            # index template, dashboards, rules
data/               # sample events, lists (TOR exits, etc.)
```

---

## License
[Apache-2.0](LICENSE)
