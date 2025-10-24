# Identity Threat Hunter — Technical Runbook (AI‑Enriched, step‑by‑step)

## Overview
This runbook provides a complete sequence to clone, deploy, and validate Identity Threat Hunter (ITH) with **Vertex AI enrichment** on Google Cloud Run and Elastic Cloud.

---

## A. Prerequisites
1. Google Cloud project with billing enabled.
2. Elastic Cloud deployment (Elasticsearch + Kibana).
3. Installed tools: `git`, `gcloud`, `jq`, `curl` (and optional PowerShell).
4. Enable APIs:
   ```bash
   gcloud services enable cloudbuild.googleapis.com run.googleapis.com iam.googleapis.com secretmanager.googleapis.com aiplatform.googleapis.com
   ```
5. Service Account and Roles:
   ```bash
   export PROJECT="<YOUR_GCP_PROJECT>"
   gcloud iam service-accounts create ith-deployer --display-name "ITH Deployer"
   gcloud projects add-iam-policy-binding $PROJECT --member="serviceAccount:ith-deployer@$PROJECT.iam.gserviceaccount.com" --role="roles/run.admin"
   gcloud projects add-iam-policy-binding $PROJECT --member="serviceAccount:ith-deployer@$PROJECT.iam.gserviceaccount.com" --role="roles/cloudbuild.builds.editor"
   gcloud projects add-iam-policy-binding $PROJECT --member="serviceAccount:ith-deployer@$PROJECT.iam.gserviceaccount.com" --role="roles/secretmanager.secretAccessor"
   gcloud projects add-iam-policy-binding $PROJECT --member="serviceAccount:ith-deployer@$PROJECT.iam.gserviceaccount.com" --role="roles/aiplatform.user"
   ```

---

## B. Clone the repository
```bash
git clone https://github.com/<your-org>/identity-threat-hunter.git
cd identity-threat-hunter
ls -la
```
**Expected:** `services/ingestor`, `services/analyst-ui`, `services/event-gen`, `addons/quantum-guardian`.

---

## C. Environment setup
```bash
export PROJECT="ith-koushik-hackathon"
export REGION="us-east4"
export TAG="$(date +%Y%m%d%H%M%S)"
export GCR_HOST="gcr.io/$PROJECT"
export ELASTIC_CLOUD_URL="<ELASTIC_URL>"
export ELASTIC_API_KEY="<ELASTIC_API_KEY>"
export VERTEX_LOCATION="us-east4"
export VERTEX_MODEL="gemini-2.5-flash"  
gcloud auth login
gcloud config set project $PROJECT
gcloud config set run/region $REGION
```

---

## D. Elastic Cloud configuration
1. Create an API key in **Kibana → Stack Management → Security → API Keys**.
2. Test connection:
   ```bash
   curl -s -H "Authorization: ApiKey <ELASTIC_API_KEY>" "$ELASTIC_CLOUD_URL/_cluster/health" | jq .
   ```

---

## E. Secrets management (optional)
```bash
echo -n "$ELASTIC_API_KEY" | gcloud secrets create elastic-api-key --data-file=-
```

---

## F. Deploy services

### 1) Ingestor (AI‑enriched)
```bash
cd services/ingestor
gcloud builds submit . --tag "$GCR_HOST/ith-ingestor:$TAG"
gcloud run deploy ith-ingestor   --image "$GCR_HOST/ith-ingestor:$TAG"   --region $REGION --allow-unauthenticated   --set-env-vars "ELASTIC_CLOUD_URL=$ELASTIC_CLOUD_URL,ELASTIC_API_KEY=$ELASTIC_API_KEY,ELASTIC_INDEX=ith-events,VERTEX_LOCATION=$VERTEX_LOCATION,VERTEX_MODEL=$VERTEX_MODEL"
```
**Expected:** URL displayed (save as `$INGEST_URL`).

**Test:**
```bash
curl -i -X POST "$INGEST_URL/ingest" -H "Content-Type: application/json" -d '{"@timestamp":"2025-10-19T00:00:00Z","event":{"category":"authentication"},"message":"ai-smoke"}'
```

### 2) Event Generator
```bash
cd ../../services/event-gen
gcloud builds submit . --tag "$GCR_HOST/ith-event-gen:$TAG"
gcloud run deploy ith-event-gen --image "$GCR_HOST/ith-event-gen:$TAG"   --region $REGION --allow-unauthenticated   --set-env-vars "INGEST_URL=$INGEST_URL/ingest"
```

### 3) Analyst UI
```bash
cd ../../services/analyst-ui
gcloud builds submit . --tag "$GCR_HOST/ith-ui:$TAG"
gcloud run deploy ith-ui --image "$GCR_HOST/ith-ui:$TAG"   --region $REGION --allow-unauthenticated   --set-env-vars "INGEST_URL=$INGEST_URL/ingest"
```

### 4) Quantum Guardian
```bash
cd ../../addons/quantum-guardian
gcloud builds submit . --tag "$GCR_HOST/quantum-guardian:$TAG"
gcloud run deploy quantum-guardian --image "$GCR_HOST/quantum-guardian:$TAG"   --region $REGION --allow-unauthenticated   --set-env-vars "ELASTIC_CLOUD_URL=$ELASTIC_CLOUD_URL,ELASTIC_API_KEY=$ELASTIC_API_KEY,ELASTIC_INDEX_TARGET=quantum-guardian"
```

---

## G. Import detection rules
1. In Kibana: **Security → Rules → Import** → upload `ITH_Baseline7_Rules.ndjson` (plus Honey & Quantum rules).
2. Enable all rules.
3. Data Views: `ith-events*`, `quantum-guardian*` (timestamp: `@timestamp`).

---

## H. Trigger tests

### 0) Burst Trigger (PowerShell) — **Recommended for demo**
```powershell
$IngestUrl = "<ITH_INGESTOR_URL>/ingest"
.\scripts\ITH_Burst_Trigger.ps1 -Mode ingestor -IngestUrl $IngestUrl -BurstSeconds 60
```
Generates multiple scenarios (Impossible Travel, MFA Bypass, Honey Identity, etc.) in a short window for validation.

### 1) Smoke Test (curl)
```bash
curl -X POST "$INGEST_URL/ingest" -H "Content-Type: application/json" -d '
{"@timestamp":"2025-10-19T00:00:00Z","event":{"category":"authentication","action":"login","outcome":"success"},"user":{"name":"smoketest"},"source":{"ip":"198.51.100.60"}}
'
```

### 2) Impossible Travel (PowerShell)
```powershell
$IG = "$INGEST_URL/ingest"
$doc = @{
  "@timestamp" = (Get-Date).ToUniversalTime().ToString("o")
  event = @{ category="authentication"; action="login"; outcome="success"; kind="event" }
  user = @{ name="manual_test" }
  source = @{ ip="198.51.100.60" }
  risk = @{ score=90; reason="Manual test: impossible_travel" }
} | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method POST $IG -ContentType "application/json" -Body $doc
```

### 3) Quantum Guardian
```bash
curl -X POST "https://<ith-ui-url>/api/trigger-quantum"
```

---

## I. Validation (Kibana)
- **Alerts:** Security → Alerts — open any alert and review **rule.explanation**.
- **Discover:** filter `ai.enriched:true` on `ith-events*` and verify `ai.summary`, `ai.confidence`, and `event.scenario` fields.
- **KQL examples:**
  ```
  ai.enriched:true and event.scenario:impossible_travel
  ```

---

## J. Troubleshooting
| Issue | Check |
|---|---|
| No alerts | Rule enabled and scheduled; index pattern matches |
| Missing AI fields | Vertex env vars set; SA has `roles/aiplatform.user` |
| 404 Not Found | Wrong service URL path |
| 401 Unauthorized | Invalid Elastic API key |
| CORS errors | Set Access-Control-Allow-Origin on UI/API |
| Cloud Build fails | `gcloud builds log <id>` |

---

## K. Cleanup
```bash
gcloud run services delete ith-ui --region $REGION --project $PROJECT
gcloud run services delete ith-ingestor --region $REGION --project $PROJECT
gcloud run services delete ith-event-gen --region $REGION --project $PROJECT
gcloud run services delete quantum-guardian --region $REGION --project $PROJECT
gcloud secrets delete elastic-api-key --quiet || true
```

---

## L. Environment Template
```
PROJECT=ith-koushik-hackathon
REGION=us-east4
ELASTIC_CLOUD_URL=cloud-id:...
ELASTIC_API_KEY=REPLACE_WITH_SECRET
INGEST_URL=https://<ith-ingestor>.run.app/ingest
VERTEX_LOCATION=us-east4
VERTEX_MODEL=gemini-2.5-flash
JUDGE_USERNAME=ith_judge
# JUDGE_PASSWORD stored in Secret Manager
```

---

## M. CI/CD (GitHub Actions)
```yaml
name: Deploy ITH
on: [push]
jobs:
  build-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google-github-actions/setup-gcloud@v2
        with:
          project_id: ${{ secrets.GCP_PROJECT }}
          service_account_key: ${{ secrets.GCP_SA_KEY }}
      - run: gcloud builds submit services/ingestor --tag "gcr.io/${{ secrets.GCP_PROJECT }}/ith-ingestor:${{ github.run_number }}"
      - run: gcloud run deploy ith-ingestor --image "gcr.io/${{ secrets.GCP_PROJECT }}/ith-ingestor:${{ github.run_number }}" --region us-east4 --allow-unauthenticated --set-env-vars "ELASTIC_CLOUD_URL=${{ secrets.ELASTIC_URL }},ELASTIC_API_KEY=${{ secrets.ELASTIC_API_KEY }},ELASTIC_INDEX=ith-events,VERTEX_LOCATION=us-east4,VERTEX_MODEL=gemini-2.5-flash"
```

---

## N. Checklist
- [ ] Clone repo
- [ ] Configure env variables
- [ ] Deploy services (ingestor/event-gen/ui/quantum)
- [ ] Import Elastic rules
- [ ] Trigger tests
- [ ] Validate AI fields and alerts
- [ ] Cleanup


---

## F.1 Additional Optional Services

### 5) Analyst Notes
AI-generated note-taking microservice that captures analyst insights and appends contextual summaries to detected alerts.
```bash
cd services/analyst-notes
gcloud builds submit . --tag "$GCR_HOST/analyst-notes:$TAG"
gcloud run deploy analyst-notes --image "$GCR_HOST/analyst-notes:$TAG" --region $REGION --allow-unauthenticated
```

### 6) Digital Twin
Identity modeling engine that detects deviations between real-world user behavior and their baseline “digital twin.”
```bash
cd services/ith-digital-twin
gcloud builds submit . --tag "$GCR_HOST/ith-digital-twin:$TAG"
gcloud run deploy ith-digital-twin --image "$GCR_HOST/ith-digital-twin:$TAG" --region $REGION --allow-unauthenticated
```

### 7) UI-AI
Enhanced AI-driven Analyst UI providing adaptive risk summaries and recommendation features.
```bash
cd services/ith-ui-ai
gcloud builds submit . --tag "$GCR_HOST/ith-ui-ai:$TAG"
gcloud run deploy ith-ui-ai --image "$GCR_HOST/ith-ui-ai:$TAG" --region $REGION --allow-unauthenticated
```



## System Enhancements (October 23, 2025)
- **Gemini-2.5-Flash** now powers enrichment summaries and correlation analysis.
- **Dual indices:** `ith-events` (primary) + `quantum-guardian` (secondary) verified via Cloud Run logs.
- **Strict-match detection rules** imported through `ITH_Rules_Final_Strict.ndjson`.
- **Correlation ID linking:** Events linked between indices for unified alert context.
- **External index warnings resolved:** Removed references to `external-security-alerts*`.

### Updated Endpoints
| Service | Description | URL |
|----------|--------------|-----|
| Analyst UI | Frontend for manual test and scenario triggers | https://ith-ui-1054075376433.us-central1.run.app/ |
| Ingestor API | Vertex AI + Elastic enrichment microservice | https://ith-ingestor-1054075376433.us-central1.run.app/ingest |
| Elastic Cloud | Main analytics and alerting | https://f5df49d7c58f4beeafe303718a943a44.us-central1.gcp.cloud.es.io |

### Judge Verification Quick Commands
```powershell
Invoke-RestMethod -Uri "https://ith-ingestor-1054075376433.us-central1.run.app/health"
$body = @{ rule_name = "ITH - Impossible Travel"; event = @{ "event.action"="login"; "user.name"="judge_user" } } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://ith-ingestor-1054075376433.us-central1.run.app/ingest" -Headers @{"Content-Type"="application/json"} -Body $body
```
