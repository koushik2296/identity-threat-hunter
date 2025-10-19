# Identity Threat Hunter — Technical Runbook (Full, step-by-step)

## Overview
This runbook provides a complete sequence of steps so any user can clone this repository, deploy Identity Threat Hunter (ITH) components to Google Cloud Run, configure Elastic Cloud, and test alert generation. Each step includes expected results and troubleshooting notes.

---

## A. Prerequisites
1. Google Cloud project with billing enabled and IAM roles for deployment (Owner/Editor).
2. Elastic Cloud deployment with Elasticsearch + Kibana.
3. Installed tools: `git`, `gcloud`, `jq`, `curl`, and (optional) PowerShell.
4. APIs enabled:
   ```bash
   gcloud services enable cloudbuild.googleapis.com run.googleapis.com iam.googleapis.com secretmanager.googleapis.com
   ```
5. Create a service account for deployment:
   ```bash
   gcloud iam service-accounts create ith-deployer --display-name "ITH Deployer"
   gcloud projects add-iam-policy-binding $PROJECT --member="serviceAccount:ith-deployer@$PROJECT.iam.gserviceaccount.com" --role="roles/run.admin"
   gcloud projects add-iam-policy-binding $PROJECT --member="serviceAccount:ith-deployer@$PROJECT.iam.gserviceaccount.com" --role="roles/cloudbuild.builds.editor"
   gcloud projects add-iam-policy-binding $PROJECT --member="serviceAccount:ith-deployer@$PROJECT.iam.gserviceaccount.com" --role="roles/secretmanager.secretAccessor"
   ```

---

## B. Clone the repository
```bash
git clone https://github.com/<your-org>/identity-threat-hunter.git
cd identity-threat-hunter
ls -la
```
**Expected:** Directories `services/ingestor`, `services/analyst-ui`, and `addons/quantum-guardian` appear.

---

## C. Environment setup
```bash
export PROJECT="ith-koushik-hackathon"
export REGION="us-central1"
export TAG="$(date +%Y%m%d%H%M%S)"
export GCR_HOST="gcr.io/$PROJECT"

gcloud auth login
gcloud config set project $PROJECT
gcloud config set run/region $REGION
```

---

## D. Elastic Cloud configuration
1. Create Elasticsearch + Kibana deployment.
2. Create an API key in Kibana → Stack Management → Security → API Keys.
3. Save:
   - `ELASTIC_CLOUD_URL`
   - `ELASTIC_API_KEY`
4. Test connection:
   ```bash
   curl -s -H "Authorization: ApiKey <ELASTIC_API_KEY>" "$ELASTIC_CLOUD_URL/_cluster/health" | jq .
   ```

---

## E. Secrets management
```bash
echo -n "<ELASTIC_API_KEY>" | gcloud secrets create elastic-api-key --data-file=-
gcloud secrets versions add elastic-api-key --data-file=<(echo -n "<ELASTIC_API_KEY>")
```

---

## F. Deploy services

### 1. Ingestor
```bash
cd services/ingestor
gcloud builds submit . --tag "$GCR_HOST/ith-ingestor:$TAG"
gcloud run deploy ith-ingestor --image "$GCR_HOST/ith-ingestor:$TAG"   --region $REGION --allow-unauthenticated   --set-env-vars "ELASTIC_CLOUD_URL=<ELASTIC_URL>,ELASTIC_API_KEY=<ELASTIC_KEY>,ELASTIC_INDEX=ith-events"
```
**Expected:** URL displayed (save as `$INGEST_URL`).

**Test:**
```bash
curl -i -X POST "$INGEST_URL/ingest" -H "Content-Type: application/json" -d '{"@timestamp":"2025-10-18T00:00:00Z","event":{"category":"test"},"message":"itest"}'
```

### 2. Analyst UI
```bash
cd ../../services/analyst-ui
gcloud builds submit . --tag "$GCR_HOST/ith-ui:$TAG"
gcloud run deploy ith-ui --image "$GCR_HOST/ith-ui:$TAG"   --region $REGION --allow-unauthenticated   --set-env-vars "INGEST_URL=<INGEST_URL>"
```
**Expected:** UI loads successfully.

### 3. Quantum Guardian
```bash
cd ../../addons/quantum-guardian
gcloud builds submit . --tag "$GCR_HOST/quantum-guardian:$TAG"
gcloud run deploy quantum-guardian --image "$GCR_HOST/quantum-guardian:$TAG"   --region $REGION --allow-unauthenticated   --set-env-vars "ELASTIC_CLOUD_URL=<ELASTIC_URL>,ELASTIC_API_KEY=<ELASTIC_KEY>,ELASTIC_INDEX_TARGET=quantum-guardian"
```

---

## G. Import detection rules
1. In Kibana: **Security → Rules → Import** → upload `ITH_Baseline7_Rules.ndjson`.
2. Enable all rules.
3. Create Data Views: `ith-events*`, `ith-events-enriched*`, `quantum-guardian*`.

---

## H. Trigger tests

### Smoke Test
```bash
curl -X POST "$INGEST_URL/ingest" -H "Content-Type: application/json" -d '{"@timestamp":"2025-10-18T00:00:00Z","event":{"category":"authentication","action":"smoke_test","outcome":"success"},"user":{"name":"manual_test"},"source":{"ip":"198.51.100.60"},"risk":{"score":10}}'
```

### Impossible Travel
```powershell
$IG = "https://ith-ingestor-<id>.run.app/ingest"
$doc = @{
  "@timestamp" = (Get-Date).ToUniversalTime().ToString("o")
  event = @{ category="authentication"; action="login"; outcome="success"; kind="event" }
  user = @{ name="manual_test" }
  source = @{ ip="198.51.100.60" }
  risk = @{ score=90; reason="Manual test: impossible_travel" }
  "event.scenario" = "impossible_travel"
} | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method POST $IG -ContentType "application/json" -Body $doc
```

### Quantum Guardian
```bash
curl -X POST "https://<ith-ui-url>/api/trigger-quantum"
```

---

## I. Validation
- Verify alerts in Kibana → **Security → Alerts**.
- KQL example:
  ```
  event.category:authentication and event.scenario:impossible_travel
  ```
- Expected fields: `rule.name`, `risk.score`, `source.ip`.

---

## J. Troubleshooting
| Issue | Check |
|-------|--------|
| No alerts | Rule enabled and scheduled; event indexed |
| 404 Not Found | Wrong service URL path |
| 401 Unauthorized | Invalid or expired API key |
| CORS errors | Configure Access-Control-Allow-Origin headers |
| Cloud Build fails | Run `gcloud builds log <id>` |

---

## K. Cleanup
```bash
gcloud run services delete ith-ui --region $REGION --project $PROJECT
gcloud run services delete ith-ingestor --region $REGION --project $PROJECT
gcloud run services delete quantum-guardian --region $REGION --project $PROJECT
gcloud secrets delete elastic-api-key
```

---

## L. Environment Template
`.env.template`
```
PROJECT=ith-koushik-hackathon
REGION=us-central1
ELASTIC_CLOUD_URL=cloud-id:...
ELASTIC_API_KEY=REPLACE_WITH_SECRET
INGEST_URL=https://<ith-ingestor>.run.app/ingest
JUDGE_USERNAME=ith_judge
# JUDGE_PASSWORD stored in Secret Manager
```

---

## M. CI/CD (GitHub Actions Example)
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
      - run: gcloud run deploy ith-ingestor --image "gcr.io/${{ secrets.GCP_PROJECT }}/ith-ingestor:${{ github.run_number }}" --region us-central1 --allow-unauthenticated
```

---

## N. Checklist
- [ ] Clone repo
- [ ] Configure env variables
- [ ] Deploy all services
- [ ] Import Elastic rules
- [ ] Trigger tests
- [ ] Verify alerts
- [ ] Cleanup resources

---

## End of Runbook
