# Identity Threat Hunter (ITH) — Technical Runbook

Detailed deployment, configuration, and testing instructions for the Identity Threat Hunter (ITH) platform.

---

## Prerequisites

- Google Cloud project with billing enabled  
- Elastic Cloud deployment with Elasticsearch + Kibana  
- gcloud CLI authenticated  
- PowerShell or bash shell environment  

---

## Deploy Services

```powershell
$PROJECT = "ith-koushik-hackathon"
$REGION  = "us-central1"
$TAG     = (Get-Date -Format "yyyyMMddHHmmss")
```

### Ingestor

```powershell
gcloud builds submit services/ingestor --tag "gcr.io/$PROJECT/ith-ingestor:$TAG"
gcloud run deploy ith-ingestor --image "gcr.io/$PROJECT/ith-ingestor:$TAG" `
  --region $REGION --allow-unauthenticated `
  --set-env-vars "ELASTIC_CLOUD_URL=<ELASTIC_URL>,ELASTIC_API_KEY=<ELASTIC_KEY>,ELASTIC_INDEX=ith-events"
```

### Analyst UI

```powershell
gcloud builds submit services/analyst-ui --tag "gcr.io/$PROJECT/ith-ui:$TAG"
gcloud run deploy ith-ui --image "gcr.io/$PROJECT/ith-ui:$TAG" `
  --region $REGION --allow-unauthenticated `
  --set-env-vars "INGEST_URL=https://ith-ingestor-wcax3xalza-uc.a.run.app/ingest"
```

### Quantum Guardian

```powershell
gcloud builds submit addons/quantum-guardian --tag "gcr.io/$PROJECT/quantum-guardian:$TAG"
gcloud run deploy quantum-guardian --image "gcr.io/$PROJECT/quantum-guardian:$TAG" `
  --region $REGION --allow-unauthenticated `
  --set-env-vars "ELASTIC_CLOUD_URL=<ELASTIC_URL>,ELASTIC_API_KEY=<ELASTIC_KEY>,ELASTIC_INDEX_TARGET=quantum-guardian"
```

---

## Elastic Configuration

- Data Views: `ith-events*`, `ith-events-enriched*`, `quantum-guardian*`  
- Import rule file: `ITH_Baseline7_Rules.ndjson` via **Security → Rules → Import → Enable all**  
- Verify alerts after scenario triggers.
- Judge login is pre-configured in the default space with read-only access (user: ith_judge, password: Hackathon2025).
- If Honey or Quantum return 404 or 500, verify the corresponding API route files (trigger-honey.js, trigger-quantum.js) exist in the Analyst UI service.
---

## Testing and Triggers

### UI Testing

Open https://ith-ui-1054075376433.us-central1.run.app and click scenario buttons.

### PowerShell Direct Trigger

```powershell
$IG = "https://ith-ingestor-wcax3xalza-uc.a.run.app/ingest"
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

### Honey Identity

```powershell
Invoke-RestMethod -Method POST "https://ith-ui-1054075376433.us-central1.run.app/api/trigger-honey?type=canary_user_probe"
Invoke-RestMethod -Method POST "https://ith-ui-1054075376433.us-central1.run.app/api/trigger-honey?type=canary_token_use"
```

### Quantum Guardian

```powershell
Invoke-RestMethod -Method POST "https://ith-ui-1054075376433.us-central1.run.app/api/trigger-quantum"
```

---

## Troubleshooting

- No alerts: verify data indexed, rule schedule active  
- CORS error: ensure middleware in Event‑Gen  
- Startup issues: review Cloud Logging for missing env vars  

---

## Cleanup

```powershell
gcloud run services delete ith-ui --region $REGION
gcloud run services delete ith-ingestor --region $REGION
gcloud run services delete ith-alert --region $REGION
gcloud run services delete ith-event-gen --region $REGION
gcloud run services delete ith-digital-twin --region $REGION
gcloud run services delete quantum-guardian --region $REGION
```

---

## Verification Checklist

- Events visible under `ith-events*`  
- Alerts fire for each baseline rule  
- Honey and Quantum triggers generate expected alerts  
- All endpoints reachable without authentication
