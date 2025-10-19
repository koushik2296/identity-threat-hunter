# Identity Threat Hunter (ITH) — Technical Runbook
Live Website: https://koushik2296.github.io/identity-threat-hunter/
## Detection Rule Definitions (Full List)

| Rule | What it detects | Severity |
|---|---|---|
| ITH – Rare Country Login | Detects logins originating from unusual or first‑seen countries. | Medium |
| ITH – Privilege Escalation | Detects post‑login privilege or role elevation events. | High |
| ITH – ASN / ISP Change | ITH – ASN / ISP Change | High |
| ITH – MFA Bypass | Detects successful authentications that appear to bypass expected MFA. | High |
| ITH – Credential Stuffing | Detects many login attempts across multiple accounts from a single source. | High |
| ITH – Brute Force Then Success | Detects multiple failures followed by a success from the same source. | High |
| ITH – All Scenarios (Judge Demo) | See Elastic rule for full detection logic. | High |
| ITH - First Seen Admin Tool on Host | Flags the first observed execution of selected admin tools per host in ITH indices. | Medium |
| ITH – Impossible Travel | Detects logins from geographically distant locations within a short time window. | High |
| ITH Honey-Identity Trap Detection | Detects honeypot/canary events from Identity Threat Hunter. | Critical |
| ITH – Quantum Adaptive Response | Triggers adaptive live OSquery investigation when a high-risk identity event is detected. | Low |
| Suspicious PowerShell (AutoTriage) | Suspicious PowerShell (AutoTriage) | High |
| ITH - Quantum Guardian High-Risk Finding | Surfaces high/critical Quantum Guardian findings or risk_score >= 70. | High |
| ITH High Risk Score (>= 90) | Any event with risk.score >= 90. | High |
| ITH Impossible Travel | ITH Impossible Travel | Critical |
| ITH Canary Username Touched | Any event involving a canary user (user.name starts with canary-). | Critical |
| ITH - Possible Brute-Force (source.ip + user.name) | Counts failed authentications per source.ip and user.name over the interval in ITH indices. | Medium |
| ITH – Impossible Travel (Custom, with Response Actions) | Custom clone for hackathon demo. Detects impossible travel or high-risk authentication, then automatically runs an OSquery sweep and isolates the host via Elastic Defend. | High |
| Quantum Guardian – High QES | Quantum Guardian – High QES | Low |
| ITH Honey Token Used | Detects canary token usage events. | Critical |
| ITH - VSS Deleted via vssadmin | Detects deletion of Volume Shadow Copies via vssadmin delete shadows in ITH indices. | Critical |
| ITH Canary User Login Attempt (Failure) | Detects canary user login attempts that failed. | Critical |
| ITH – Smoke Test (mfa_bypass) | ITH – Smoke Test (mfa_bypass) | Low |
| ITH Suspicious Test IP Ranges (Demo) | Matches RFC5737 example IPs used in demo honey events. | Medium |
| ITH Alert Webhook | See Elastic rule for full detection logic. | — |


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
