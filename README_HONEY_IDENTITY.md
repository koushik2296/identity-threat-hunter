# Honey-Identity Traps (Canary Users & Tokens)

Adds high-signal detections to the Identity Threat Hunter project by introducing canary users and decoy tokens. Any interaction with these decoys is malicious and triggers critical alerts.

## Contents
- `services/event-gen/app/routes/honey.py` — Demo routes to emit canary events
- `services/ingestor/app/middlewares/honey_guard.py` — Enrichment to tag honeypot events and force high risk
- `services/alert-webhook/app/utils/severity.py` — Severity override for honeypot events (P1)
- `web/analyst-ui/components/HoneyToggle.tsx` and `pages/honey.tsx` — UI toggle and demo page
- `kibana/rules/honey_identity_trigger.ndjson` — Detection rule export (KQL)
- `config/.env.honey.example` — Environment toggles

## Quick Start (local demo)
1. Add `.env` variables from `config/.env.honey.example` to your environment.
2. Ensure `ingestor` is reachable at `INGESTOR_URL` (or update `INGESTOR_URL` in `emit_event.py`).
3. Run event-gen and hit the demo endpoints:
   - `POST /honey/canary_user_probe` with body: `{ "username": "canary-db-admin" }`
   - `POST /honey/canary_token_use` with body: `{ "token_id": "tok_canary_1" }`
4. In Kibana, import `kibana/rules/honey_identity_trigger.ndjson` and enable the rule.
5. In the Analyst UI, open `/honey` and toggle the HONEY filter.

## Integration Notes
- No new index is required. Honeypot events are written into your existing enriched index.
- The honey guard can be inserted after your normal enrichers and before indexing.
- The severity helper can be used in the alert-webhook to hardcode P1 for honeypot category.

## Naming Conventions
- Canary users: `canary-*` (e.g., `canary-db-admin`, `canary-backup-svc`)
- Tokens: `tok_canary_*`

## Safety
- Canary users should not be granted real access.
- Canary tokens must never connect to production systems.
