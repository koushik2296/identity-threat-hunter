import os, json, logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx

# Optional Slack integration
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# Logging setup
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ith-alert")

app = FastAPI(title="ITH Alert Webhook")

@app.get("/healthz")
def healthz():
    """Simple health check endpoint for Cloud Run."""
    return {"status": "ok"}

@app.post("/alert")
async def alert(req: Request):
    """
    Receives alert payloads from Kibana detection rules.
    Never crashes — safely handles empty or malformed JSON.
    """
    raw = await req.body()
    text = raw.decode("utf-8", errors="replace") if raw else ""
    log.info("POST /alert raw body: %s", text)

    # Try parse JSON, fallback safely
    if text.strip():
        try:
            payload = json.loads(text)
        except Exception as e:
            log.warning("Non-JSON or malformed body: %s", e)
            payload = {"_raw": text}
    else:
        payload = {}

    # Optional Slack forward (safe)
    if SLACK_WEBHOOK_URL:
        msg = f"ITH Alert:\n```{json.dumps(payload)[:1500]}```"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(SLACK_WEBHOOK_URL, json={"text": msg})
        except Exception as e:
            log.warning("Slack send failed: %s", e)

    # Always return 200 OK
    return JSONResponse({"status": "ok"}, status_code=200)
