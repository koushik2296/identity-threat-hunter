import os, json
from fastapi import FastAPI, Request
import httpx

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
app = FastAPI(title="ITH Alert Webhook")

@app.post("/alert")
async def alert(req: Request):
    payload = await req.json()
    text = f"ITH Alert:\n```{json.dumps(payload)[:1500]}```"
    if SLACK_WEBHOOK_URL:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(SLACK_WEBHOOK_URL, json={"text": text})
    return {"ok": True}
