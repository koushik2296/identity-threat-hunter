import os
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import vertexai
from vertexai.generative_models import GenerativeModel

PROJECT_ID = os.environ["GCP_PROJECT"]
LOCATION = os.environ.get("GCP_LOCATION", "us-central1")
MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

app = FastAPI(title="ITH Analyst Notes")

class AlertIn(BaseModel):
    alert: dict  # Elastic/Kibana alert JSON

@app.on_event("startup")
def _init_vertex():
    vertexai.init(project=PROJECT_ID, location=LOCATION)

def _prompt(alert: dict) -> str:
    # Keep the prompt concise; the model returns a 1–2 sentence analyst note.
    return (
        "Explain this Elastic Security identity alert to a SOC analyst in two sentences. "
        "Be concise and actionable. Alert JSON:\n" + json.dumps(alert)[:6000]
    )

@app.get("/")
def root():
    return {"status": "ok"}

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.post("/explain")
def explain(body: AlertIn):
    try:
        model = GenerativeModel(MODEL_NAME)
        resp = model.generate_content(_prompt(body.alert))
        note = (resp.text or "").strip()
        return {"analyst_note": note[:500]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
