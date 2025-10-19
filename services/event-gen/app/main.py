import os
from fastapi import FastAPI

app = FastAPI(
    title="ITH Event Generator",
    description="Generates synthetic identity/security events (attack scenarios + honey traps).",
    version="1.0.0"
)

# Try to mount scenarios only if it truly exists
try:
    from app.routes import scenarios  # may not exist in your tree
    try:
        app.include_router(scenarios.router)
        print("ROUTER >> mounted scenarios router")
    except Exception as e:
        print("ROUTER >> failed to mount scenarios:", repr(e))
except Exception as e:
    print("ROUTER >> no scenarios router, skipping:", repr(e))

# Mount honey when enabled
if os.getenv("HONEY_ENABLED", "false").lower() == "true":
    try:
        from app.routes.honey import router as honey_router
        app.include_router(honey_router)
        print("HONEY >> MOUNTED /honey routes")
    except Exception as e:
        print("HONEY >> FAILED to mount /honey routes:", repr(e))

@app.get("/healthz")
def health_check():
    return {"status": "ok", "service": "event-gen"}
