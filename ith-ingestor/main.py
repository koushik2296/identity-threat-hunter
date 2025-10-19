async def _index_one(payload: Dict[str, Any]) -> Dict[str, Any]:
    index = payload.get("index") or DEFAULT_INDEX
    if not index:
        raise HTTPException(status_code=400, detail="No index specified and ELASTIC_INDEX is empty")
    if not ELASTIC_CLOUD_URL:
        raise HTTPException(status_code=500, detail="500: Elastic Cloud URL not configured")
    if not ELASTIC_API_KEY:
        raise HTTPException(status_code=500, detail="500: Elastic API key not configured")

    # If client passes 'raw', index *that* — but preserve '@timestamp' if it was sent at the top level
    body: Dict[str, Any] = payload.get("raw") or dict(payload)  # copy if not raw
    if "@timestamp" in payload and "@timestamp" not in body:
        body["@timestamp"] = payload["@timestamp"]

    # (Optional but helpful for rules)
    body.setdefault("event", {}).setdefault("kind", "event")

    url = f"{ELASTIC_CLOUD_URL.rstrip('/')}/{index}/_doc"
    headers = _auth_headers()
    try:
        resp = await _client.post(url, headers=headers, json=body)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"httpx_error: {e!s}")

    if resp.status_code >= 400:
        raise HTTPException(status_code=500, detail=f"elastic_error {resp.status_code}: {resp.text}")

    try:
        return resp.json()
    except Exception:
        return {"status_code": resp.status_code, "text": resp.text}
