# server/main.py
from __future__ import annotations

import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, Response, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .v2_compat import router as v2_router
from api_scanner.engine.scan_orchestrator import router as scan_router

# -----------------------------
# App & logging
# -----------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("scan_worker")

app = FastAPI(title="Scan Worker", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten for prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v2_router, prefix="/v2")
app.include_router(scan_router, prefix="/scan")

# -----------------------------
# Utils
# -----------------------------
def now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")

def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)

# -----------------------------
# Your real work goes here
# -----------------------------
def process_message(payload: Dict[str, Any], attributes: Optional[Dict[str, str]] = None) -> None:
    """
    TODO: call your actual scanning/dispatch logic here.
    This runs in a background task for push endpoints.
    """
    try:
        log.info("[worker] processing payload=%s attrs=%s", _safe_json(payload), _safe_json(attributes or {}))
    except Exception:
        log.exception("[worker] processing failed")

# -----------------------------
# Health
# -----------------------------
@app.get("/health")
def health():
    return {"ok": True, "time": now_utc_str()}

# -----------------------------
# Pub/Sub push (legacy) at /pubsub/push
# -----------------------------
@app.post("/pubsub/push")
async def pubsub_push(request: Request, background: BackgroundTasks):
    try:
        envelope = await request.json()
    except Exception:
        log.warning("[push] invalid JSON body; acking")
        return Response(status_code=204)

    msg = envelope.get("message") or {}
    data_b64 = msg.get("data")
    attributes = msg.get("attributes") or {}

    payload: Dict[str, Any] = {}
    if data_b64:
        try:
            decoded = base64.b64decode(data_b64).decode("utf-8")
            payload = json.loads(decoded)
        except Exception:
            log.exception("[push] failed to decode/parse message.data; raw=%s", data_b64[:40] + "..." if isinstance(data_b64, str) else str(data_b64))
            payload = {"_decode_error": True}

    log.info("[push] envelope=%s", _safe_json({k: v for k, v in envelope.items() if k != "message"}))
    log.info("[push] attrs=%s payload=%s", _safe_json(attributes), _safe_json(payload))

    background.add_task(process_message, payload, attributes)
    return Response(status_code=204)

# -----------------------------
# CloudEvents "custom_pubsub" fallback on "/"
# -----------------------------
@app.post("/")
async def cloudevents_custom_pubsub(request: Request, background: BackgroundTasks):
    mode = request.query_params.get("__GCP_CloudEventsMode")
    ce_type = request.headers.get("ce-type", "")
    is_custom = bool(mode or (ce_type and "google.cloud.pubsub" in ce_type))

    body_text = await request.body()
    body_str = body_text.decode("utf-8", errors="ignore") if body_text else ""

    payload: Dict[str, Any] = {}
    attributes: Dict[str, Any] = {}

    if not is_custom:
        log.info("[root] non-PubSub POST received; acking")
        return Response(status_code=204)

    try:
        as_json = json.loads(body_str) if body_str else {}
    except Exception:
        as_json = {}

    if isinstance(as_json, dict) and "message" in as_json:
        msg = as_json.get("message") or {}
        data_b64 = msg.get("data")
        attributes = msg.get("attributes") or {}
        if data_b64:
            try:
                decoded = base64.b64decode(data_b64).decode("utf-8")
                payload = json.loads(decoded)
            except Exception:
                log.exception("[root] failed to decode/parse message.data; raw=%s", data_b64[:40] + "..." if isinstance(data_b64, str) else str(data_b64))
                payload = {"_decode_error": True}
    elif body_str:
        try:
            decoded = base64.b64decode(body_str).decode("utf-8")
            try:
                payload = json.loads(decoded)
            except Exception:
                payload = {"_raw": decoded}
        except Exception:
            try:
                payload = json.loads(body_str)
            except Exception:
                payload = {"_raw": body_str}

    log.info("[root] custom_pubsub mode=%s ce-type=%s attrs=%s payload=%s",
             mode, ce_type, _safe_json(attributes), _safe_json(payload))

    background.add_task(process_message, payload, attributes)
    return Response(status_code=204)

# -----------------------------
# (Optional) GET / for quick smoke test
# -----------------------------
@app.get("/")
def root():
    return {"service": "scan-worker", "ok": True, "time": now_utc_str()}
