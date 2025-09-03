# api_scanner/services/scan_middleware.py
from __future__ import annotations

import base64
import json
import logging
import os
import random
import time
from typing import Any, Dict, Optional

import requests
from fastapi import FastAPI, Request, Response
from pydantic import BaseModel, Field
import google.auth.transport.requests
import google.oauth2.id_token

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [scan-middleware] %(message)s",
)
log = logging.getLogger("scan-middleware")

app = FastAPI(title="scan-middleware", version="1.0.0")

# --- Config via env ---
WORKER_URL = os.getenv("WORKER_URL", "").rstrip("/")
FORWARD_PATH = os.getenv("WORKER_FORWARD_PATH", "/pubsub/push")  # reuse worker's push handler
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT_SEC", "3"))
READ_TIMEOUT = float(os.getenv("READ_TIMEOUT_SEC", "10"))
MAX_RETRIES = int(os.getenv("FORWARD_MAX_RETRIES", "3"))
BACKOFF_BASE = float(os.getenv("FORWARD_BACKOFF_BASE", "0.3"))  # seconds
DEDUP_WINDOW_SEC = int(os.getenv("DEDUP_WINDOW_SEC", "0"))      # 0 = disabled (stateless best-effort)
REJECT_NO_URL = os.getenv("REJECT_IF_NO_URL", "false").lower() in ("1","true","yes")

if not WORKER_URL:
    log.error("WORKER_URL is not set. Forwarding will fail.")

# --- Light, in-memory dedupe (best-effort; instance-local) ---
_dedupe: Dict[str, float] = {}

def _dedupe_ok(scan_id: str) -> bool:
    if not DEDUP_WINDOW_SEC or not scan_id:
        return True
    now = time.time()
    # cleanup occasionally
    if random.random() < 0.01:
        for k, ts in list(_dedupe.items()):
            if now - ts > DEDUP_WINDOW_SEC:
                _dedupe.pop(k, None)
    seen_at = _dedupe.get(scan_id)
    if seen_at and now - seen_at < DEDUP_WINDOW_SEC:
        return False
    _dedupe[scan_id] = now
    return True

# --- Models for optional validation/enrichment ---
class ScanMsg(BaseModel):
    scan_id: str = Field(..., description="Unique scan/job id")
    url: Optional[str] = None
    source_url: Optional[str] = None
    priority: Optional[int] = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)

def _fetch_id_token(audience: str) -> str:
    req = google.auth.transport.requests.Request()
    return google.oauth2.id_token.fetch_id_token(req, audience)

def _forward_to_worker(payload: Dict[str, Any]) -> None:
    if not WORKER_URL:
        log.error("WORKER_URL unset; dropping payload: %s", payload)
        return
    # Worker expects Pub/Sub envelope at /pubsub/push; wrap our payload
    data_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    envelope = {"message": {"data": data_b64}}
    url = f"{WORKER_URL}{FORWARD_PATH}"

    # OIDC for Cloud Run → Cloud Run
    token = _fetch_id_token(WORKER_URL)

    sess = requests.Session()
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = sess.post(
                url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=envelope,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            if 200 <= resp.status_code < 300:
                if attempt > 1:
                    log.info("Forwarded to worker after %d attempt(s)", attempt)
                return
            else:
                log.warning("Worker HTTP %s (attempt %d): %s", resp.status_code, attempt, resp.text[:500])
        except requests.RequestException as e:
            log.warning("Forward attempt %d failed: %s", attempt, e)
        time.sleep(BACKOFF_BASE * (2 ** (attempt - 1)) + random.random() * 0.1)

    log.error("Exhausted retries forwarding payload scan_id=%s", payload.get("scan_id"))

@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"ok": True}

@app.post("/pubsub/push", summary="Pub/Sub → middleware")
async def pubsub_push(request: Request) -> Response:
    # Acknowledge regardless to avoid retries; log/forward internally
    try:
        envelope = await request.json()
    except Exception:
        log.warning("Invalid JSON from Pub/Sub; ack 204")
        return Response(status_code=204)

    msg = envelope.get("message") or {}
    attrs = msg.get("attributes") or {}
    data_b64 = msg.get("data")
    if not data_b64:
        log.warning("No data in envelope; attrs=%s", attrs)
        return Response(status_code=204)

    try:
        payload = json.loads(base64.b64decode(data_b64).decode("utf-8"))
    except Exception as e:
        log.warning("Failed to decode message.data: %s", e)
        return Response(status_code=204)

    # Normalize + validate
    try:
        sm = ScanMsg(**payload)
    except Exception as e:
        log.warning("Bad payload schema; acking. Error: %s; payload=%s", e, payload)
        return Response(status_code=204)

    # Normalize url field for downstreams (optional)
    url = sm.url or sm.source_url
    if REJECT_NO_URL and not url:
        log.warning("Rejecting payload without url/source_url: %s", payload)
        return Response(status_code=204)

    # Dedupe (best effort)
    if not _dedupe_ok(sm.scan_id):
        log.info("Deduped scan_id=%s within %ss window", sm.scan_id, DEDUP_WINDOW_SEC)
        return Response(status_code=204)

    # Optional enrichment example
    normalized = {
        "scan_id": sm.scan_id,
        "url": url,
        "priority": sm.priority or 1,
        "metadata": {"scan_type": (sm.metadata.get("scan_type") or (url.split(":",1)[0] if url else "http"))} | sm.metadata,
    }

    log.info("Forwarding scan_id=%s url=%s priority=%s", sm.scan_id, url, sm.priority)
    try:
        _forward_to_worker(normalized)
    except Exception as e:
        # We still 204 to avoid Pub/Sub redelivery storms; rely on upstream requeue if needed
        log.exception("Failed forwarding to worker for scan_id=%s: %s", sm.scan_id, e)

    return Response(status_code=204)

