# api_scanner/services/scan_dispatcher.py
from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional, Tuple

import google.auth
from fastapi import FastAPI, HTTPException, status
from google.api_core.exceptions import GoogleAPICallError, NotFound, PermissionDenied
from google.cloud import pubsub_v1
from pydantic import BaseModel, Field, HttpUrl, field_validator

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [scan-dispatcher] %(message)s",
)
log = logging.getLogger("scan-dispatcher")

# -----------------------------------------------------------------------------
# FastAPI app
# -----------------------------------------------------------------------------
app = FastAPI(
    title="scan-dispatcher",
    version="1.1.1",
    docs_url="/docs",
    redoc_url="/redoc",
)

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class ScanRequest(BaseModel):
    scan_id: str = Field(..., description="Unique id for the scan/job")
    source_url: HttpUrl = Field(..., description="URL to scan")
    priority: int = Field(1, ge=0, le=9)
    ttl_seconds: int = Field(3600, ge=60, le=86400)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scan_id")
    @classmethod
    def _strip(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("scan_id cannot be empty")
        return s


class PublishResponse(BaseModel):
    status: str
    message_id: Optional[str] = None
    topic: Optional[str] = None


# -----------------------------------------------------------------------------
# Lazy Pub/Sub client & config
# -----------------------------------------------------------------------------
_PUBLISH_TIMEOUT_SEC = float(os.getenv("PUBLISH_TIMEOUT_SEC", "15"))

# Value from env may be a short topic id ("scan-requests") or a full path
# ("projects/XYZ/topics/scan-requests").
_TOPIC_ENV = os.getenv("PUBSUB_TOPIC")

# Singleton publisher created on first use
_publisher: Optional[pubsub_v1.PublisherClient] = None
_topic_path: Optional[str] = None
_initialized: bool = False  # set True once we've created the client (no network yet)


def _get_env_project_id() -> Optional[str]:
    for key in ("GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "PROJECT_ID"):
        v = os.getenv(key)
        if v:
            return v
    return None


def _resolve_topic_path(publisher: pubsub_v1.PublisherClient) -> str:
    """
    Turn PUBSUB_TOPIC into a fully-qualified path. We only hit metadata server
    if we *must* (i.e., no project id in env and user gave a short topic id).
    """
    assert _TOPIC_ENV, "PUBSUB_TOPIC env var is required"

    if _TOPIC_ENV.startswith("projects/") and "/topics/" in _TOPIC_ENV:
        return _TOPIC_ENV

    project_id = _get_env_project_id()
    if not project_id:
        # This may touch the metadata server, but only when first publish happens.
        _, project_id = google.auth.default()
        if not project_id:
            raise RuntimeError(
                "Could not resolve project id. Set GOOGLE_CLOUD_PROJECT or provide "
                "PUBSUB_TOPIC as a fully-qualified path (projects/…/topics/…)."
            )

    return publisher.topic_path(project_id, _TOPIC_ENV)


def _get_publisher() -> Tuple[pubsub_v1.PublisherClient, str]:
    """Create publisher & topic path lazily without making RPCs."""
    global _publisher, _topic_path, _initialized

    if not _TOPIC_ENV:
        raise RuntimeError("PUBSUB_TOPIC environment variable is required")

    if _publisher is None:
        _publisher = pubsub_v1.PublisherClient()
        _initialized = True

    if _topic_path is None:
        _topic_path = _resolve_topic_path(_publisher)

    return _publisher, _topic_path


def _publish_scan(req: ScanRequest) -> str:
    pub, topic = _get_publisher()  # may resolve project id here if needed

    # IMPORTANT: Use Pydantic's JSON serializer so HttpUrl becomes a plain string
    data = req.model_dump_json().encode("utf-8")

    # Attributes are useful for lightweight filtering on the subscriber side
    attrs = {
        "scan_id": req.scan_id,
        "priority": str(req.priority),
        "ttl_seconds": str(req.ttl_seconds),
    }
    future = pub.publish(topic, data=data, **attrs)
    return future.result(timeout=_PUBLISH_TIMEOUT_SEC)


# -----------------------------------------------------------------------------
# Lifespan: do NOT perform network here, just quick validation
# -----------------------------------------------------------------------------
@app.on_event("startup")
def _on_startup() -> None:
    # Only create the client & compute topic path (no RPCs). If anything goes
    # wrong, we still keep serving and surface errors at /readyz or /dispatch.
    try:
        _get_publisher()
        log.info("scan-dispatcher initialized (lazy). Topic: %s", _topic_path)
    except Exception as e:
        log.warning("Deferred initialization: %s", e)


@app.on_event("shutdown")
def _on_shutdown() -> None:
    try:
        if _publisher is not None:
            _publisher.transport.close()
            log.info("Publisher closed")
    except Exception:
        log.exception("Error during shutdown")


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/", summary="Service info")
def root() -> dict[str, Any]:
    return {
        "service": "scan-dispatcher",
        "version": "1.1.1",
        "docs": "/docs",
        "health": "/healthz",
        "readiness": "/readyz",
    }


@app.get("/healthz", summary="Liveness probe")
def healthz() -> dict[str, str]:
    # No dependencies: just say the process is alive
    return {"status": "ok"}


@app.get("/readyz", summary="Readiness (lightweight, no network)")
def readyz() -> dict[str, Any]:
    # Report whether config is present and client initialized;
    # we deliberately avoid any RPCs here so the container stays responsive.
    return {
        "ready": bool(_TOPIC_ENV),
        "publisher_initialized": _initialized,
        "topic_env": _TOPIC_ENV,
        "topic_path": _topic_path,
    }


@app.get("/config", summary="Echo non-secret config")
def config() -> dict[str, Any]:
    return {
        "pubsub_topic_env": _TOPIC_ENV,
        "topic_path": _topic_path,
        "publisher_initialized": _initialized,
        "project_env": _get_env_project_id(),
    }


@app.post(
    "/dispatch",
    response_model=PublishResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Publish a scan request to Pub/Sub",
)
def dispatch(scan: ScanRequest) -> PublishResponse:
    if not _TOPIC_ENV:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PUBSUB_TOPIC not configured",
        )

    try:
        msg_id = _publish_scan(scan)
        return PublishResponse(status="published", message_id=msg_id, topic=_topic_path)
    except NotFound as e:
        # Topic missing
        log.exception("Topic not found: %s", _topic_path)
        raise HTTPException(status_code=503, detail=f"Pub/Sub topic not found: {_topic_path}") from e
    except PermissionDenied as e:
        # Service account lacks roles/pubsub.publisher (or viewer if you add checks)
        log.exception("Permission denied when publishing")
        raise HTTPException(status_code=502, detail="Permission denied publishing to Pub/Sub") from e
    except GoogleAPICallError as e:
        log.exception("Pub/Sub publish failed: %s", e)
        detail = getattr(e, "message", str(e))
        raise HTTPException(status_code=502, detail=f"Pub/Sub publish failed: {detail}") from e
    except Exception as e:
        log.exception("Unexpected error")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}") from e

