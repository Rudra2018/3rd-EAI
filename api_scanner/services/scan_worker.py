# services/scan_worker.py
import base64
import json
import logging
import os
from typing import Any, Dict, Callable, Optional
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, Request, Response, HTTPException
from google.cloud import pubsub_v1

# ---------------- Env ----------------
PROJECT_ID = os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT")
CURATED_TOPIC = os.getenv("TOPIC_FINDINGS_CURATED", "findings.curated")

# ---------------- Logger ----------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [scan-worker] %(message)s",
)

# ---------------- Engine (optional) ----------------
ENGINE_AVAILABLE = False
try:
    from engine.scanner_engine import ScannerEngine  # type: ignore
    ENGINE_AVAILABLE = True
except Exception as e:
    logging.warning("ScannerEngine not available, falling back to lightweight checks: %s", e)

# ---------------- Pub/Sub Publisher ----------------
_publisher: Optional[pubsub_v1.PublisherClient] = None


def publisher() -> pubsub_v1.PublisherClient:
    global _publisher
    if _publisher is None:
        _publisher = pubsub_v1.PublisherClient()
    return _publisher


def publish_curated(finding: Dict[str, Any]) -> None:
    if not PROJECT_ID:
        logging.error("PROJECT_ID not set; cannot publish curated finding")
        return
    topic_path = publisher().topic_path(PROJECT_ID, CURATED_TOPIC)
    data = json.dumps(finding).encode("utf-8")
    publisher().publish(topic_path, data=data)

# ---------------- Handlers ----------------
def handle_http(url: str, meta: Dict[str, Any]) -> None:
    """
    HTTP/HTTPS entrypoint. If the real engine is present, use it.
    Otherwise do a light probe so the pipeline still emits a finding.
    """
    program = meta.get("program") or (urlparse(url).hostname or "http")
    scan_id = meta.get("scan_id")

    if ENGINE_AVAILABLE:
        try:
            engine = ScannerEngine()
            findings = engine.scan_url(url)  # expected to return iterable[dict]
            for f in findings or []:
                curated = {
                    "program": program,
                    "scope_url": url,
                    "analysis": {
                        "title": f.get("title", "Finding"),
                        "vrt_category": f.get("vrt_category", "UNMAPPED"),
                        "severity": f.get("severity", "medium"),
                        "confidence": f.get("confidence", 0.6),
                        "recommended_fix": f.get("recommended_fix", ""),
                    },
                    "scan_id": scan_id,
                    "source": meta.get("source") or "http",
                }
                publish_curated(curated)
        except Exception as e:
            logging.exception("Engine HTTP scan failed for %s: %s", url, e)
    else:
        try:
            r = requests.get(url, timeout=10, allow_redirects=True)
            sev = "low" if r.status_code < 400 else "medium"
            curated = {
                "program": program,
                "scope_url": url,
                "analysis": {
                    "title": f"HTTP probe: {r.status_code}",
                    "vrt_category": "INFO/HTTP-PROBE",
                    "severity": sev,
                    "confidence": 0.5,
                    "recommended_fix": "",
                },
                "scan_id": scan_id,
                "source": meta.get("source") or "http",
            }
            publish_curated(curated)
        except Exception as e:
            logging.warning("HTTP probe failed for %s: %s", url, e)


def handle_openapi(src: str, meta: Dict[str, Any]) -> None:
    try:
        from importers.openapi_parser import OpenAPIParser  # type: ignore

        program = meta.get("program") or (urlparse(src).hostname or "openapi")
        parser = OpenAPIParser()
        apis = parser.parse(src)

        if ENGINE_AVAILABLE:
            engine = ScannerEngine()
            for api in apis or []:
                for ep in api.get("endpoints", []):
                    for finding in engine.scan_api_endpoint(ep) or []:
                        curated = {
                            "program": program,
                            "scope_url": ep.get("url"),
                            "analysis": {
                                "title": finding.get("title", "API finding"),
                                "vrt_category": finding.get("vrt_category", "UNMAPPED"),
                                "severity": finding.get("severity", "medium"),
                                "confidence": finding.get("confidence", 0.6),
                                "recommended_fix": finding.get("recommended_fix", ""),
                            },
                            "scan_id": meta.get("scan_id"),
                            "source": meta.get("source") or "openapi",
                        }
                        publish_curated(curated)
    except Exception as e:
        logging.warning("OpenAPI handler error for %s: %s", src, e)


def handle_postman(src: str, meta: Dict[str, Any]) -> None:
    try:
        from importers.postman_parser import PostmanParser  # type: ignore

        program = meta.get("program") or (urlparse(src).hostname or "postman")
        parser = PostmanParser()
        colls = parser.parse(src)

        if ENGINE_AVAILABLE:
            engine = ScannerEngine()
            for c in colls or []:
                for req in c.get("requests", []):
                    for finding in engine.scan_api_request(req) or []:
                        curated = {
                            "program": program,
                            "scope_url": req.get("url"),
                            "analysis": {
                                "title": finding.get("title", "API finding"),
                                "vrt_category": finding.get("vrt_category", "UNMAPPED"),
                                "severity": finding.get("severity", "medium"),
                                "confidence": finding.get("confidence", 0.6),
                                "recommended_fix": finding.get("recommended_fix", ""),
                            },
                            "scan_id": meta.get("scan_id"),
                            "source": meta.get("source") or "postman",
                        }
                        publish_curated(curated)
    except Exception as e:
        logging.warning("Postman handler error for %s: %s", src, e)


def handle_graphql(src: str, meta: Dict[str, Any]) -> None:
    try:
        from importers.graphql_importer import GraphQLImporter  # type: ignore

        program = meta.get("program") or (urlparse(src).hostname or "graphql")
        imp = GraphQLImporter()
        schema = imp.load(src)

        if ENGINE_AVAILABLE:
            engine = ScannerEngine()
            for finding in engine.scan_graphql_schema(schema) or []:
                curated = {
                    "program": program,
                    "scope_url": src,
                    "analysis": {
                        "title": finding.get("title", "GraphQL finding"),
                        "vrt_category": finding.get("vrt_category", "UNMAPPED"),
                        "severity": finding.get("severity", "medium"),
                        "confidence": finding.get("confidence", 0.6),
                        "recommended_fix": finding.get("recommended_fix", ""),
                    },
                    "scan_id": meta.get("scan_id"),
                    "source": meta.get("source") or "graphql",
                }
                publish_curated(curated)
    except Exception as e:
        logging.warning("GraphQL handler error for %s: %s", src, e)


SCAN_HANDLERS: Dict[str, Callable[[str, Dict[str, Any]], None]] = {
    "http": handle_http,
    "https": handle_http,
    "openapi": handle_openapi,
    "postman": handle_postman,
    "graphql": handle_graphql,
}

# ---------------- FastAPI ----------------
app = FastAPI()


@app.get("/healthz")
def healthz():
    return {"ok": True, "handlers": list(SCAN_HANDLERS.keys())}


def _dispatch_scan(url_or_src: str, scan_type: Optional[str], meta: Dict[str, Any]) -> None:
    """
    Common dispatcher used by both /scan (direct JSON) and /pubsub/push (envelope).
    Resolves handler key from explicit scan_type or URL scheme.
    """
    if scan_type:
        key = scan_type.lower()
    else:
        key = (urlparse(url_or_src).scheme or "").lower() or "http"
    handler = SCAN_HANDLERS.get(key)
    if not handler:
        logging.warning("scan_fn_missing key=%s url=%s", key, url_or_src)
        return
    handler(url_or_src, meta)


def _extract_payload(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts Pub/Sub push envelope and returns the decoded message dict.
    Supports both Cloud Run push and test cURL payloads.
    """
    msg = envelope.get("message") or envelope  # tolerate direct body
    data_b64 = msg.get("data")
    if not data_b64:
        return {}
    try:
        return json.loads(base64.b64decode(data_b64).decode("utf-8"))
    except Exception as e:
        logging.warning("Failed to decode message.data: %s", e)
        return {}


@app.post("/pubsub/push")
async def pubsub_push(request: Request) -> Response:
    """
    Pub/Sub push entrypoint. Always 204 on success to ack the message.
    """
    try:
        envelope = await request.json()
    except Exception:
        return Response(status_code=400)

    payload = _extract_payload(envelope)
    if not payload:
        logging.warning("empty_or_bad_payload")
        return Response(status_code=204)

    # Normalized fields
    url = payload.get("source_url") or payload.get("url")
    explicit_type = payload.get("scan_type")  # optional override e.g., "openapi"
    meta = {
        "scan_id": payload.get("scan_id"),
        "source": payload.get("source"),
        "program": payload.get("program"),
        "priority": payload.get("priority"),
        "campaign": payload.get("campaign"),
        "metadata": payload.get("metadata") or {},
    }

    if not explicit_type and not url:
        logging.warning("no_url_and_no_scan_type")
        return Response(status_code=204)

    try:
        _dispatch_scan(url or payload.get("source"), explicit_type, meta)
    except Exception as e:
        logging.exception("scan_handler_error url=%s err=%s", url, e)

    return Response(status_code=204)


@app.post("/scan")
async def scan_direct(request: Request):
    """
    Accepts JSON like:
      {"url":"https://example.com",
       "scan_type":"openapi|postman|graphql|http",
       "program":"...", "campaign":"...", "metadata":{...}, "scan_id":"..."}

    Returns 200 with JSON on success.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")

    url = body.get("url") or body.get("source_url") or body.get("source")
    scan_type = body.get("scan_type")
    if not url and not scan_type:
        raise HTTPException(status_code=400, detail="missing url or scan_type")

    meta = {
        "scan_id": body.get("scan_id"),
        "source": body.get("source"),
        "program": body.get("program"),
        "priority": body.get("priority"),
        "campaign": body.get("campaign"),
        "metadata": body.get("metadata") or {},
    }
    try:
        _dispatch_scan(url or body.get("source"), scan_type, meta)
    except Exception as e:
        logging.exception("scan_direct_error url=%s err=%s", url, e)
        raise HTTPException(status_code=500, detail="scan error")

    return {"ok": True, "dispatched": True, "url": url, "scan_type": scan_type or "auto"}

