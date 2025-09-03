from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Callable
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, Request, Response

# Logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [scan-worker] %(message)s",
)
log = logging.getLogger("scan-worker")

app = FastAPI(title="API Scanner Worker", version="2.0.0")

# Configuration
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
FINDINGS_TOPIC = os.getenv("PUBSUB_FINDINGS_TOPIC", "vuln-findings-clean")

# Pub/Sub Setup
try:
    from google.cloud import pubsub_v1
    _publisher = pubsub_v1.PublisherClient()
    HAS_PUBSUB = True
except ImportError:
    _publisher = None
    HAS_PUBSUB = False
    log.warning("Pub/Sub client not available")

# Advanced Scanner Engine
ENGINE_AVAILABLE = False
try:
    from api_scanner.engine.scanner_engine_fixed import ScannerEngine
    from api_scanner.ai.ai_vulnerability_detector import AIVulnerabilityDetector
    from api_scanner.core.context import Target, ScanContext
    from api_scanner.utils.vrt import map_vrt_from_context
    ENGINE_AVAILABLE = True
    log.info("Advanced scanning engine loaded successfully")
except Exception as e:
    log.warning(f"Advanced scanning engine not available: {e}")
    
    # Fallback classes
    class ScannerEngine:
        def __init__(self, ctx): pass
        async def run(self): return []
    
    class AIVulnerabilityDetector:
        def analyze(self, result): return []
    
    def map_vrt_from_context(ctx):
        return {"vrt_category": "API - Other"}

def publish_finding(finding: Dict[str, Any]) -> None:
    """Publish finding to Pub/Sub topic."""
    if not HAS_PUBSUB or not PROJECT_ID or not _publisher:
        log.warning("Pub/Sub not configured - skipping finding publication")
        return
    
    try:
        topic_path = _publisher.topic_path(PROJECT_ID, FINDINGS_TOPIC)
        clean_finding = {
            "scan_id": str(finding.get("scan_id", "")),
            "program": str(finding.get("program", "")),
            "scope_url": str(finding.get("scope_url", "")),
            "analysis_title": str(finding.get("analysis_title", "")),
            "analysis_severity": str(finding.get("analysis_severity", "")),
            "vrt_category": str(finding.get("vrt_category", "")),
            "confidence": str(finding.get("confidence", "0.7")),
            "recommended_fix": str(finding.get("recommended_fix", "")),
            "evidence": str(finding.get("evidence", "")),
            "raw_event": str(finding.get("raw_event", "")),
            "created_at": str(finding.get("created_at", ""))
        }
        
        data = json.dumps(clean_finding, ensure_ascii=False).encode("utf-8")
        future = _publisher.publish(topic_path, data=data)
        future.result(timeout=10)
        log.info(f"Published finding: {finding.get('analysis_title', 'Unknown')}")
    except Exception as e:
        log.error(f"Failed to publish finding: {e}")

def smoke_reachability(url: str) -> List[Dict[str, Any]]:
    """Basic reachability check."""
    try:
        headers = {"User-Agent": "API-Scanner/2.0"}
        r = requests.get(url, timeout=(5, 10), allow_redirects=True, headers=headers)
        return [{
            "title": "API Endpoint Reachability",
            "severity": "info",
            "evidence": {
                "status_code": r.status_code,
                "final_url": str(r.url),
                "response_time_ms": int(r.elapsed.total_seconds() * 1000),
                "content_length": len(r.content) if r.content else 0,
                "headers": dict(list(r.headers.items())[:10])  # Limit headers
            }
        }]
    except Exception as e:
        return [{
            "title": "API Endpoint Unreachable",
            "severity": "medium", 
            "evidence": {"error": str(e), "url": url}
        }]

async def run_full_scan(url: str, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run comprehensive security scan with AI-powered detection."""
    findings = []
    
    # Always include reachability check
    findings.extend(smoke_reachability(url))
    
    if not ENGINE_AVAILABLE:
        log.info(f"Advanced scanning unavailable for {url}")
        return findings

    log.info(f"Starting comprehensive scan for: {url}")
    try:
        # Create scan context
        targets = [Target(method="GET", url=url, headers={}, body=None)]
        ctx = ScanContext(targets=targets)
        
        # Run scanner engine
        engine = ScannerEngine(ctx)
        raw_results = await engine.run()
        
        # Analyze with AI detector
        detector = AIVulnerabilityDetector()
        for result in raw_results:
            if isinstance(result, str):
                try:
                    result = json.loads(result)
                except json.JSONDecodeError:
                    log.warning("Skipping malformed scan result")
                    continue

            analyzed_findings = detector.analyze(result)
            findings.extend([f.__dict__ for f in analyzed_findings])
        
        log.info(f"Comprehensive scan completed for {url}: {len(findings)} findings")
        return findings
        
    except Exception as e:
        log.exception(f"Advanced scan failed for {url}: {e}")
        return findings

SCAN_HANDLERS: Dict[str, Callable[[str, Dict[str, Any]], List[Dict[str, Any]]]] = {
    "http": run_full_scan,
    "https": run_full_scan,
}

async def process_scan_request(payload: Dict[str, Any]) -> None:
    """Process a scan request with advanced capabilities."""
    url = payload.get("url") or payload.get("source_url") or payload.get("target_url")
    scan_id = payload.get("scan_id") or payload.get("id")
    metadata = payload.get("metadata", {})
    priority = payload.get("priority", 1)

    if not url or not scan_id:
        log.warning(f"Invalid payload - missing url or scan_id. Keys: {list(payload.keys())}")
        return

    parsed_url = urlparse(url)
    scan_type = parsed_url.scheme.lower() if parsed_url.scheme else "https"
    
    handler = SCAN_HANDLERS.get(scan_type)
    if not handler:
        log.warning(f"No handler for scheme: {scan_type}")
        return

    log.info(f"Processing scan_id={scan_id}, url={url}, priority={priority}")
    
    try:
        findings = await handler(url, metadata)
        
        for finding in findings:
            curated_finding = {
                "scan_id": scan_id,
                "program": metadata.get("program", "unknown"),
                "scope_url": url,
                "analysis_title": finding.get("title", "Unnamed Finding"),
                "analysis_severity": finding.get("severity", "info").upper(),
                "vrt_category": map_vrt_from_context({
                    "title": finding.get("title", ""),
                    "summary": str(finding.get("evidence", ""))
                }).get("vrt_category", "API - Other"),
                "confidence": 0.7,
                "recommended_fix": "Review findings and implement appropriate security controls.",
                "evidence": json.dumps(finding.get("evidence", {}), ensure_ascii=False),
                "raw_event": json.dumps({
                    "scan_id": scan_id,
                    "original_payload": payload
                }, ensure_ascii=False),
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            publish_finding(curated_finding)
        
        log.info(f"Completed scan_id={scan_id}: {len(findings)} findings published")
        
    except Exception as e:
        log.exception(f"Scan processing failed for scan_id={scan_id}: {e}")

# API endpoints
@app.get("/")
def root():
    return {
        "service": "scan-worker",
        "version": "2.0.0",
        "status": "healthy",
        "engine_available": ENGINE_AVAILABLE
    }

@app.get("/health")
@app.get("/healthz")
def health():
    return {"status": "healthy", "engine_available": ENGINE_AVAILABLE, "timestamp": time.time()}

@app.post("/pubsub/push")
async def pubsub_push(request: Request):
    """Handle Pub/Sub push messages."""
    try:
        envelope = await request.json()
        log.debug("Received push notification")
    except Exception:
        log.warning("Invalid JSON in push request")
        return Response(status_code=400)

    payload = extract_pubsub_payload(envelope)
    if not payload:
        log.warning("Empty or invalid payload")
        return Response(status_code=200)

    asyncio.create_task(process_scan_request(payload))
    return Response(status_code=200)

def extract_pubsub_payload(envelope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract JSON payload from Pub/Sub message."""
    try:
        message = envelope.get("message", {})
        if "data" in message:
            data_b64 = message["data"]
            if data_b64:
                return json.loads(base64.b64decode(data_b64).decode("utf-8"))
        
        if "url" in envelope and "scan_id" in envelope:
            return envelope
            
    except Exception as e:
        log.error(f"Payload extraction failed: {e}")
    
    return None

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)

