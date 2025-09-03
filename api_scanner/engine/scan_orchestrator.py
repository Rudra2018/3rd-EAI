from __future__ import annotations
import asyncio, uuid, json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, HTTPException, status
from pydantic import BaseModel, Field

# Local imports
from ..core.context import ScanContext, Target
from ..core.reporting import ensure_dir, write_md, write_json, render_markdown
from ..settings import settings
from ..scanners.graphql_scanner import GraphQLScanner
from ..engine.scanner_engine import ScannerEngine
from ..ai.ai_vulnerability_detector import AIVulnerabilityDetector

router = APIRouter()

# -----------------------------
# Input Models
# -----------------------------
class UrlScanRequest(BaseModel):
    url: str
    max_pages: Optional[int] = 3
    same_host_only: Optional[bool] = True
    use_heavy_ml: Optional[bool] = True

class PostmanScanRequest(BaseModel):
    collection: Dict[str, Any]
    handles: Optional[List[str]] = Field(default_factory=list)

# -----------------------------
# Internal Functions
# -----------------------------
async def run_graphql(endpoint: str, headers: dict[str, str] | None = None) -> Dict[str, Any]:
    g = GraphQLScanner(endpoint, headers or {}, timeout=settings.http_timeout)
    raw = await g.run_all()
    samples = []
    for r in raw:
        samples.append({
            "request": {"method": "POST", "url": endpoint, "headers": headers or {}, "body": "<graphql>"},
            "response": {"status": r.get("status", 0), "headers": {}, "body": json.dumps(r)}
        })
    det = AIVulnerabilityDetector()
    findings = []
    for s in samples:
        findings.extend([f.__dict__ for f in det.analyze(s)])
    return {"raw": raw, "findings": findings}

async def run_rest_targets(targets: List[Target]) -> Dict[str, Any]:
    ctx = ScanContext(targets=targets, rate_per_sec=settings.rate_per_sec, timeout=settings.http_timeout)
    engine = ScannerEngine(ctx)
    return await engine.run()

async def save_report(bundle: Dict[str, Any], name: str) -> Dict[str, str]:
    ensure_dir(settings.reports_dir)
    md = render_markdown(bundle.get("findings", []))
    md_path = f"{settings.reports_dir}/{name}.md"
    json_path = f"{settings.reports_dir}/{name}.json"
    write_md(md, md_path)
    write_json(bundle, json_path)
    return {"markdown": md_path, "json": json_path}

# -----------------------------
# API Endpoints
# -----------------------------
@router.post("/url", status_code=status.HTTP_202_ACCEPTED)
async def scan_url_endpoint(req: UrlScanRequest):
    targets = [Target(method="GET", url=req.url)]
    
    # Run the core scanner
    scan_results = await run_rest_targets(targets)
    
    # Run AI vulnerability detection on the results
    all_findings = []
    detector = AIVulnerabilityDetector()
    for result in scan_results.get("results", []):
        sample = {
            "request": result.get("request"),
            "response": result.get("response"),
        }
        findings = detector.analyze(sample)
        all_findings.extend([f.__dict__ for f in findings])

    return {
        "status": "accepted",
        "message": "URL scan dispatched",
        "results": scan_results,
        "findings": all_findings
    }

@router.post("/postman", status_code=status.HTTP_202_ACCEPTED)
async def scan_postman_endpoint(req: PostmanScanRequest):
    return {
        "status": "accepted",
        "message": "Postman scan dispatched",
        "collection_name": req.collection.get("info", {}).get("name", "untitled")
    }

@router.post("/report", status_code=status.HTTP_202_ACCEPTED)
async def scan_report_endpoint(req: PostmanScanRequest):
    return {
        "status": "accepted",
        "message": "Report generation dispatched"
    }

