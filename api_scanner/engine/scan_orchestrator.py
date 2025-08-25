
from __future__ import annotations
import asyncio, uuid, json
from typing import Any, Dict, List
from ..core.context import ScanContext, Target
from ..core.reporting import ensure_dir, write_md, write_json, render_markdown
from ..settings import settings
from ..scanners.graphql_scanner import GraphQLScanner
from ..engine.scanner_engine import ScannerEngine

class ScanOrchestrator:
    def __init__(self):
        pass

    async def run_graphql(self, endpoint: str, headers: dict[str,str] | None = None) -> Dict[str, Any]:
        g = GraphQLScanner(endpoint, headers or {}, timeout=settings.http_timeout)
        raw = await g.run_all()
        # Convert raw to pseudo results for detector normalization
        samples = []
        for r in raw:
            samples.append({"request":{"method":"POST","url":endpoint,"headers":headers or {},"body":"<graphql>"},
                            "response":{"status": r.get("status",0), "headers":{}, "body": json.dumps(r)}})
        from ..ai.ai_vulnerability_detector import AIVulnerabilityDetector
        det = AIVulnerabilityDetector()
        findings = []
        for s in samples: findings.extend([f.__dict__ for f in det.analyze(s)])
        return {"raw": raw, "findings": findings}

    async def run_rest_targets(self, targets: List[Target]) -> Dict[str, Any]:
        ctx = ScanContext(targets=targets, rate_per_sec=settings.rate_per_sec, timeout=settings.http_timeout)
        engine = ScannerEngine(ctx)
        return await engine.run()

    async def save_report(self, bundle: Dict[str, Any], name: str) -> Dict[str, str]:
        ensure_dir(settings.reports_dir)
        md = render_markdown(bundle.get("findings", []))
        md_path = f"{settings.reports_dir}/{name}.md"
        json_path = f"{settings.reports_dir}/{name}.json"
        write_md(md, md_path)
        write_json(bundle, json_path)
        return {"markdown": md_path, "json": json_path}
