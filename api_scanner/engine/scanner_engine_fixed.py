from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
import httpx
from aiolimiter import AsyncLimiter
import logging

# Remove Rich Progress to avoid conflicts in Cloud Run
log = logging.getLogger("scanner-engine")

from ..core.context import ScanContext, Target
from ..ai.ai_vulnerability_detector import AIVulnerabilityDetector

class ScannerEngine:
    """Enhanced async engine without Rich Progress conflicts."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.detector = AIVulnerabilityDetector()

    async def _send_one(self, client: httpx.AsyncClient, t: Target) -> Dict[str, Any]:
        """Send one request with comprehensive error handling."""
        headers: Dict[str, str] = {}
        if isinstance(t.headers, dict):
            headers = {str(k): str(v) for k, v in t.headers.items() if v is not None}

        try:
            resp = await client.request(t.method, t.url, headers=headers, content=t.body)
            body_preview = resp.text[:4096] if resp.text else None

            return {
                "request": {"method": t.method, "url": t.url, "headers": headers, "body": t.body},
                "response": {"status": resp.status_code, "headers": dict(resp.headers), "body_preview": body_preview},
                "error": None,
            }
        except httpx.HTTPError as e:
            return {
                "request": {"method": t.method, "url": t.url, "headers": headers, "body": t.body},
                "response": None,
                "error": f"{type(e).__name__}: {e}",
            }

    async def run(self) -> Dict[str, Any]:
        """Execute comprehensive scan with simple logging instead of Rich progress."""
        limiter = AsyncLimiter(self.ctx.rate_per_sec, time_period=1)
        sem = asyncio.Semaphore(self.ctx.concurrency)
        results: List[Dict[str, Any]] = []

        log.info(f"Starting comprehensive scan of {len(self.ctx.targets)} targets")

        async with httpx.AsyncClient(
            timeout=self.ctx.timeout,
            headers={"User-Agent": "api-scanner/2.0"},
        ) as client:
            
            async def worker(i: int, t: Target) -> None:
                async with sem:
                    async with limiter:
                        log.debug(f"Scanning target {i+1}/{len(self.ctx.targets)}: {t.url}")
                        res = await self._send_one(client, t)
                        results.append(res)

            await asyncio.gather(*(worker(i, t) for i, t in enumerate(self.ctx.targets)))

        # AI post-processing
        findings: List[Dict[str, Any]] = []
        for r in results:
            try:
                if r.get("response"):
                    for f in self.detector.analyze(r):
                        findings.append(getattr(f, "__dict__", f))
            except Exception as e:
                log.warning(f"AI analysis failed: {e}")
                continue

        log.info(f"Comprehensive scan completed: {len(results)} results, {len(findings)} findings")
        return {"results": results, "findings": findings}
