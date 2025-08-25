from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import httpx
from aiolimiter import AsyncLimiter
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn

# Optional: list registered scanners if plugin exists
try:
    from ..core.plugin import list_scanners as _list_scanners
except Exception:
    def _list_scanners() -> List[str]:
        return []

from ..core.context import ScanContext, Target
from ..ai.ai_vulnerability_detector import AIVulnerabilityDetector


class ScannerEngine:
    """
    Generic async engine that sends HTTP requests from ScanContext.targets,
    obeys rate limiting & concurrency, and returns results + AI findings.
    """

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.detector = AIVulnerabilityDetector()

    async def _send_one(self, client: httpx.AsyncClient, t: Target) -> Dict[str, Any]:
        """Send one request; never raise — record error in result instead."""
        # Normalize headers into a simple dict[str, str]
        headers: Dict[str, str] = {}
        if isinstance(t.headers, dict):
            headers = {str(k): str(v) for k, v in t.headers.items() if v is not None}
        elif isinstance(t.headers, list):
            for h in t.headers:
                if isinstance(h, dict) and "key" in h and "value" in h:
                    headers[str(h["key"])] = str(h["value"])

        try:
            resp = await client.request(
                t.method,
                t.url,
                headers=headers,
                content=t.body,
            )
            body_preview: Optional[str] = None
            try:
                body_preview = resp.text[:4096]
            except Exception:
                body_preview = None

            return {
                "request": {
                    "method": t.method,
                    "url": t.url,
                    "headers": headers,
                    "body": t.body,
                },
                "response": {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_preview": body_preview,
                },
                "error": None,
            }

        except httpx.HTTPError as e:
            return {
                "request": {
                    "method": t.method,
                    "url": t.url,
                    "headers": headers,
                    "body": t.body,
                },
                "response": None,
                "error": f"{type(e).__name__}: {e}",
            }

    async def run(self) -> Dict[str, Any]:
        """
        Execute the scan:
          - respects AsyncLimiter(rate_per_sec) and a Semaphore(concurrency)
          - uses sync 'with Progress(...)' inside async code (correct usage)
          - returns JSON-serializable dict with 'results' and 'findings'
        """
        limiter = AsyncLimiter(self.ctx.rate_per_sec, time_period=1)
        sem = asyncio.Semaphore(self.ctx.concurrency)
        results: List[Dict[str, Any]] = []

        # httpx client is async; Progress must be used with regular 'with'
        async with httpx.AsyncClient(
            timeout=self.ctx.timeout,
            headers={"User-Agent": "api-scanner/0.1"},
        ) as client:
            with Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                TimeElapsedColumn(),
            ) as progress:
                task_id = progress.add_task("Scanning targets", total=len(self.ctx.targets))

                async def worker(t: Target) -> None:
                    # Optional in-scope gate if context exposes it
                    if hasattr(self.ctx, "in_scope") and callable(self.ctx.in_scope):
                        if not self.ctx.in_scope(t.url):
                            progress.advance(task_id)
                            return
                    async with sem:
                        async with limiter:
                            res = await self._send_one(client, t)
                            results.append(res)
                            progress.advance(task_id)

                await asyncio.gather(*(worker(t) for t in self.ctx.targets))

        # AI post-processing (safe: never crash the run)
        findings: List[Dict[str, Any]] = []
        for r in results:
            try:
                if r.get("response"):
                    # detector.analyze may return objects; normalize to dicts
                    for f in self.detector.analyze(r):
                        findings.append(getattr(f, "__dict__", f))
            except Exception:
                # Ignore AI errors — scanning results still useful
                continue

        return {
            "results": results,
            "findings": findings,
            "scanners": _list_scanners(),
        }

