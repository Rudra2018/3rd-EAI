# agents/beast_mode.py
import concurrent.futures as futures
import logging
from typing import Any, Dict, List, Optional

from agents.hunter import HunterAgent

log = logging.getLogger(__name__)


def _run_attempt(adapter, attempt: Dict[str, Any]) -> List[Dict]:
    """
    Executes one attempt via ScannerAdapter.
    Adapter will forward to the underlying scanner (or fallback HTTP probe),
    and normalize results to list[dict].
    """
    return adapter.call(
        attempt["url"],
        attempt["method"],
        headers=attempt.get("headers") or {},
        data=attempt.get("data") or {},
    ) or []


def run_beast_mode(endpoints: List[Dict[str, Any]], adapter, max_workers: int = 16) -> List[Dict]:
    """
    Multi-agent, concurrent, safe ‘beast mode’.
    - Uses HunterAgent to craft targeted attempts for each endpoint.
    - Executes them with a bounded thread pool.
    - Merges and de-dupes vulnerabilities.
    """
    if not endpoints:
        return []

    hunter = HunterAgent(max_attempts_per_endpoint=6)
    tasks: List[Dict[str, Any]] = []
    for ep in endpoints:
        plan = hunter.build_plan(ep)
        for attempt in plan.attempts:
            # Carry through endpoint context (folder/business_function)
            attempt["_context"] = {
                "endpoint_name": ep.get("name", ""),
                "folder_path": ep.get("folder_path", []),
                "business_function": ep.get("business_function", ""),
            }
            tasks.append(attempt)

    vulns: List[Dict] = []
    seen_keys = set()

    with futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for res in pool.map(lambda a: _run_attempt(adapter, a), tasks, chunksize=4):
            for v in res or []:
                # Normalize + attach context
                if hasattr(v, "to_dict"):
                    v = v.to_dict()
                ctx = v.get("_context") or {}
                v.update(ctx)

                # De-dupe by (type, endpoint, method, marker)
                key = (v.get("type"), v.get("endpoint") or v.get("url"), v.get("method"), v.get("description"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                v["agentic"] = True
                vulns.append(v)

    log.info(f"Beast Mode: {len(vulns)} findings after {len(tasks)} attempts")
    return vulns

