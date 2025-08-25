
from __future__ import annotations
import json, asyncio
from typing import Any, Dict, List, Optional
import httpx

INTROSPECTION_QUERY = {"query": "query IntrospectionQuery { __schema { queryType { name } types { name } }}"}

class GraphQLScanner:
    def __init__(self, endpoint: str, headers: Optional[Dict[str,str]] = None, timeout: float = 20.0):
        self.endpoint = endpoint
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout

    async def check_introspection(self) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(self.endpoint, json=INTROSPECTION_QUERY, headers=self.headers)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        open_ = bool(data and data.get("data") and data["data"].get("__schema"))
        return {"ok": True, "introspection_open": open_, "status": r.status_code, "evidence": data if open_ else {"snippet": (r.text[:300])}}

    async def depth_probe(self, depth: int = 15) -> Dict[str, Any]:
        # Generates synthetic deep query to see if limits exist
        field_chain = "a" + ("{ a" * depth) + (" }" * depth)
        q = {"query": f"query D {{ {field_chain} }}"}
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(self.endpoint, json=q, headers=self.headers)
        return {"status": r.status_code, "snippet": r.text[:400]}

    async def run_all(self) -> List[Dict[str, Any]]:
        checks = [self.check_introspection(), self.depth_probe()]
        return await asyncio.gather(*checks)
