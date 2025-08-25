
from __future__ import annotations
import asyncio, json, re
from typing import Any, Dict, List
import httpx
from ..core.payloads import idor_variants, mass_assignment_body

class RESTScanner:
    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    async def _req(self, client: httpx.AsyncClient, method: str, url: str, headers: Dict[str,str], body: Any = None):
        r = await client.request(method, url, headers=headers, json=body if isinstance(body,(dict,list)) else None, content=body if isinstance(body,(str,bytes)) else None)
        try: text = r.text
        except Exception: text = "<non-text-body>"
        return {"status": r.status_code, "headers": dict(r.headers), "body": text}

    async def probe_auth_bypass(self, url: str, headers: Dict[str,str]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r_noauth = await self._req(c, "GET", url, {k:v for k,v in headers.items() if k.lower()!="authorization"})
            r_auth = await self._req(c, "GET", url, headers)
        return {"noauth": r_noauth, "auth": r_auth}

    async def probe_idor(self, method: str, url: str, headers: Dict[str,str], body: Any = None) -> List[Dict[str, Any]]:
        outs = []
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            for v in idor_variants(url):
                outs.append({"url": v, "resp": await self._req(c, method, v, headers, body)})
        return outs

    async def probe_mass_assignment(self, method: str, url: str, headers: Dict[str,str], body: Any = None) -> Dict[str, Any]:
        mb = mass_assignment_body(body)
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            return await self._req(c, method, url, headers, mb)

    async def run_basic(self, method: str, url: str, headers: Dict[str,str], body: Any = None) -> Dict[str, Any]:
        tks = [self.probe_auth_bypass(url, headers), self.probe_mass_assignment(method, url, headers, body)]
        idor_task = self.probe_idor(method, url, headers, body)
        a,b,idor = await asyncio.gather(*tks, idor_task)
        return {"auth_bypass": a, "mass_assignment": b, "idor": idor}
