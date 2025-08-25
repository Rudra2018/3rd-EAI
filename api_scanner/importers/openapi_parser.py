
from __future__ import annotations
import json, re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

@dataclass
class APIRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[Any] = None
    meta: Dict[str, Any] = None

class OpenAPIParser:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url.rstrip("/") if base_url else None

    def load(self, src: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        if isinstance(src, dict):
            return src
        text = src
        if text.strip().startswith("{"):
            try:
                return json.loads(text)
            except Exception:
                pass
        if yaml:
            try:
                return yaml.safe_load(text)
            except Exception:
                with open(text, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
        with open(text, "r", encoding="utf-8") as f:
            return json.load(f)

    def to_requests(self, spec: Dict[str, Any]) -> List[APIRequest]:
        servers = spec.get("servers", [])
        base = self.base_url or (servers[0].get("url") if servers else "")
        reqs: List[APIRequest] = []
        paths = spec.get("paths", {})
        for p, item in paths.items():
            for m, op in item.items():
                if m.upper() not in {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}: 
                    continue
                url = (base.rstrip("/") + "/" + p.lstrip("/")).replace("//", "/")
                headers = {}
                # Security
                if "security" in op and spec.get("components", {}).get("securitySchemes"):
                    headers.update(self._auth_headers(op["security"], spec["components"]["securitySchemes"]))
                body = self._example_body(op)
                reqs.append(APIRequest(method=m.upper(), url=url, headers=headers, body=body, meta={"operationId": op.get("operationId")}))
        return reqs

    def _auth_headers(self, security: List[Dict[str, Any]], schemes: Dict[str, Any]) -> Dict[str, str]:
        hdrs: Dict[str, str] = {}
        for rule in security:
            for name in rule.keys():
                sch = schemes.get(name) or {}
                if sch.get("type") == "http" and sch.get("scheme") == "bearer":
                    hdrs["Authorization"] = "Bearer <TOKEN>"
                elif sch.get("type") == "apiKey" and sch.get("in") == "header":
                    hdrs[sch.get("name","X-API-Key")] = "<API_KEY>"
        return hdrs

    def _example_body(self, op: Dict[str, Any]) -> Optional[Any]:
        reqBody = op.get("requestBody", {})
        content = reqBody.get("content", {}) if isinstance(reqBody, dict) else {}
        for ct, desc in content.items():
            ex = desc.get("example") or (desc.get("examples", {}) or {}).get("default", {}).get("value")
            if ex is not None: return ex
        return None
