import json
import re
from typing import Any, Dict, List, Optional
from types import SimpleNamespace
from urllib.parse import urlencode


class PostmanParser:
    """
    Converts a Postman v2.1 collection into a flat list of requests the engine understands.
    Supports {{var}} substitution from an optional environment dict.
    Returned objects have attributes: method, url, headers, body.
    """

    _VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}")

    def __init__(self, env: Optional[Dict[str, str]] = None):
        self.env = env or {}

    def load(self, path: str) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def to_requests(self, col_json: Dict[str, Any]) -> List[SimpleNamespace]:
        root = col_json.get("collection") or col_json  # tolerate raw export
        items_out: List[SimpleNamespace] = []

        def walk(node: Dict[str, Any]) -> None:
            if "item" in node and isinstance(node["item"], list):
                for it in node["item"]:
                    walk(it)
            req = node.get("request")
            if req and isinstance(req, dict):
                items_out.append(self._convert_request(req))

        walk(root)
        return items_out

    # ----- helpers -----

    def _subst_text(self, s: Optional[str]) -> Optional[str]:
        if s is None:
            return None
        def repl(m: re.Match) -> str:
            k = m.group(1)
            return str(self.env.get(k, m.group(0)))
        return self._VAR_RE.sub(repl, str(s))

    def _convert_request(self, req: Dict[str, Any]) -> SimpleNamespace:
        method = (req.get("method") or "GET").upper()

        url_obj = req.get("url") or {}
        url = self._build_url(url_obj)
        url = self._subst_text(url)

        headers = self._headers_to_dict(req.get("header"))
        # substitute in header values
        headers = {k: self._subst_text(v) or "" for k, v in headers.items()}

        body = self._extract_body(req.get("body"))
        if isinstance(body, str):
            body = self._subst_text(body)

        return SimpleNamespace(method=method, url=url, headers=headers, body=body)

    def _build_url(self, url_obj: Any) -> str:
        # Prefer raw, if present
        if isinstance(url_obj, dict):
            raw = url_obj.get("raw")
            if raw:
                return str(raw)

            protocol = url_obj.get("protocol") or "https"
            host = url_obj.get("host")
            if isinstance(host, list):
                host = ".".join(str(h) for h in host)
            elif host is None:
                host = ""

            path = url_obj.get("path") or []
            if isinstance(path, list):
                path = "/" + "/".join(str(p).strip("/") for p in path if p is not None)
            else:
                path = f"/{str(path).lstrip('/')}"

            query = url_obj.get("query") or []
            qdict: Dict[str, str] = {}
            if isinstance(query, list):
                for q in query:
                    k = q.get("key")
                    v = q.get("value")
                    if k is not None and v is not None:
                        qdict[str(k)] = str(v)
            qstr = f"?{urlencode(qdict)}" if qdict else ""
            return f"{protocol}://{host}{path}{qstr}"

        if isinstance(url_obj, str):
            return url_obj
        return ""

    def _headers_to_dict(self, hdrs: Optional[Any]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not hdrs:
            return out
        if isinstance(hdrs, list):
            for h in hdrs:
                if not isinstance(h, dict):
                    continue
                k = h.get("key")
                v = h.get("value")
                if k is None or v is None:
                    continue
                out[str(k)] = str(v)
            return out
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if v is not None:
                    out[str(k)] = str(v)
            return out
        return out

    def _extract_body(self, body_obj: Optional[Dict[str, Any]]) -> Optional[str]:
        if not body_obj or not isinstance(body_obj, dict):
            return None
        mode = body_obj.get("mode")
        if mode == "raw":
            raw = body_obj.get("raw")
            return None if raw is None else str(raw)
        if mode == "urlencoded":
            pairs = [
                (i.get("key"), i.get("value"))
                for i in (body_obj.get("urlencoded") or [])
            ]
            pairs = [(str(k), "" if v is None else str(v)) for k, v in pairs if k]
            return urlencode(pairs)
        if mode == "formdata":
            # serialize as urlencoded for now
            pairs = [
                (i.get("key"), i.get("value"))
                for i in (body_obj.get("formdata") or [])
            ]
            pairs = [(str(k), "" if v is None else str(v)) for k, v in pairs if k]
            return urlencode(pairs)
        return None

