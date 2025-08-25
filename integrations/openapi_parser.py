# integrations/openapi_parser.py
from typing import List, Dict, Any, Union
import os, json, yaml

def parse_openapi(path_or_text: Union[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return list of {name, method, url, headers, body}
    Supports OAS3 JSON/YAML string, dict object, or path to JSON/YAML.
    """
    if isinstance(path_or_text, str) and os.path.exists(path_or_text):
        with open(path_or_text, "r", encoding="utf-8") as f:
            spec = yaml.safe_load(f)
    elif isinstance(path_or_text, str):
        spec = yaml.safe_load(path_or_text)
    else:
        spec = path_or_text

    servers = (spec.get("servers") or [{"url": ""}])
    base = (servers[0].get("url") or "").rstrip("/")
    reqs: List[Dict[str, Any]] = []
    for p, ops in (spec.get("paths") or {}).items():
        for m, op in (ops or {}).items():
            if not isinstance(op, dict):
                continue
            url = f"{base}/{p.lstrip('/')}"
            name = op.get("summary") or op.get("operationId") or url
            reqs.append({"name": name, "method": m.upper(), "url": url, "headers": {}, "body": None})
    return reqs

