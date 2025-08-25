# integrations/har_parser.py
from typing import List, Dict, Any, Union
import os, json

def parse_har(path_or_obj: Union[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return list of {name, method, url, headers, body} from HAR
    """
    if isinstance(path_or_obj, str) and os.path.exists(path_or_obj):
        with open(path_or_obj, "r", encoding="utf-8") as f:
            har = json.load(f)
    elif isinstance(path_or_obj, str):
        har = json.loads(path_or_obj)
    else:
        har = path_or_obj

    reqs: List[Dict[str, Any]] = []
    seen = set()
    for e in (har.get("log", {}).get("entries") or []):
        r = e.get("request") or {}
        m = (r.get("method") or "GET").upper()
        u = r.get("url") or ""
        if not u: continue
        key = (m, u)
        if key in seen: continue
        seen.add(key)
        hdrs = {h["name"]: h["value"] for h in (r.get("headers") or []) if "name" in h and "value" in h}
        body = None
        if "postData" in r and isinstance(r["postData"], dict):
            body = r["postData"].get("text")
        reqs.append({"name": u, "method": m, "url": u, "headers": hdrs, "body": body})
    return reqs

