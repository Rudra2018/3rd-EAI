
from __future__ import annotations
import re, json
from typing import Any

def idor_variants(url: str) -> list[str]:
    # Replace numeric ids with neighbors
    outs = set([url])
    for m in re.finditer(r"/(\d{1,10})(?=/|$)", url):
        val = int(m.group(1))
        for d in (-2,-1,1,2,10,100):
            outs.add(url[:m.start(1)] + str(max(0, val+d)) + url[m.end(1):])
    return list(outs)

def mass_assignment_body(body: Any) -> Any:
    try:
        obj = json.loads(body) if isinstance(body, str) else dict(body or {})
    except Exception:
        return body
    obj.setdefault("isAdmin", True)
    obj.setdefault("role", "admin")
    obj.setdefault("ownerId", 0)
    return obj
