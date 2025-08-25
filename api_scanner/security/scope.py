
from __future__ import annotations
from typing import List
from urllib.parse import urlparse

def filter_in_scope(urls: List[str], allow_suffixes: List[str]) -> List[str]:
    out = []
    for u in urls:
        host = urlparse(u).hostname or ""
        if not allow_suffixes or any(host.endswith(suf) for suf in allow_suffixes):
            out.append(u)
    return out
