
from __future__ import annotations
from typing import List

def fetch_in_scope_assets(token: str | None) -> List[str]:
    if not token:
        return []
    return ["bugcrowd-scope.example", "target.tld"]
