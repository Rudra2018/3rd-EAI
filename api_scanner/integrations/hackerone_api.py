
from __future__ import annotations
import os, json
from typing import Any, Dict, List

def fetch_in_scope_assets(token: str | None) -> List[str]:
    """Placeholder: return host patterns from H1 API. Implement real calls later.
    Expects H1 API token via env or parameter; filters in-scope assets with type URL/API.
    """
    if not token:
        return []
    # TODO: real HTTP call to HackerOne API. For now, allowlist examples:
    return ["example.com", "api.example.com"]
