
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class Target:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Any | None = None
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanContext:
    targets: List[Target]
    concurrency: int = 20
    rate_per_sec: float = 5.0
    timeout: float = 20.0
    scope_allow: List[str] = field(default_factory=list)  # host suffixes allowed
    scope_block: List[str] = field(default_factory=list)

    def in_scope(self, url: str) -> bool:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        if any(host.endswith(b) for b in self.scope_block):
            return False
        if not self.scope_allow:
            return True
        return any(host.endswith(a) for a in self.scope_allow)
