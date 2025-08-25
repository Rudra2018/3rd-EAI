# api_scanner/models.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Target:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None   # IMPORTANT: matches cli.py's "body="


@dataclass
class ScanContext:
    targets: List[Target]
    rate_per_sec: float = 5.0
    concurrency: int = 20
    timeout_sec: float = 30.0

