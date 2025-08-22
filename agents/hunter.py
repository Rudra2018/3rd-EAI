# agents/hunter.py
import itertools
import random
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


class AttackPlan:
    """
    A structured set of additional test attempts for an endpoint.
    Each attempt is a (method, url, headers, data) tuple.
    """
    def __init__(self, attempts: List[Dict[str, Any]]):
        self.attempts = attempts or []


class HunterAgent:
    """
    Strategy generator:
      - Mines endpoint metadata (method, params, auth hints)
      - Crafts a few safe mutations (payloads), tuned per category
    """

    REDIRECT_KEYS = {"redirect", "next", "returnUrl", "url", "callback", "dest"}
    SSRF_KEYS = {"url", "target", "image", "source", "feed"}

    def __init__(self, max_attempts_per_endpoint: int = 6):
        self.max_attempts = max_attempts_per_endpoint

    def build_plan(self, endpoint: Dict[str, Any]) -> AttackPlan:
        method = endpoint.get("method", "GET").upper()
        url = endpoint.get("url", "")
        headers = endpoint.get("headers", {}) or {}
        data = {}

        attempts: List[Dict[str, Any]] = []

        # 1) If endpoint has query params: mutate a few
        #    We'll attempt potential XSS/SQLi probes via 'q' or first param
        attempts.append({"method": "GET", "url": self._with_query(url, "q", "<xss-probe>"), "headers": headers, "data": {}})
        attempts.append({"method": "GET", "url": self._with_query(url, "q", "1' OR '1'='1"), "headers": headers, "data": {}})

        # 2) If looks like redirect param
        for k in self.REDIRECT_KEYS:
            attempts.append({"method": "GET", "url": self._with_query(url, k, "https://example.org"), "headers": headers, "data": {}})

        # 3) If body endpoint, add benign JSON probe
        if method in ("POST", "PUT", "PATCH"):
            attempts.append({"method": method, "url": url, "headers": headers, "data": {"_probe": "<xss-probe>"}})
            attempts.append({"method": method, "url": url, "headers": headers, "data": {"_probe": "1' OR '1'='1"}})

        # 4) SSRF-shaped probe (non-destructive)
        for k in self.SSRF_KEYS:
            attempts.append({"method": "GET", "url": self._with_query(url, k, "http://127.0.0.1:80"), "headers": headers, "data": {}})

        # De-dupe and clamp
        cleaned = []
        seen = set()
        for a in attempts:
            key = (a["method"], a["url"], tuple(sorted(a["headers"].items())), tuple(sorted((a.get("data") or {}).items())))
            if key in seen: 
                continue
            seen.add(key)
            cleaned.append(a)

        return AttackPlan(cleaned[: self.max_attempts])

    # ---------------- helpers ----------------

    def _with_query(self, url: str, key: str, value: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        p = urlparse(url)
        q = parse_qs(p.query)
        q[key] = [value]
        qstr = urlencode({k: v[0] if isinstance(v, list) else v for k, v in q.items()})
        return urlunparse(p._replace(query=qstr))

