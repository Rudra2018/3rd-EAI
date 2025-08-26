import os
import json
import requests
from typing import List, Dict, Any, Optional

class BugcrowdClient:
    """
    Minimal Bugcrowd client. Prefers BC_PROGRAMS_JSON env for normalized data.
    """
    def __init__(self, token: Optional[str]):
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"Token {token}"})
        self.base = "https://api.bugcrowd.com"

    @classmethod
    def from_env(cls):
        return cls(token=os.getenv("BUGCROWD_API_TOKEN"))

    def list_programs(self) -> List[Dict[str, Any]]:
        raw = os.getenv("BC_PROGRAMS_JSON")
        if raw:
            try:
                data = json.loads(raw)
                return [self._normalize_fallback(p) for p in data]
            except Exception:
                pass

        if not self.token:
            return []

        # Implement authenticated calls if you have enterprise API access.
        return []

    def _normalize_fallback(self, p: Dict[str, Any]) -> Dict[str, Any]:
        targets = []
        for t in p.get("targets", []):
            ep = t.get("endpoint") or t.get("url")
            if not ep:
                continue
            targets.append({
                "category": t.get("category","api"),
                "endpoint": ep,
                "kind": t.get("kind","rest"),
                "meta": t
            })
        return {
            "platform": "bugcrowd",
            "slug": p.get("slug") or p.get("handle") or p.get("name"),
            "policy": p.get("policy"),
            "targets": targets
        }

