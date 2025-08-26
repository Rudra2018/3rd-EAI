import os
import json
import requests
from typing import List, Dict, Any, Optional

class HackerOneClient:
    """
    Minimal client that returns a normalized list:
    {
      "platform": "hackerone",
      "slug": "<program-handle>",
      "policy": "<policy-url-or-text>",
      "targets": [{"category":"api","endpoint":"https://...","kind":"rest","meta":{...}}]
    }

    If API token is not present, falls back to env var H1_PROGRAMS_JSON (JSON string).
    """
    def __init__(self, token: Optional[str], username: Optional[str] = None):
        self.token = token
        self.username = username
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        self.base = "https://api.hackerone.com/v1/hackers"

    @classmethod
    def from_env(cls):
        return cls(
            token=os.getenv("HACKERONE_API_TOKEN"),
            username=os.getenv("HACKERONE_USERNAME")
        )

    def list_programs(self) -> List[Dict[str, Any]]:
        # Fallback first, unless you have H1 API access baked.
        raw = os.getenv("H1_PROGRAMS_JSON")
        if raw:
            try:
                data = json.loads(raw)
                return [self._normalize_fallback(p) for p in data]
            except Exception:
                pass

        if not self.token:
            # No API & no fallback -> return empty list
            return []

        # NOTE: The public H1 "hackers" API access is limited; most org details require auth.
        # This stub demonstrates the shape; expand it if you have proper access.
        url = f"{self.base}/programs"
        r = self.session.get(url, timeout=20)
        if r.status_code != 200:
            return []
        payload = r.json()
        out: List[Dict[str, Any]] = []
        for item in payload.get("data", []):
            slug = (item.get("attributes") or {}).get("handle")
            policy = (item.get("attributes") or {}).get("policy")
            targets = []
            # Real scopes generally require another call; keep empty unless you have the scopes.
            out.append({
                "platform": "hackerone",
                "slug": slug,
                "policy": policy,
                "targets": targets
            })
        return out

    def _normalize_fallback(self, p: Dict[str, Any]) -> Dict[str, Any]:
        targets = []
        for t in p.get("targets", []):
            ep = t.get("endpoint") or t.get("url")
            if not ep:
                continue
            targets.append({
                "category": t.get("category", "api"),
                "endpoint": ep,
                "kind": t.get("kind", "rest"),
                "meta": t
            })
        return {
            "platform": "hackerone",
            "slug": p.get("slug") or p.get("handle") or p.get("name"),
            "policy": p.get("policy"),
            "targets": targets
        }

