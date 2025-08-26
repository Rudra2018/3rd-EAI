# integrations/projectdiscovery_chaos.py
from __future__ import annotations

"""
Small client for ProjectDiscovery Chaos (DNS) API.

Docs (summary):
- Base URL: https://dns.projectdiscovery.io
- Endpoint : GET /dns/{domain}/subdomains
- Auth     : header `Authorization: <API_TOKEN>`  (NOT "Bearer ...")
- Response : Either
    1) {"domain":"example.com","subdomains":["a","b", ...]}  # labels only
    2) ["a.example.com","b.example.com", ...]                # full FQDNs

This client normalizes the output to a `set[str]` of full FQDNs (lowercased).

Usage:
    from integrations.projectdiscovery_chaos import ChaosClient, ChaosNotFound

    client = ChaosClient(api_token=os.environ["CHAOS_API_TOKEN"])
    try:
        subs = client.get_subdomains("example.com")
        for host in sorted(subs):
            print(host)
    except ChaosNotFound:
        print("No Chaos data for example.com")
"""

import logging
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

import requests


__all__ = [
    "ChaosClient",
    "ChaosError",
    "ChaosNotFound",
    "ChaosAuthError",
    "ChaosRateLimited",
]

log = logging.getLogger(__name__)


# ------------------------- Exceptions -------------------------
class ChaosError(Exception):
    """Generic Chaos API error."""


class ChaosNotFound(ChaosError):
    """Raised when Chaos has no data for a domain (HTTP 404)."""


class ChaosAuthError(ChaosError):
    """Raised on authentication/authorization failures (HTTP 401/403)."""


class ChaosRateLimited(ChaosError):
    """Raised when API indicates rate limiting (HTTP 429)."""


# --------------------------- Client ---------------------------
@dataclass
class ChaosClient:
    api_token: str
    timeout: int = 20
    base_url: str = "https://dns.projectdiscovery.io"
    max_retries: int = 3
    backoff_factor: float = 1.5
    user_agent: str = "program-fetcher/chaos-client"

    def __post_init__(self) -> None:
        if not self.api_token:
            raise ChaosError("CHAOS_API_TOKEN is required")
        self._s = requests.Session()
        # IMPORTANT: Chaos expects the token directly (no "Bearer " prefix)
        self._s.headers.update(
            {
                "Authorization": self.api_token,
                "Accept": "application/json",
                "User-Agent": self.user_agent,
                "Connection": "close",
            }
        )

    # -------- Public methods --------
    def get_subdomains(self, domain: str) -> Set[str]:
        """
        Return a set of full FQDNs (lowercased) for the given domain.
        Handles both documented response shapes and normalizes results.
        """
        if not _looks_like_domain(domain):
            raise ChaosError(f"Invalid domain: {domain!r}")

        path = f"/dns/{domain}/subdomains"
        data = self._request_json("GET", path)

        return _normalize_subdomains_payload(data, domain)

    def get_many(self, domains: Iterable[str]) -> Dict[str, Set[str]]:
        """
        Convenience: fetch subdomains for multiple domains.
        Returns a mapping domain -> set of FQDNs.
        """
        out: Dict[str, Set[str]] = {}
        for d in domains:
            try:
                out[d] = self.get_subdomains(d)
            except ChaosNotFound:
                out[d] = set()
            except Exception as e:
                # Surface partial results but record error in logs
                log.warning("Chaos error for %s: %s", d, e)
                out[d] = set()
        return out

    # -------- Internal helpers --------
    def _request_json(self, method: str, path: str) -> object:
        """
        Make a request with small retry logic for 429/5xx.
        Returns parsed JSON (python object).
        """
        url = f"{self.base_url.rstrip('/')}{path}"
        last_exc: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._s.request(method, url, timeout=self.timeout)
                # Map status codes to errors
                if resp.status_code == 404:
                    raise ChaosNotFound(f"No Chaos data at {url}")
                if resp.status_code in (401, 403):
                    raise ChaosAuthError(f"Unauthorized to access {url}: {resp.text[:200]}")
                if resp.status_code == 429:
                    # Retry with backoff
                    raise ChaosRateLimited(f"Rate limited at {url}")
                if 500 <= resp.status_code < 600:
                    raise ChaosError(f"Chaos {resp.status_code} at {url}: {resp.text[:200]}")
                if resp.status_code >= 400:
                    raise ChaosError(f"Chaos {resp.status_code} at {url}: {resp.text[:200]}")

                return resp.json()
            except (ChaosRateLimited, ChaosError) as e:
                last_exc = e
                if isinstance(e, ChaosRateLimited) or "Chaos 5" in str(e):
                    # 429 or 5xx -> backoff and retry (unless we're out of attempts)
                    if attempt < self.max_retries:
                        sleep_s = self.backoff_factor ** (attempt - 1)
                        log.info("Chaos retry %s/%s after %.2fs: %s", attempt, self.max_retries, sleep_s, e)
                        time.sleep(sleep_s)
                        continue
                # For other 4xx or on last attempt, stop
                raise
            except requests.RequestException as e:
                last_exc = e
                if attempt < self.max_retries:
                    sleep_s = self.backoff_factor ** (attempt - 1)
                    log.info("Chaos network retry %s/%s after %.2fs: %s", attempt, self.max_retries, sleep_s, e)
                    time.sleep(sleep_s)
                    continue
                raise ChaosError(f"Chaos network error at {url}: {e}") from e

        # Should not reach here due to raises, but keep mypy happy
        if last_exc:
            raise last_exc
        raise ChaosError("Unknown Chaos error")


# ---------------------- Utility functions ----------------------
def _looks_like_domain(domain: str) -> bool:
    """
    Very light domain check; keeps things permissive (punycode, dots).
    """
    if not domain or "." not in domain:
        return False
    if "://" in domain or "/" in domain or " " in domain:
        return False
    return True


def _normalize_subdomains_payload(payload: object, domain: str) -> Set[str]:
    """
    Accepts either:
      - {"domain":"example.com","subdomains":["a","b", ...]}
      - ["a.example.com","b.example.com", ...]
    Returns a set of FQDNs (lowercased).
    """
    out: Set[str] = set()

    # Dict shape with "subdomains": labels only
    if isinstance(payload, dict) and "subdomains" in payload and isinstance(payload["subdomains"], list):
        for s in payload["subdomains"]:
            label = str(s).strip().lower()
            if not label:
                continue
            fqdn = label if label.endswith(f".{domain}") else f"{label}.{domain}"
            out.add(fqdn)

    # List shape: could be labels or fully-qualified names
    elif isinstance(payload, list):
        for s in payload:
            val = str(s).strip().lower()
            if not val:
                continue
            fqdn = val if val.endswith(f".{domain}") else f"{val}.{domain}"
            out.add(fqdn)

    else:
        raise ChaosError(f"Unexpected Chaos response type: {type(payload).__name__}")

    # Filter obvious junk
    cleaned = {h for h in out if _looks_like_domain(h)}
    return cleaned

