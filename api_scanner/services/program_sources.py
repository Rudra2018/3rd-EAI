"""
Program source aggregator + scope enricher.

- Pulls programs from multiple platforms (H1, Bugcrowd, YesWeHack, Intigriti, HackenProof)
  and vendor VRPs (MSRC, Apple, Google).
- Normalizes to: {
      platform, program, policy,
      scopes: [{type: "api", url, kind: "rest|graphql|ws", meta}]
  }
- Optionally enriches scopes by parsing the program policy page (HTML) to extract API-like
  endpoints (requires PUBLIC_HTML_SCRAPE_OK=true). This is best-effort and conservative:
  it only proposes URLs that look "API-ish" (api.* hosts, /api/, /graphql, ws://…).
- Supports explicit ENV JSON seeding/overrides for scopes to keep scanning strictly
  in-scope and policy-compliant.

SAFE DEFAULTS:
- If scraping is disabled or parsing yields nothing, the program is returned with
  empty scopes so your UI can show “needs scoping”.
- You should prefer platform APIs / explicit policy scope JSON when available.

ENVIRONMENT VARIABLES:
- PUBLIC_HTML_SCRAPE_OK=true|false     -> gate HTML policy-page fetching (default false)
- SCRAPER_UA="Mozilla/5.0 ..."         -> custom UA for polite scraping
- *_PROGRAMS_JSON                      -> YWH_PROGRAMS_JSON, INTI_PROGRAMS_JSON, HACKEN_PROGRAMS_JSON
- MSRC_SCOPES_JSON, APPLE_SCOPES_JSON, GOOGLE_SCOPES_JSON
- PROGRAM_SCOPE_OVERRIDES_JSON         -> {"slug-or-name":[{"endpoint":"https://api.x", "kind":"rest"}, ...]}

NOTE: Respect each program’s policy. Only scan explicit in-scope assets.
"""

from __future__ import annotations
import os
import re
import json
import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

# Optional BeautifulSoup (recommended); we fallback to regex if missing
try:
    from bs4 import BeautifulSoup  # type: ignore
    _HAS_BS4 = True
except Exception:
    _HAS_BS4 = False

from integrations.hackerone_api import HackerOneClient
from integrations.bugcrowd_api import BugcrowdClient
from integrations.yeswehack_api import YesWeHackClient
from integrations.intigriti_api import IntigritiClient
from integrations.hackenproof_api import HackenProofClient
from integrations.msrc_api import msrc_programs
from integrations.apple_bounty import apple_programs
from integrations.google_vrp import google_vrp_programs


log = logging.getLogger(__name__)

UA = os.getenv("SCRAPER_UA", "Mozilla/5.0 (compatible; Rudra-Scanner/1.0)")
SCRAPE = os.getenv("PUBLIC_HTML_SCRAPE_OK", "false").lower() in ("1", "true", "yes")

# Heuristics for detecting "API-like" URLs on policy pages
API_HOST_HINTS = (
    ".api.", "api.", ".gateway.", "gateway.", ".gql.", "gql.", ".graph.", "graph.",
)
API_PATH_HINTS = ("/api/", "/v1/", "/v2/", "/graphql", "/gql")
WS_SCHEMES = ("ws://", "wss://")

URL_RE = re.compile(r'https?://[^\s"\'<>()]+', re.IGNORECASE)

SEEN_LIMIT_PER_PROGRAM = int(os.getenv("SCOPE_ENRICH_MAX_PER_PROGRAM", "5"))  # cap


def _json_env(name: str) -> Optional[Any]:
    raw = os.getenv(name)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        log.warning("Failed to parse JSON from %s", name)
        return None


def _infer_kind(url: str) -> str:
    lu = url.lower()
    if lu.startswith(WS_SCHEMES):
        return "ws"
    if "/graphql" in lu or "graphql" in lu or "/gql" in lu or "gql" in lu or "graph" in lu:
        return "graphql"
    return "rest"


def _apiish(url: str) -> bool:
    """Conservative filter to decide if a discovered URL looks like an API endpoint."""
    lu = url.lower()
    if lu.startswith(WS_SCHEMES):
        return True
    if any(h in lu for h in API_HOST_HINTS):
        return True
    if any(h in lu for h in API_PATH_HINTS):
        return True
    # Avoid obvious static/CDN/media/download/docs assets
    if any(ext in lu for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".css", ".js")):
        return False
    if any(seg in lu for seg in ("/docs", "/documentation", "/swagger", "/openapi")):
        # Allow swagger/openapi JSON/YAML as it can be a valid spec URL
        if lu.endswith(".json") or lu.endswith(".yaml") or lu.endswith(".yml"):
            return True
    # Tolerate cloud provider APIs if clearly called out (be cautious):
    return False


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _domain_only(u: str) -> str:
    """Return 'scheme://host' (preserves scheme) without path/query, useful to normalize."""
    try:
        p = urlparse(u)
        if not p.scheme or not p.netloc:
            return u
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return u


def _extract_candidates_from_html(url: str, html: str) -> List[str]:
    """Extract candidate URLs from a policy page HTML."""
    candidates: List[str] = []

    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        # Links
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                candidates.append(href)
        # Also sweep visible text for raw URLs
        text = soup.get_text(" ", strip=True)[:2_000_000]  # cap
        candidates.extend(URL_RE.findall(text))
    else:
        # Regex-only fallback
        candidates.extend(URL_RE.findall(html[:2_000_000]))

    # Keep only API-ish and dedupe
    apiish = [u for u in candidates if _apiish(u)]
    apiish = _dedupe_keep_order(apiish)

    # Prefer base hosts if many deep paths appear; collapse to domain when repeated
    # but keep unique deep API paths when limited.
    normalized: List[str] = []
    host_counts: Dict[str, int] = {}
    for u in apiish:
        base = _domain_only(u)
        host_counts[base] = host_counts.get(base, 0) + 1

    for u in apiish:
        base = _domain_only(u)
        # If a host appears many times, prefer just the base host to reduce noise.
        if host_counts.get(base, 0) >= 3:
            if base not in normalized:
                normalized.append(base)
        else:
            normalized.append(u)

    return _dedupe_keep_order(normalized)


def _enrich_program_scopes(program: Dict[str, Any], session: requests.Session) -> None:
    """Mutates 'program' in place; adds scopes if we can extract them from the policy page."""
    if not SCRAPE:
        return
    if (program.get("scopes") or []):
        # Already has scopes; don't auto-add unless explicitly empty.
        return
    policy = program.get("policy")
    if not policy or not policy.startswith(("http://", "https://")):
        return

    try:
        r = session.get(policy, timeout=30)
        if r.status_code != 200 or not r.text:
            return
        candidates = _extract_candidates_from_html(policy, r.text)
        if not candidates:
            return

        scopes = []
        for u in candidates[:SEEN_LIMIT_PER_PROGRAM]:
            kind = _infer_kind(u)
            scopes.append({"type": "api", "url": u, "kind": kind, "meta": {"source": "policy_enricher"}})

        if scopes:
            program["scopes"] = scopes
    except Exception as e:
        log.debug("Scope enrich failed for %s: %s", program.get("program"), e)


def _merge_env_vendor_scopes(programs: List[Dict[str, Any]]) -> None:
    """Merge MSRC/Apple/Google ENV-provided scopes if present."""
    vendor_env = {
        "msrc": _json_env("MSRC_SCOPES_JSON") or [],
        "apple": _json_env("APPLE_SCOPES_JSON") or [],
        "google": _json_env("GOOGLE_SCOPES_JSON") or [],
    }
    for p in programs:
        plat = (p.get("platform") or "").lower()
        if plat in vendor_env and vendor_env[plat]:
            # Extend only if empty or not present
            if not p.get("scopes"):
                p["scopes"] = []
            for t in vendor_env[plat]:
                endpoint = t.get("endpoint")
                if not endpoint:
                    continue
                kind = t.get("kind") or _infer_kind(endpoint)
                p["scopes"].append({"type": "api", "url": endpoint, "kind": kind, "meta": {"source": "env_vendor"}})


def _apply_program_scope_overrides(programs: List[Dict[str, Any]]) -> None:
    """Apply PROGRAM_SCOPE_OVERRIDES_JSON = {"slug-or-name":[{endpoint, kind?}, ...]}."""
    overrides = _json_env("PROGRAM_SCOPE_OVERRIDES_JSON")
    if not overrides:
        return
    index: Dict[str, Dict[str, Any]] = {}
    for p in programs:
        key = (p.get("program") or p.get("slug") or "").lower()
        if key:
            index[key] = p

    for key, targets in overrides.items():
        p = index.get((key or "").lower())
        if not p:
            continue
        if not p.get("scopes"):
            p["scopes"] = []
        for t in targets:
            ep = t.get("endpoint")
            if not ep:
                continue
            kind = t.get("kind") or _infer_kind(ep)
            p["scopes"].append({"type": "api", "url": ep, "kind": kind, "meta": {"source": "env_override"}})


async def list_all_program_targets(include: List[str], exclude: List[str]) -> List[Dict[str, Any]]:
    """
    Returns a list of normalized programs. Enrichment runs after merge.

    Each item:
    {
      "platform": "<provider>",
      "program": "<slug-or-name>",
      "policy": "<policy-url>",
      "scopes": [
        {"type":"api","url":"https://api.example.com","kind":"rest|graphql|ws","meta":{...}}
      ]
    }
    """
    # Instantiate clients (some are sync)
    h1 = HackerOneClient.from_env()
    bc = BugcrowdClient.from_env()
    ywh = YesWeHackClient.from_env()
    inti = IntigritiClient.from_env()
    hp = HackenProofClient.from_env()

    # Concurrent fetch of program lists
    h1_programs, bc_programs, ywh_programs, inti_programs, hp_programs = await asyncio.gather(
        asyncio.to_thread(h1.list_programs),
        asyncio.to_thread(bc.list_programs),
        asyncio.to_thread(ywh.list_programs),
        asyncio.to_thread(inti.list_programs),
        asyncio.to_thread(hp.list_programs),
    )

    vendor_programs = msrc_programs() + apple_programs() + google_vrp_programs()

    raw = (h1_programs or []) + (bc_programs or []) + (ywh_programs or []) + (inti_programs or []) + (hp_programs or []) + vendor_programs

    # Normalize and filter include/exclude
    programs: List[Dict[str, Any]] = []
    for p in raw:
        name = p.get("slug") or p.get("handle") or p.get("name")
        if not name:
            continue
        if include and name not in include:
            continue
        if exclude and name in exclude:
            continue

        scopes = []
        for t in p.get("targets", []):
            endpoint = t.get("endpoint") or t.get("url")
            if not endpoint:
                continue
            kind = t.get("kind") or ("graphql" if "graphql" in (endpoint or "").lower() else ("ws" if endpoint.startswith(("ws://", "wss://")) else "rest"))
            scopes.append({"type": "api", "url": endpoint, "kind": kind, "meta": t})

        programs.append({
            "platform": p.get("platform", "unknown"),
            "program": name,
            "policy": p.get("policy"),
            "scopes": scopes
        })

    # Merge vendor ENV scopes and program-level overrides
    _merge_env_vendor_scopes(programs)
    _apply_program_scope_overrides(programs)

    # Scope enricher (policy page → candidates)
    if SCRAPE:
        with requests.Session() as s:
            s.headers.update({"User-Agent": UA})
            for prog in programs:
                try:
                    if not prog.get("scopes"):
                        _enrich_program_scopes(prog, s)
                except Exception as e:
                    log.debug("Error enriching %s: %s", prog.get("program"), e)

    # Final pass: dedupe scopes per program & cap
    for prog in programs:
        scopes = prog.get("scopes") or []
        uniq: List[Dict[str, Any]] = []
        seen_urls = set()
        for sc in scopes:
            u = sc.get("url")
            if not u or u in seen_urls:
                continue
            seen_urls.add(u)
            uniq.append(sc)
        prog["scopes"] = uniq[:SEEN_LIMIT_PER_PROGRAM] if uniq else []

    return programs

