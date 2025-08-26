# services/program_fetcher.py
from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl, field_validator
from integrations.hackerone_api import HackerOneClient


from integrations.projectdiscovery_chaos import (
    ChaosClient,
    ChaosError,
    ChaosNotFound,
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [program-fetcher] %(message)s",
)
log = logging.getLogger("program-fetcher")

# -----------------------------------------------------------------------------
# Env/config
# -----------------------------------------------------------------------------
DISPATCHER_URL = os.getenv("DISPATCHER_URL", "").rstrip("/")
CHAOS_API_TOKEN = os.getenv("CHAOS_API_TOKEN", "")
ENABLED_SOURCES = set(
    s.strip().lower() for s in os.getenv("ENABLED_SOURCES", "chaos").split(",") if s.strip()
)

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SEC", "10"))
DEFAULT_MAX_PER_DOMAIN = int(os.getenv("MAX_PER_DOMAIN", "500"))  # cap to keep /sync fast
DEFAULT_PARALLELISM = int(os.getenv("PARALLELISM", "20"))        # concurrent dispatches

if not DISPATCHER_URL:
    log.warning("DISPATCHER_URL is not set; dispatching will fail.")

# -----------------------------------------------------------------------------
# FastAPI
# -----------------------------------------------------------------------------
app = FastAPI(
    title="program-fetcher",
    version="1.3.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class SyncRequest(BaseModel):
    # Option 1: provide domains we’ll expand via Chaos
    domains: Optional[List[str]] = None

    # Option 2: (legacy) seed URLs to dispatch directly
    seed_urls: Optional[List[HttpUrl]] = None

    # optional metadata to attach to each dispatch
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # knobs to keep the request snappy
    max_per_domain: int = Field(DEFAULT_MAX_PER_DOMAIN, ge=1, le=50_000)
    parallelism: int = Field(DEFAULT_PARALLELISM, ge=1, le=64)

    scheme: str = Field("https", description="Scheme for subdomain dispatch, e.g. https/http")
    priority: int = Field(1, ge=0, le=9)
    ttl_seconds: int = Field(3600, ge=60, le=86400)

    @field_validator("domains")
    @classmethod
    def _normalize_domains(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        out = []
        for d in v:
            d = (d or "").strip().lower()
            if not d or "." not in d or "://" in d or "/" in d or " " in d:
                raise ValueError(f"Invalid domain: {d!r}")
            out.append(d)
        return out

    @field_validator("scheme")
    @classmethod
    def _scheme_ok(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ("http", "https"):
            raise ValueError("scheme must be http or https")
        return v


class SyncResult(BaseModel):
    seen: int
    dispatched: int
    errors: List[str]
    enabled_sources: List[str]
    mode: str
    when: str
    truncated: bool = False  # true if we cut off subdomain list due to max_per_domain


class ChaosTestResult(BaseModel):
    domain: str
    count: int
    sample: List[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _dispatch_one(
    session: requests.Session,
    base_url: str,
    target_url: str,
    priority: int,
    ttl_seconds: int,
    extra_meta: Dict[str, Any],
) -> Tuple[bool, Optional[str]]:
    """POST to scan-dispatcher /dispatch for a single target_url."""
    payload = {
        "scan_id": str(uuid.uuid4()).upper(),
        "source_url": target_url,
        "priority": priority,
        "ttl_seconds": ttl_seconds,
        "metadata": extra_meta,
    }
    try:
        resp = session.post(
            f"{base_url}/dispatch",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code >= 400:
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        return True, None
    except requests.RequestException as e:
        return False, f"request error: {e}"


def _build_urls_from_subdomains(subdomains: Set[str], scheme: str) -> List[str]:
    # We must satisfy scan-dispatcher’s Pydantic (HttpUrl), so use http/https
    # and let downstream decide what to do with the host.
    return [f"{scheme}://{h}" for h in sorted(subdomains)]


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/", summary="Info")
def root() -> Dict[str, Any]:
    return {
        "service": "program-fetcher",
        "version": "1.3.0",
        "docs": "/docs",
        "config": "/config",
        "test_chaos": "/chaos/test?domain=example.com",
    }

@app.get("/h1/programs", summary="List HackerOne programs (requires API or env fallback)")
def h1_programs() -> Dict[str, Any]:
    client = HackerOneClient.from_env()
    progs = client.list_programs()
    return {"count": len(progs), "programs": progs}

@app.get("/config", summary="Echo non-secret config")
def config() -> Dict[str, Any]:
    return {
        "dispatcher_url": DISPATCHER_URL or "<unset>",
        "enabled_sources": sorted(ENABLED_SOURCES),
        "chaos_token_present": bool(CHAOS_API_TOKEN),
        "defaults": {
            "max_per_domain": DEFAULT_MAX_PER_DOMAIN,
            "parallelism": DEFAULT_PARALLELISM,
            "http_timeout_sec": HTTP_TIMEOUT,
        },
    }


@app.get("/chaos/test", response_model=ChaosTestResult, summary="Quick Chaos token/domain sanity check")
def chaos_test(domain: str, sample: int = 10) -> ChaosTestResult:
    if "chaos" not in ENABLED_SOURCES:
        raise HTTPException(status_code=400, detail="Chaos source is not enabled")

    client = ChaosClient(api_token=CHAOS_API_TOKEN)
    try:
        subs = client.get_subdomains(domain.strip().lower())
    except ChaosNotFound:
        return ChaosTestResult(domain=domain, count=0, sample=[])
    except ChaosError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e

    subs_l = sorted(subs)
    return ChaosTestResult(domain=domain, count=len(subs_l), sample=subs_l[:max(0, sample)])


@app.post("/sync", response_model=SyncResult, status_code=status.HTTP_202_ACCEPTED)
def sync(req: SyncRequest) -> SyncResult:
    """
    - If `domains` provided and Chaos is enabled: fetch subdomains, cap by `max_per_domain`,
      and dispatch concurrently to scan-dispatcher as https://<subdomain>.
    - If `seed_urls` provided: dispatch those directly.
    """
    if not DISPATCHER_URL:
        raise HTTPException(status_code=503, detail="DISPATCHER_URL not configured")

    errors: List[str] = []
    seen = 0
    dispatched = 0
    truncated = False

    sess = requests.Session()

    # 1) seed_urls path (simple)
    if req.seed_urls:
        urls = [str(u) for u in req.seed_urls]
        seen += len(urls)
        meta = dict(req.metadata)
        meta.setdefault("source", "seed")
        with concurrent.futures.ThreadPoolExecutor(max_workers=req.parallelism) as ex:
            futures = [
                ex.submit(
                    _dispatch_one, sess, DISPATCHER_URL, u, req.priority, req.ttl_seconds, meta
                )
                for u in urls
            ]
            for fut in concurrent.futures.as_completed(futures):
                ok, err = fut.result()
                if ok:
                    dispatched += 1
                else:
                    errors.append(f"seed dispatch failed: {err}")

    # 2) Chaos path
    if req.domains and "chaos" in ENABLED_SOURCES:
        if not CHAOS_API_TOKEN:
            raise HTTPException(status_code=503, detail="CHAOS_API_TOKEN is not configured")

        client = ChaosClient(api_token=CHAOS_API_TOKEN)

        for domain in req.domains:
            try:
                subs = client.get_subdomains(domain)
            except ChaosNotFound:
                log.info("Chaos has no data for %s", domain)
                continue
            except ChaosError as e:
                msg = f"Chaos error for {domain}: {e}"
                log.warning(msg)
                errors.append(msg)
                continue

            # cap results so we return fast
            subs_l = sorted(subs)
            if len(subs_l) > req.max_per_domain:
                subs_l = subs_l[: req.max_per_domain]
                truncated = True

            urls = _build_urls_from_subdomains(set(subs_l), req.scheme)
            seen += len(urls)

            # Prepare per-target metadata
            def meta_for(h: str) -> Dict[str, Any]:
                m = dict(req.metadata)
                m.update({"source": "chaos", "program_domain": domain, "host": h.split("://", 1)[-1]})
                return m

            # Dispatch concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=req.parallelism) as ex:
                futures = [
                    ex.submit(
                        _dispatch_one,
                        sess,
                        DISPATCHER_URL,
                        u,
                        req.priority,
                        req.ttl_seconds,
                        meta_for(u),
                    )
                    for u in urls
                ]
                for fut in concurrent.futures.as_completed(futures):
                    ok, err = fut.result()
                    if ok:
                        dispatched += 1
                    else:
                        errors.append(f"dispatch failed: {err}")

    return SyncResult(
        seen=seen,
        dispatched=dispatched,
        errors=errors,
        enabled_sources=sorted(ENABLED_SOURCES),
        mode="http",
        when=_now_iso(),
        truncated=truncated,
    )

