# server/main.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

from fastapi import FastAPI, Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Optional deps for URL crawling + "heavy ML"
try:
    import requests
except Exception:
    requests = None  # type: ignore

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # type: ignore

# Optional transformers zero-shot
_ZS_AVAILABLE = False
_zs_pipeline = None
try:
    from transformers import pipeline  # type: ignore

    def _load_zero_shot():
        global _ZS_AVAILABLE, _zs_pipeline
        if _zs_pipeline is None:
            # This is a heavy model; will download if not cached.
            # If this fails, we fallback to heuristics.
            _zs_pipeline = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
            _ZS_AVAILABLE = True
        return _zs_pipeline
except Exception:
    def _load_zero_shot():
        return None

# -----------------------------
# FastAPI app + CORS
# -----------------------------
app = FastAPI(title="API Scanner", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev-friendly; tighten for prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Models
# -----------------------------
class FixRequest(BaseModel):
    collection: Any
    provider: str = "none"            # "openai" | "gemini" | "none"
    redact_secrets: bool = True

class ScanRequest(BaseModel):
    collection: Any
    handles: Optional[List[str]] = None  # bug bounty handles, optional

class ReportRequest(BaseModel):
    collection: Any
    handles: Optional[List[str]] = None
    format: str = "markdown"  # "markdown" only for now

class UrlScanRequest(BaseModel):
    url: str
    max_pages: int = 3
    same_host_only: bool = True
    use_heavy_ml: bool = True  # attempt zero-shot if available

# -----------------------------
# Utilities
# -----------------------------
def _now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")

def _as_dict(obj: Any) -> Dict[str, Any]:
    """Accepts dict or JSON string; returns dict or raises."""
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, str):
        try:
            return json.loads(obj)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    raise HTTPException(status_code=400, detail="`collection` must be an object or JSON string.")

def _walk_items(items: List[Dict[str, Any]], prefix: str = "") -> List[Tuple[str, Dict[str, Any]]]:
    """Yield (path, item) pairs recursively from a Postman collection."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    for it in items or []:
        name = it.get("name") or "(unnamed)"
        path = f"{prefix}/{name}" if prefix else name
        if "request" in it:
            out.append((path, it))
        # folder
        if "item" in it and isinstance(it["item"], list):
            out.extend(_walk_items(it["item"], path))
    return out

def _headers_list_to_dict(headers: List[Dict[str, Any]]) -> Dict[str, str]:
    d: Dict[str, str] = {}
    for h in headers or []:
        key = h.get("key")
        val = h.get("value")
        if key is not None and val is not None:
            d[str(key)] = str(val)
    return d

def _set_headers_from_dict(hdict: Dict[str, str]) -> List[Dict[str, str]]:
    return [{"key": k, "value": v} for k, v in hdict.items()]

# -----------------------------
# "AI Fix" – lightweight normalizer
# -----------------------------
SENSITIVE_HEADER_KEYS = {
    "authorization",
    "x-app-token",
    "x_app_token",
    "x-auth-user",
    "cookie",
    "access-token",
}

def _coerce_bool(val: Any) -> Optional[bool]:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        v = val.strip().lower()
        if v in {"true", "t", "1", "yes"}:
            return True
        if v in {"false", "f", "0", "no"}:
            return False
    return None  # unknown

def ai_style_fix(collection: Dict[str, Any], redact_secrets: bool = True) -> Dict[str, Any]:
    col = json.loads(json.dumps(collection))  # deep-copy

    items = col.get("collection", {}).get("item", [])
    for path, it in _walk_items(items):
        req = it.get("request", {})
        method = str(req.get("method", "GET")).upper()

        # Normalize headers
        headers = _headers_list_to_dict(req.get("header", []))

        # Redact secrets
        if redact_secrets:
            for hk in list(headers.keys()):
                if hk.lower() in SENSITIVE_HEADER_KEYS:
                    headers[hk] = "***REDACTED***"

        # Ensure Content-Type for methods with bodies
        if method in {"POST", "PUT", "PATCH"}:
            if "Content-Type" not in headers and "content-type" not in headers:
                headers["Content-Type"] = "application/json"

        # Replace obviously invalid boolean strings
        body = req.get("body", {})
        if isinstance(body, dict) and body.get("mode") == "raw":
            raw = body.get("raw")
            if isinstance(raw, str) and raw.strip():
                try:
                    j = json.loads(raw)
                    changed = False
                    for k in list(j.keys()):
                        if k in {"is_trigger_workflow"}:
                            b = _coerce_bool(j[k])
                            if b is None:
                                j[k] = False
                                changed = True
                            else:
                                if b != j[k]:
                                    j[k] = b
                                    changed = True
                    if changed:
                        body["raw"] = json.dumps(j, ensure_ascii=False)
                        req["body"] = body
                except Exception:
                    pass

        req["header"] = _set_headers_from_dict(headers)
        it["request"] = req

    return col

# -----------------------------
# Scanner rules (Postman)
# -----------------------------
class Finding(Dict[str, Any]):
    pass

def _add_finding(findings: List[Finding], severity: str, path: str, msg: str, recommend: str, evidence: Optional[Dict[str, Any]] = None) -> None:
    findings.append({
        "severity": severity,  # High/Medium/Low/Info
        "path": path,
        "issue": msg,
        "recommendation": recommend,
        "evidence": evidence or {},
    })

_HTTP_RE = re.compile(r"^http://", re.IGNORECASE)
_STAGE_RE = re.compile(r"stage[-.]k8s|staging|dev|prod-dev", re.IGNORECASE)
_KEY_HINTS = re.compile(r"(?:key|token|secret|password|client_id|access[_-]?token|api[_-]?key)=", re.I)

def _contains_redacted_value(obj: Any) -> bool:
    if isinstance(obj, str):
        return "***REDACTED***" in obj
    if isinstance(obj, dict):
        return any(_contains_redacted_value(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_redacted_value(v) for v in obj)
    return False

def scan_collection(collection: Dict[str, Any]) -> Dict[str, Any]:
    items = collection.get("collection", {}).get("item", [])
    findings: List[Finding] = []

    unique_hosts: Set[str] = set()
    out_of_scope: Set[str] = set()

    for path, it in _walk_items(items):
        req = it.get("request", {})
        url = req.get("url", {})
        method = str(req.get("method", "GET")).upper()
        headers = _headers_list_to_dict(req.get("header", []))

        # Host capture
        host = None
        if isinstance(url, dict):
            if "host" in url and isinstance(url["host"], list):
                host = ".".join([str(x) for x in url["host"] if x])
            elif "raw" in url:
                host = str(url["raw"])
                try:
                    m = re.search(r"://([^/]+)", host)
                    if m:
                        host = m.group(1)
                except Exception:
                    pass
        if host:
            unique_hosts.add(host)

        # Rule: HTTP scheme (non-TLS)
        raw = url.get("raw") if isinstance(url, dict) else None
        if isinstance(raw, str) and _HTTP_RE.search(raw):
            sev = "Medium"
            if not _STAGE_RE.search(raw):
                sev = "High"
            _add_finding(
                findings,
                severity=sev,
                path=path,
                msg="Request uses insecure HTTP.",
                recommend="Use HTTPS for all requests. Enforce TLS and HSTS.",
                evidence={"url": raw, "method": method},
            )

        # Rule: Sensitive headers present (even if redacted)
        for hk, hv in headers.items():
            if hk.lower() in SENSITIVE_HEADER_KEYS:
                _add_finding(
                    findings,
                    severity="Low",
                    path=path,
                    msg=f"Sensitive header '{hk}' is used.",
                    recommend="Avoid sending secrets from client tools; use env vars, vaults, or short-lived tokens. Ensure values are redacted in exports.",
                    evidence={"header": hk, "value": hv},
                )

        # Rule: Keys/Secrets in query strings
        if isinstance(raw, str) and _KEY_HINTS.search(raw):
            _add_finding(
                findings,
                severity="Medium",
                path=path,
                msg="Possible credentials in URL query string.",
                recommend="Do not place secrets/IDs in query; use headers or POST body and rotate keys.",
                evidence={"url": raw},
            )

        # Rule: GET with body
        body = req.get("body", {})
        if method == "GET" and isinstance(body, dict) and any(body.get(k) for k in ("raw", "formdata", "graphql", "urlencoded", "file")):
            _add_finding(
                findings,
                severity="Low",
                path=path,
                msg="GET request includes a body.",
                recommend="Remove body for GET or change to POST/PUT as appropriate.",
            )

        # Rule: POST/PUT/PATCH without Content-Type
        if method in {"POST", "PUT", "PATCH"}:
            if not any(k.lower() == "content-type" for k in headers.keys()):
                _add_finding(
                    findings,
                    severity="Low",
                    path=path,
                    msg="No Content-Type for request with body.",
                    recommend="Set 'Content-Type: application/json' (or correct type).",
                )

        # Rule: Boolean fields expressed as strings in JSON bodies
        if isinstance(body, dict) and body.get("mode") == "raw":
            rawb = body.get("raw")
            if isinstance(rawb, str) and rawb.strip():
                try:
                    jb = json.loads(rawb)
                    if isinstance(jb, dict):
                        for k, v in jb.items():
                            if k in {"is_trigger_workflow"} and isinstance(v, str):
                                _add_finding(
                                    findings,
                                    severity="Low",
                                    path=path,
                                    msg=f"Boolean field '{k}' provided as string.",
                                    recommend="Use true/false (boolean) instead of quoted strings.",
                                    evidence={"value": v},
                                )
                except Exception:
                    pass

        # Rule: Stage/dev host — Info
        if raw and _STAGE_RE.search(raw):
            _add_finding(
                findings,
                severity="Info",
                path=path,
                msg="Request points to staging/dev environment.",
                recommend="Ensure no production secrets are used against non-prod hosts.",
                evidence={"url": raw},
            )

        # Rule: Placeholder redactions left inside JSON bodies (indicates incomplete config)
        if isinstance(body, dict) and _contains_redacted_value(body):
            _add_finding(
                findings,
                severity="Low",
                path=path,
                msg="Request body contains redacted placeholders.",
                recommend="Provide real values securely at runtime; do not hardcode secrets in exported collections.",
            )

        # Rule: Suspicious non-standard headers like 'Port'
        for hk in headers.keys():
            if hk.lower() == "port":
                _add_finding(
                    findings,
                    severity="Info",
                    path=path,
                    msg="Non-standard header 'Port' detected.",
                    recommend="Avoid custom headers for infra details; prefer hostnames/ports in URL.",
                )

    in_scope_assets = sorted(unique_hosts)
    out_scope_assets = sorted(out_of_scope)

    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "generated_at": _now_utc_str(),
        "summary": counts,
        "findings": findings,
        "in_scope_assets": in_scope_assets,
        "out_of_scope_hosts": out_scope_assets,
    }

# -----------------------------
# URL Scanner (crawl + ML)
# -----------------------------
SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "Possible AWS Access Key ID"),
    (re.compile(r"(?i)sk-[a-z0-9]{32,}"), "Possible secret key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Possible Google API key"),
    (re.compile(r"ghp_[0-9A-Za-z]{36}"), "Possible GitHub token"),
    (re.compile(r"(?i)(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['\"][^'\"<>]{8,}['\"]"), "Hardcoded credential"),
]

API_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)

def _normalize_url(u: str) -> str:
    return u.split("#", 1)[0].strip()

def _same_host(a: str, b: str) -> bool:
    def host(x: str) -> str:
        m = re.search(r"^https?://([^/]+)", x, re.I)
        return m.group(1).lower() if m else ""
    return host(a) == host(b)

def _fetch(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (text, content_type) or (None, None) on failure."""
    if requests is None:
        return None, None
    try:
        r = requests.get(url, timeout=10)
        ct = r.headers.get("content-type", "")
        if "text" in ct or "json" in ct or "javascript" in ct:
            return r.text, ct
        return "", ct
    except Exception:
        return None, None

def _extract_links(base_url: str, html: str) -> List[str]:
    links: Set[str] = set()
    if BeautifulSoup is not None:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["a", "script"]):
                href = tag.get("href") or tag.get("src")
                if href and isinstance(href, str):
                    if href.startswith("//"):
                        href = "https:" + href
                    elif href.startswith("/"):
                        # build absolute from base
                        m = re.match(r"^(https?://[^/]+)", base_url, re.I)
                        if m:
                            href = m.group(1) + href
                    elif not href.startswith("http"):
                        # skip relative oddities
                        continue
                    links.add(_normalize_url(href))
        except Exception:
            pass
    # Fallback: regex URLs
    for m in API_URL_RE.finditer(html):
        links.add(_normalize_url(m.group(0)))
    return list(links)

def _heavy_ml_labels(snippet: str) -> List[str]:
    """
    Try zero-shot classification on a snippet to detect likely bugs.
    Returns list of labels that pass a threshold.
    """
    candidate_labels = [
        "exposed secret",
        "api key leakage",
        "hardcoded credentials",
        "insecure http link",
        "open admin endpoint",
        "debug endpoint",
        "token exposure",
    ]
    zs = _load_zero_shot()
    if not zs:
        return []
    try:
        res = zs(snippet[:800], candidate_labels=candidate_labels, multi_label=True)
        labels = []
        for lbl, score in zip(res["labels"], res["scores"]):
            if score >= 0.65:
                labels.append(lbl)
        return labels
    except Exception:
        return []

def scan_url_root(url: str, max_pages: int = 3, same_host_only: bool = True, use_heavy_ml: bool = True) -> Dict[str, Any]:
    findings: List[Finding] = []
    visited: Set[str] = set()
    queue: List[str] = [url]
    pages_scanned = 0

    in_scope_assets: Set[str] = set()
    start_host_match = re.search(r"^https?://([^/]+)", url, re.I)
    start_host = start_host_match.group(1).lower() if start_host_match else ""

    while queue and pages_scanned < max_pages:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        text, ct = _fetch(current)
        if text is None:
            _add_finding(
                findings,
                severity="Info",
                path=current,
                msg="Fetch failed (network or permission).",
                recommend="Ensure the scanner has network access and the URL is reachable.",
            )
            continue

        in_scope_assets.add(start_host or current)

        # Heuristic rules on page
        if current.lower().startswith("http://"):
            _add_finding(
                findings,
                severity="High",
                path=current,
                msg="Page served over HTTP (no TLS).",
                recommend="Serve pages over HTTPS with HSTS.",
            )

        # Secrets / tokens leakage in page content
        for rx, label in SECRET_PATTERNS:
            for m in rx.finditer(text):
                val = m.group(0)
                _add_finding(
                    findings,
                    severity="High",
                    path=current,
                    msg=f"Potential secret detected: {label}.",
                    recommend="Remove secrets from client-delivered content. Rotate keys immediately.",
                    evidence={"match": val[:8] + "..."},
                )

        # API endpoints in page
        for m in API_URL_RE.finditer(text):
            api_u = m.group(0)
            if api_u.lower().startswith("http://"):
                _add_finding(
                    findings,
                    severity="Medium",
                    path=current,
                    msg="Insecure API endpoint reference (HTTP).",
                    recommend="Use HTTPS API endpoints.",
                    evidence={"url": api_u},
                )

        # Optional "heavy ML" pass (zero-shot)
        if use_heavy_ml:
            labels = _heavy_ml_labels(text[:5000])
            for lbl in labels:
                sev = "Medium"
                if "secret" in lbl or "credentials" in lbl or "token" in lbl:
                    sev = "High"
                _add_finding(
                    findings,
                    severity=sev,
                    path=current,
                    msg=f"ML-suspected issue: {lbl}.",
                    recommend="Review and sanitize client-delivered content; rotate and move secrets server-side.",
                )

        # Crawl next links (only if HTML)
        if ct and "html" in ct.lower():
            links = _extract_links(current, text)
            for lnk in links:
                if same_host_only and not _same_host(url, lnk):
                    continue
                if lnk not in visited and len(queue) + pages_scanned < max_pages:
                    queue.append(lnk)

        pages_scanned += 1

    # Summary
    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "generated_at": _now_utc_str(),
        "summary": counts,
        "findings": findings,
        "in_scope_assets": sorted(in_scope_assets),
        "out_of_scope_hosts": [],
    }

# -----------------------------
# Report renderer
# -----------------------------
def render_markdown_report(scan: Dict[str, Any]) -> str:
    ts = scan.get("generated_at") or _now_utc_str()
    s = scan.get("summary", {})
    findings: List[Dict[str, Any]] = scan.get("findings", [])
    in_scope = scan.get("in_scope_assets", []) or []
    out_scope = scan.get("out_of_scope_hosts", []) or []

    lines: List[str] = []
    lines.append("# API Scan Report")
    lines.append(f"_Generated: {ts}_\n")
    lines.append("## Summary")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ["High", "Medium", "Low", "Info"]:
        lines.append(f"| {sev} | {int(s.get(sev, 0))} |")
    lines.append("")

    lines.append("## Findings")
    if not findings:
        lines.append("No findings.\n")
    else:
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f.get('issue')}")
            lines.append(f"- **Severity:** {f.get('severity')}")
            if f.get("path"):
                lines.append(f"- **Item:** `{f['path']}`")
            ev = f.get("evidence") or {}
            if ev:
                pretty = "  \n".join(f"- `{k}`: `{v}`" for k, v in ev.items())
                lines.append(f"- **Evidence:**  \n{pretty}")
            if f.get("recommendation"):
                lines.append(f"- **Recommendation:** {f['recommendation']}")
            lines.append("")

    lines.append("## Out-of-Scope Hosts")
    if out_scope:
        for h in out_scope:
            lines.append(f"- `{h}`")
    else:
        lines.append("None")

    lines.append("\n## In-Scope Assets")
    if in_scope:
        for h in in_scope:
            lines.append(f"- `{h}`")
    else:
        lines.append("None")

    return "\n".join(lines)

# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
def health():
    return {"ok": True, "time": _now_utc_str()}

@app.post("/ai/fix_postman")
def ai_fix_postman(req: FixRequest):
    col = _as_dict(req.collection)
    fixed = ai_style_fix(col, redact_secrets=req.redact_secrets)
    return fixed

@app.post("/scan/postman")
def scan_postman(req: ScanRequest):
    col = _as_dict(req.collection)
    return scan_collection(col)

@app.post("/scan/report")
def scan_report(req: ReportRequest):
    col = _as_dict(req.collection)
    scan = scan_collection(col)
    md = render_markdown_report(scan)
    return md

@app.post("/scan/url")
def scan_url(req: UrlScanRequest):
    if not re.match(r"^https?://", req.url, re.I):
        raise HTTPException(status_code=400, detail="Provide an absolute URL starting with http:// or https://")
    return scan_url_root(req.url, max_pages=max(1, min(20, req.max_pages)), same_host_only=req.same_host_only, use_heavy_ml=req.use_heavy_ml)

@app.post("/scan/url_report")
def scan_url_report(req: UrlScanRequest):
    scan = scan_url(req)
    md = render_markdown_report(scan)
    return md

@app.get("/hackerone/inscope")
def hackerone_inscope(handles: Optional[str] = None):
    handles_list = [h.strip() for h in (handles or "").split(",") if h.strip()]
    return {"handles": handles_list, "assets": []}

