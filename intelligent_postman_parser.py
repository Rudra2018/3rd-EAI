"""
Intelligent Postman Parser & Auto-Fixer
--------------------------------------

This module loads a Postman collection (v2.x), analyzes each request, and auto-fixes
common issues using a blend of deterministic heuristics and an LLM (OpenAI or Gemini).

Key features
- Safe-by-default: redacts secrets before sending to LLM; never logs secret values.
- Deterministic fixes first (headers, content-type, accept, JSON coercion, date/boolean types).
- LLM-assisted patches when deterministic passes cannot fix a request.
- Structured JSON patches: we ask the model to output a strict JSON object with a list of
  RFC 6901 JSON-Pointer operations (add/replace/remove) + rationale for each change.
- Provider abstraction: works with OpenAI or Gemini (via OpenAI-compatible API) with the
  same code path. Choose via env: AI_PROVIDER=openai|gemini.
- Error-feedback loop (optional): if you pass a scan results JSON (like the one you posted),
  the script correlates failures by method+URL and feeds the error text to the LLM as hints.

Environment variables (suggested)
- AI_PROVIDER: "openai" or "gemini" (default: openai)
- OPENAI_API_KEY: <your key>
- GEMINI_API_KEY: <your key>
- GEMINI_COMPAT_BASE: Optional override for Gemini OpenAI-compat base URL
  (default: https://generativelanguage.googleapis.com)
- AI_MODEL: openai model name (default: gpt-4o-mini) or gemini model name (via compat layer,
  e.g. gemini-1.5-pro-latest). See docs.
- OFFLINE_ONLY: if set to "1", disables LLM calls; only deterministic fixes are applied.

Tokens per service (recommended, optional)
- Define per-domain tokens as env vars; e.g. TOKEN_RECON_INIT, TOKEN_PD_B2C, etc.
  The script includes a hook to map hostnames to token env vars so it can inject
  x-app-token for you without exposing secret values to the LLM.

CLI usage
---------
python intelligent_postman_parser.py \
  --in path/to/collection.json \
  --out path/to/fixed.collection.json \
  --logs path/to/scanner_results.json  # optional error corpus

"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime as _dt
import json
import os
import re
import sys
import typing as t
from pathlib import Path
from urllib.parse import urlparse

# ----------------------------- Utilities -----------------------------

_JSON = t.Union[dict, list, str, int, float, bool, None]

HEADER_CANONICAL = {
    "content-type": "Content-Type",
    "accept": "Accept",
    "user-agent": "User-Agent",
    "x-app-token": "X-APP-TOKEN",
    "x-auth-user": "X-AUTH-USER",
}

DEFAULT_USER_AGENT = "UA-intelligent-postman-parser/1.0"
DEFAULT_CONTENT_TYPE = "application/json"
DEFAULT_ACCEPT = "application/json"

DATE_FORMATS_IN = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
]
DATE_FORMAT_OUT = "%Y-%m-%d %H:%M:%S"  # normalize to this when time is present

RE_BOOLISH_KEY = re.compile(r"^(is_|has_|enable|enabled|disable|disabled|flag_|use_|allow_|require)", re.I)


def _is_json_like_body(raw: t.Any) -> bool:
    if raw is None:
        return False
    if isinstance(raw, (dict, list)):
        return True
    if isinstance(raw, str):
        # crude check to avoid pulling in json5; we'll let LLM fix tricky cases
        s = raw.strip()
        return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))
    return False


def _canonicalize_headers(headers: list[dict]) -> list[dict]:
    seen = {}
    fixed = []
    for h in headers or []:
        key = h.get("key") or h.get("name")
        if not key:
            continue
        val = h.get("value", "")
        lk = key.lower()
        ck = HEADER_CANONICAL.get(lk, "-".join([p.capitalize() for p in lk.split("-")]))
        if ck.lower() in seen:
            # merge duplicates: prefer non-empty
            if val and not seen[ck.lower()]["value"]:
                seen[ck.lower()]["value"] = val
            continue
        item = {"key": ck, "value": val}
        seen[ck.lower()] = item
        fixed.append(item)
    # ensure defaults exist
    if not any(h["key"].lower() == "content-type" for h in fixed):
        fixed.append({"key": "Content-Type", "value": DEFAULT_CONTENT_TYPE})
    if not any(h["key"].lower() == "accept" for h in fixed):
        fixed.append({"key": "Accept", "value": DEFAULT_ACCEPT})
    if not any(h["key"].lower() == "user-agent" for h in fixed):
        fixed.append({"key": "User-Agent", "value": DEFAULT_USER_AGENT})
    return fixed


def _coerce_booleans_and_dates(obj: _JSON) -> _JSON:
    """Recursively coerce string booleans and common date formats to canonical forms."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = _coerce_booleans_and_dates(v)
            # KEYS that imply boolean but value is string
            if isinstance(v, str) and RE_BOOLISH_KEY.search(k):
                lv = v.lower().strip()
                if lv in {"true", "false"}:
                    out[k] = lv == "true"
            # Strings that look like dates
            if isinstance(out[k], str):
                out[k] = _normalize_date_string(out[k]) or out[k]
        return out
    if isinstance(obj, list):
        return [_coerce_booleans_and_dates(v) for v in obj]
    if isinstance(obj, str):
        # top-level string that looks like a date
        return _normalize_date_string(obj) or obj
    return obj


def _normalize_date_string(s: str) -> t.Optional[str]:
    s2 = s.strip().replace("/", "-")
    # Try multiple formats
    for fmt in DATE_FORMATS_IN:
        try:
            dt = _dt.datetime.strptime(s2, fmt)
            # If format had date only, return date only
            if fmt == "%Y-%m-%d":
                return dt.strftime("%Y-%m-%d")
            # otherwise return uniform datetime
            return dt.strftime(DATE_FORMAT_OUT)
        except Exception:
            continue
    # ISO-ish like 2025-08-24T14:19:59Z
    try:
        from dateutil import parser as _p  # optional dependency if available
        dt = _p.parse(s2)
        # keep date if 00:00
        if dt.hour == 0 and dt.minute == 0 and dt.second == 0 and dt.tzinfo is None:
            return dt.strftime("%Y-%m-%d")
        return dt.strftime(DATE_FORMAT_OUT)
    except Exception:
        return None


def _redact_secrets(headers: list[dict]) -> list[dict]:
    redacted = []
    for h in headers or []:
        k = (h.get("key") or "").lower()
        v = h.get("value")
        if any(x in k for x in ["token", "authorization", "api-key", "x-app-token", "x-auth-token", "apikey"]):
            redacted.append({"key": h.get("key"), "value": "<REDACTED>"})
        else:
            redacted.append(h)
    return redacted


# ----------------------------- LLM Client -----------------------------

@dataclasses.dataclass
class LLMConfig:
    provider: str = os.getenv("AI_PROVIDER", "openai").strip().lower()  # openai|gemini
    model: str = os.getenv("AI_MODEL", "gpt-4o-mini")
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    gemini_api_key: str | None = os.getenv("GEMINI_API_KEY")
    gemini_compat_base: str = os.getenv("GEMINI_COMPAT_BASE", "https://generativelanguage.googleapis.com")
    offline_only: bool = os.getenv("OFFLINE_ONLY", "0") == "1"


class AIClient:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._client = None
        if self.cfg.offline_only:
            return
        try:
            from openai import OpenAI
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "Please install openai: pip install openai"
            ) from e
        # Use OpenAI client for both providers (Gemini via OpenAI-compatible API)
        base_url = None
        api_key = None
        if self.cfg.provider == "openai":
            api_key = self.cfg.openai_api_key
            base_url = None
        elif self.cfg.provider == "gemini":
            api_key = self.cfg.gemini_api_key
            # Gemini OpenAI-compat path is /openai/ on the generativelanguage domain
            base_url = f"{self.cfg.gemini_compat_base}/openai/"
        else:
            raise ValueError("AI_PROVIDER must be 'openai' or 'gemini'")
        if not api_key:
            raise RuntimeError(f"Missing API key for provider {self.cfg.provider}")
        self._client = OpenAI(api_key=api_key, base_url=base_url)

    def suggest_patches(self, *, request: dict, errors: list[str]) -> dict:
        """Ask the model for JSON patches for this Postman request.
        Returns a dict with {"patches": [...], "notes": "..."}
        """
        if self.cfg.offline_only:
            return {"patches": [], "notes": "offline-only: no LLM used"}
        assert self._client is not None

        system = (
            "You are a strict linter and auto-fixer for Postman collections. "
            "You return ONLY valid JSON as per the schema. "
            "Follow HTTP semantics. Don't invent tokens. Don't change URL paths. "
            "When you must create example values, use safe placeholders (e.g. '2024-01-01 00:00:00', true/false). "
            "Fix common issues: add 'Content-Type: application/json', add 'Accept: application/json', "
            "coerce boolean-like strings to booleans, normalize date strings to 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DD', "
            "and ensure bodies are valid JSON with correct types."
        )

        user = {
            "request": {
                "name": request.get("name"),
                "method": request.get("method"),
                "url": request.get("url"),
                "headers": _redact_secrets(request.get("header", [])),
                "body": request.get("body"),
            },
            "errors": errors or [],
            "instructions": (
                "Return a JSON object with keys 'patches' and 'notes'.\n"
                "Each item in 'patches' must be an object: {""""op"""": "add|replace|remove", """"path"""": "/header/0/value" style JSON-Pointer, """"value"""": any}.\n"
                "Allowed paths: /header/<idx>/<key|value>, /body/raw (complete), /method, /url.\n"
                "Prefer replace over add when the target exists.\n"
                "Do NOT include any secrets or tokens. Use '<REDACTED>' when needed."
            ),
        }

        # Ask the model for JSON output using chat.completions and response_format json_object
        resp = self._client.chat.completions.create(
            model=self.cfg.model,
            response_format={"type": "json_object"},
            temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
            ],
        )
        content = resp.choices[0].message.content
        try:
            data = json.loads(content)
            # Ensure shape
            if "patches" not in data or not isinstance(data["patches"], list):
                raise ValueError("missing patches")
            return data
        except Exception as e:
            # graceful fallback: no patches
            return {"patches": [], "notes": f"LLM parse error: {e}"}


# ------------------------- Postman structures -------------------------

@dataclasses.dataclass
class FixReport:
    name: str
    method: str
    url: str
    deterministic_fixes: list[str]
    llm_fixes: list[str]


# Postman v2 uses nested items (folders). We'll flatten and track pointers.
@dataclasses.dataclass
class ItemRef:
    path: list[int]  # indices to locate in collection["item"][*] recursively
    item: dict


def _iter_items(items: list[dict], prefix: list[int] | None = None) -> t.Iterator[ItemRef]:
    prefix = prefix or []
    for idx, it in enumerate(items or []):
        p = prefix + [idx]
        if "item" in it and isinstance(it["item"], list):
            yield from _iter_items(it["item"], p)
        else:
            yield ItemRef(path=p, item=it)


# ----------------------------- Core logic -----------------------------

def _request_from_item(it: dict) -> dict:
    req = it.get("request") or {}
    # Normalize URL to raw string for analysis
    url = req.get("url")
    if isinstance(url, dict):
        req["url"] = url.get("raw") or url
    return req


def _apply_header_fix(req: dict, report_msgs: list[str]) -> None:
    headers = req.get("header") or []
    fixed = _canonicalize_headers(headers)
    if headers != fixed:
        req["header"] = fixed
        report_msgs.append("normalized headers, added defaults where missing")


def _apply_body_coercions(req: dict, report_msgs: list[str]) -> None:
    body = req.get("body")
    if not body:
        return
    mode = body.get("mode")
    if mode == "raw":
        raw = body.get("raw")
        if not _is_json_like_body(raw):
            return
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            # keep as-is; LLM may fix later
            return
        coerced = _coerce_booleans_and_dates(parsed)
        if coerced != parsed:
            req.setdefault("body", {})["raw"] = json.dumps(coerced, ensure_ascii=False, indent=2)
            report_msgs.append("coerced booleans/dates in JSON body")
    elif mode == "urlencoded":
        # could coerce booleans in form-data values
        fields = body.get("urlencoded") or []
        changed = False
        for f in fields:
            v = f.get("value")
            if isinstance(v, str) and v.lower() in {"true", "false"}:
                f["value"] = "true" if v.lower() == "true" else "false"
                changed = True
        if changed:
            report_msgs.append("normalized bool-like strings in x-www-form-urlencoded body")


def _inject_token_if_configured(req: dict, report_msgs: list[str]) -> None:
    # map host -> env var for token
    url = req.get("url") or ""
    if not isinstance(url, str):
        return
    host = urlparse(url).hostname or ""
    mapping = {
        "recon-init.stage-k8s.halodoc.com": "TOKEN_RECON_INIT",
        "pd-b2c-recon-init.stage-k8s.halodoc.com": "TOKEN_PD_B2C",
        "medisend-b2b-recon-init.stage-k8s.halodoc.com": "TOKEN_MEDISEND_B2B",
        "halolab-recon-init.stage-k8s.halodoc.com": "TOKEN_HALOLAB",
        "pg-recon-init.stage-k8s.halodoc.com": "TOKEN_PG",
        "scrooge-payment.stage-k8s.halodoc.com": "TOKEN_SCROOGE_PAY",
        "recon-catalog.stage-k8s.halodoc.com": "TOKEN_RECON_CATALOG",
        "tpa-recon-init.stage-k8s.halodoc.com": "TOKEN_TPA",
        "watchdog-service.stage-k8s.halodoc.com": "TOKEN_WATCHDOG",
        "accurate-inventory-system.stage-k8s.halodoc.com": "TOKEN_ACCURATE_INV",
    }
    env_var = mapping.get(host)
    if not env_var:
        return
    token = os.getenv(env_var)
    if not token:
        return
    headers = req.setdefault("header", [])
    # check existing
    if not any((h.get("key") or "").lower() == "x-app-token" for h in headers):
        headers.append({"key": "X-APP-TOKEN", "value": token})
        report_msgs.append(f"injected X-APP-TOKEN from env {env_var}")


PATCH_OP = t.TypedDict(
    "PATCH_OP",
    {"op": str, "path": str, "value": t.NotRequired[_JSON]},
)


def _apply_json_pointer(obj: _JSON, path: str, op: str, value: _JSON | None) -> _JSON:
    # limited JSON-Pointer for our needs
    if not path.startswith("/"):
        raise ValueError("JSON-Pointer must start with /")
    parts = [p.replace("~1", "/").replace("~0", "~") for p in path.strip("/").split("/") if p]
    parent = None
    current = obj
    key = None
    for p in parts:
        parent = current
        key = p
        if isinstance(current, list):
            idx = int(p)
            if idx < 0 or idx >= len(current):
                raise IndexError(f"index out of range: {p}")
            current = current[idx]
        elif isinstance(current, dict):
            if p not in current:
                if op == "add" and p == parts[-1]:
                    break
                raise KeyError(f"missing key: {p}")
            current = current[p]
        else:
            raise TypeError("invalid path traversal")

    # apply operation on parent[key]
    if isinstance(parent, list):
        idx = int(key)
        if op == "remove":
            parent.pop(idx)
        elif op in {"add", "replace"}:
            if value is None:
                raise ValueError("value required")
            parent[idx] = value
        else:
            raise ValueError("unsupported op")
    elif isinstance(parent, dict):
        if op == "remove":
            parent.pop(key, None)
        elif op in {"add", "replace"}:
            if value is None:
                raise ValueError("value required")
            parent[key] = value
        else:
            raise ValueError("unsupported op")
    else:
        raise TypeError("cannot modify non-container parent")
    return obj


def _apply_llm_patches(req: dict, patches: list[PATCH_OP], report_msgs: list[str]) -> None:
    for p in patches:
        try:
            op = p.get("op")
            path = p.get("path")
            val = p.get("value")
            if op not in {"add", "replace", "remove"}:
                continue
            if not isinstance(path, str):
                continue
            # We only allow limited paths for safety
            if not (path.startswith("/header/") or path == "/body/raw" or path in {"/method", "/url"}):
                continue
            # Expand shortcut paths to actual structure
            if path.startswith("/header/"):
                headers = req.setdefault("header", [])
                # naive: ensure index exists by padding
                try:
                    target_idx = int(path.split("/")[2])
                except Exception:
                    continue
                while len(headers) <= target_idx:
                    headers.append({"key": "", "value": ""})
            if path == "/body/raw":
                req.setdefault("body", {})["mode"] = "raw"
            _apply_json_pointer(req, path, op, val)
            report_msgs.append(f"LLM patch {op} {path}")
        except Exception:
            continue


# ------------------------------ Scanner Hints ------------------------------

def _load_scanner_hints(path: Path | None) -> dict[tuple[str, str], list[str]]:
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    hints: dict[tuple[str, str], list[str]] = {}
    for entry in data.get("results", []):
        req = entry.get("request", {})
        method = (req.get("method") or "").upper()
        url = req.get("url") or ""
        key = (method, url)
        msgs = []
        if entry.get("error"):
            msgs.append(str(entry["error"]))
        resp = entry.get("response") or {}
        if resp:
            status = resp.get("status")
            body_prev = resp.get("body_preview")
            if status is not None:
                msgs.append(f"status={status}")
            if body_prev:
                msgs.append(str(body_prev))
        if msgs:
            hints.setdefault(key, []).extend(msgs)
    return hints


# ------------------------------- Main flow -------------------------------

def intelligent_fix(collection: dict, *, logs_path: Path | None = None, ai: AIClient | None = None) -> tuple[dict, list[FixReport]]:
    coll = copy.deepcopy(collection)
    reports: list[FixReport] = []

    hints = _load_scanner_hints(logs_path)

    for ref in _iter_items(coll.get("item", [])):
        it = ref.item
        name = it.get("name") or "<unnamed>"
        req = _request_from_item(it)
        if not req:
            continue
        method = (req.get("method") or "").upper()
        url = req.get("url") or ""
        det_msgs: list[str] = []
        llm_msgs: list[str] = []

        _apply_header_fix(req, det_msgs)
        _apply_body_coercions(req, det_msgs)
        _inject_token_if_configured(req, det_msgs)

        # LLM assisted pass if we have hints or body failed JSON parsing
        errors = hints.get((method, url), [])

        # Detect invalid JSON body to escalate
        need_llm = False
        body = req.get("body")
        if body and body.get("mode") == "raw":
            raw = body.get("raw")
            if _is_json_like_body(raw):
                if isinstance(raw, str):
                    try:
                        json.loads(raw)
                    except Exception:
                        need_llm = True
        if errors:
            # escalate on 415/422/400 and null body parsing
            if any(x.startswith("status=") and x.split("=")[-1] in {"415", "422", "400"} for x in errors):
                need_llm = True

        if need_llm and ai is not None:
            resp = ai.suggest_patches(request=req, errors=errors)
            patches = t.cast(list[PATCH_OP], resp.get("patches", []))
            _apply_llm_patches(req, patches, llm_msgs)
            notes = resp.get("notes")
            if notes:
                llm_msgs.append(f"notes: {notes}")

        reports.append(
            FixReport(name=name, method=method, url=url, deterministic_fixes=det_msgs, llm_fixes=llm_msgs)
        )

    return coll, reports


def main() -> int:
    ap = argparse.ArgumentParser(description="Intelligent Postman collection parser & fixer")
    ap.add_argument("--in", dest="in_path", required=True, help="input Postman collection JSON")
    ap.add_argument("--out", dest="out_path", required=True, help="output path for fixed collection")
    ap.add_argument("--logs", dest="logs_path", default=None, help="optional scanner results JSON path")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)
    logs_path = Path(args.logs_path) if args.logs_path else None

    try:
        collection = json.loads(in_path.read_text())
    except Exception as e:
        print(f"Failed to read collection: {e}", file=sys.stderr)
        return 2

    cfg = LLMConfig()
    ai: AIClient | None = None
    if not cfg.offline_only:
        try:
            ai = AIClient(cfg)
        except Exception as e:
            print(f"LLM disabled: {e}")
            ai = None

    fixed, reports = intelligent_fix(collection, logs_path=logs_path, ai=ai)

    out_path.write_text(json.dumps(fixed, ensure_ascii=False, indent=2))

    # Summarize to stdout
    print("Fix Summary:\n" + "-" * 60)
    for r in reports:
        if not (r.deterministic_fixes or r.llm_fixes):
            continue
        print(f"{r.method} {r.url} [{r.name}]")
        for m in r.deterministic_fixes:
            print(f"  ✔ {m}")
        for m in r.llm_fixes:
            print(f"  ✨ {m}")
        print()

    print(f"Saved fixed collection -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

