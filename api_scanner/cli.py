# api_scanner/cli.py
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import inspect
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode

# ------------------------
# Optional imports with robust fallbacks
# ------------------------
try:
    from .models import Target, ScanContext  # type: ignore
except Exception:
    @dataclass
    class Target:
        method: str
        url: str
        headers: Dict[str, str] | None = None
        body: Any = None

    @dataclass
    class ScanContext:
        targets: List["Target"]
        rate_per_sec: float = 5.0
        timeout: float = 15.0

# Try to find ScannerEngine in several plausible locations
ScannerEngine = None  # type: ignore
for _candidate in (
    "api_scanner.engine.scanner_engine",
    "api_scanner.engine",
    ".engine.scanner_engine",
    ".engine",
):
    try:
        if _candidate.startswith("."):
            mod = __import__(__package__ + _candidate[1:], fromlist=["ScannerEngine"])
        else:
            mod = __import__(_candidate, fromlist=["ScannerEngine"])
        ScannerEngine = getattr(mod, "ScannerEngine")
        break
    except Exception:
        continue

if ScannerEngine is None:
    raise ImportError("Could not import ScannerEngine from api_scanner.engine")

# Introspect ScanContext ctor params once
try:
    _SCANCTX_PARAMS = set(inspect.signature(ScanContext).parameters.keys())
except Exception:
    _SCANCTX_PARAMS = {"targets", "rate_per_sec", "timeout"}
_SUPPORTS_RATE = "rate_per_sec" in _SCANCTX_PARAMS
_SUPPORTS_TIMEOUT = "timeout" in _SCANCTX_PARAMS

# ------------------------
# Settings discovery (module, object, or fallback)
# ------------------------
_settings_mod_or_obj: Any = None
for _imp in ((".", "settings"), ("api_scanner", "settings")):
    try:
        pkg, name = _imp
        if pkg == ".":
            _settings_mod_or_obj = __import__(__package__, fromlist=[name]).__dict__.get(name)
        else:
            _settings_mod_or_obj = __import__(pkg, fromlist=[name]).__dict__.get(name)
        if _settings_mod_or_obj is not None:
            break
    except Exception:
        continue

if _settings_mod_or_obj is None:
    class _FallbackSettings:
        rate_per_sec: float = 5.0
        timeout: float = 15.0
    _settings_mod_or_obj = _FallbackSettings()

def _resolve_setting(name: str, default: Any) -> Any:
    try:
        if hasattr(_settings_mod_or_obj, name):
            return getattr(_settings_mod_or_obj, name)
        for cand in ("settings", "config", "cfg"):
            inner = getattr(_settings_mod_or_obj, cand, None)
            if inner is not None and hasattr(inner, name):
                return getattr(inner, name)
        if isinstance(_settings_mod_or_obj, type) and hasattr(_settings_mod_or_obj, name):
            return getattr(_settings_mod_or_obj, name)
    except Exception:
        pass
    return default

DEFAULT_RATE = float(_resolve_setting("rate_per_sec", 5.0))
DEFAULT_TIMEOUT = float(_resolve_setting("timeout", 15.0))

# ------------------------
# Utilities
# ------------------------
def _load_json_file(p: Union[str, Path]) -> Any:
    p = Path(p).expanduser()
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def _normalize_headers(hdrs: Any) -> Dict[str, str]:
    if not hdrs:
        return {}
    if isinstance(hdrs, dict):
        return {str(k): "" if v is None else str(v) for k, v in hdrs.items()}
    if isinstance(hdrs, list):
        out: Dict[str, str] = {}
        for item in hdrs:
            if isinstance(item, dict) and item.get("key"):
                out[str(item["key"])] = "" if item.get("value") is None else str(item.get("value"))
        return out
    return {"_raw_headers": str(hdrs)}

def _extract_body(body: Any) -> Any:
    if not isinstance(body, dict):
        return body
    mode = body.get("mode")
    if mode == "raw":
        return body.get("raw")
    if mode == "urlencoded":
        params = body.get("urlencoded") or []
        return {p.get("key"): p.get("value") for p in params if isinstance(p, dict) and p.get("key") is not None}
    if mode == "formdata":
        params = body.get("formdata") or []
        return {p.get("key"): p.get("value") for p in params if isinstance(p, dict) and p.get("key") is not None}
    return body

def _url_from_postman_url(u: Any) -> Optional[str]:
    if isinstance(u, str):
        return u.strip() or None
    if not isinstance(u, dict):
        return None

    raw = u.get("raw")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()

    protocol = (u.get("protocol") or "").strip()
    host = u.get("host")
    path = u.get("path")
    query = u.get("query") or []

    if isinstance(host, list):
        host_str = ".".join([str(h) for h in host if h is not None])
    elif isinstance(host, str):
        host_str = host
    else:
        host_str = ""

    if isinstance(path, list):
        path_str = "/".join([str(p).lstrip("/") for p in path if p is not None])
    elif isinstance(path, str):
        path_str = path.lstrip("/")
    else:
        path_str = ""

    base = ""
    if protocol and host_str:
        base = f"{protocol}://{host_str}"
    elif host_str:
        base = f"http://{host_str}"

    if path_str:
        base = f"{base}/{path_str.lstrip('/')}"

    if isinstance(query, list):
        qd = {q.get("key"): q.get("value") for q in query if isinstance(q, dict) and q.get("key")}
        if qd:
            base = f"{base}?{urlencode(qd)}"
    return base or None

def _as_dict(obj: Any) -> Any:
    try:
        if dataclasses.is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, (list, tuple)):
            return [_as_dict(i) for i in obj]
        if isinstance(obj, dict):
            return {k: _as_dict(v) for k, v in obj.items()}
        return obj
    except Exception:
        return str(obj)

# ------------------------
# Lightweight embedded Postman parser
# ------------------------
_VAR_PATTERN = re.compile(r"{{\s*([A-Za-z0-9_.-]+)\s*}}")

def _subst_env(value: Any, env: Dict[str, str]) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            k = m.group(1)
            return env.get(k, m.group(0))
        return _VAR_PATTERN.sub(repl, value)
    if isinstance(value, list):
        return [_subst_env(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _subst_env(v, env) for k, v in value.items()}
    return value

class PostmanParser:
    def __init__(self, env: Optional[Dict[str, str]] = None):
        self.env = env or {}

    def load(self, path: Union[str, Path]) -> Dict[str, Any]:
        data = _load_json_file(path)
        if isinstance(data, dict) and "collection" in data and isinstance(data["collection"], dict):
            return data["collection"]
        if isinstance(data, dict):
            return data
        raise ValueError("Invalid Postman collection JSON structure.")

    def to_requests(self, collection: Dict[str, Any]) -> List[Dict[str, Any]]:
        items = collection.get("item") if isinstance(collection, dict) else None
        out: List[Dict[str, Any]] = []

        def walk(node_list: Any) -> None:
            if not isinstance(node_list, list):
                return
            for node in node_list:
                if not isinstance(node, dict):
                    continue
                if "item" in node and isinstance(node["item"], list):
                    walk(node["item"])
                req = node.get("request")
                if isinstance(req, dict):
                    method = req.get("method")
                    url_obj = req.get("url")
                    headers_obj = req.get("header") or req.get("headers")
                    body_obj = req.get("body")

                    url_obj = _subst_env(url_obj, self.env)
                    headers_obj = _subst_env(headers_obj, self.env)
                    body_obj = _subst_env(body_obj, self.env)

                    out.append(
                        {
                            "method": method,
                            "url": url_obj,
                            "headers": headers_obj,
                            "body": body_obj,
                        }
                    )

        walk(items)
        return out

# ------------------------
# Build Targets from parsed requests
# ------------------------
def _requests_to_targets(reqs: List[Any]) -> List[Target]:
    targets: List[Target] = []
    for r in reqs:
        method = getattr(r, "method", None) or (r.get("method") if isinstance(r, dict) else None)
        url_obj = getattr(r, "url", None) or (r.get("url") if isinstance(r, dict) else None)
        headers_obj = (
            getattr(r, "headers", None)
            or (r.get("headers") if isinstance(r, dict) else None)
            or (r.get("header") if isinstance(r, dict) else None)
        )
        body_obj = getattr(r, "body", None) or (r.get("body") if isinstance(r, dict) else None)

        url = _url_from_postman_url(url_obj)
        headers = _normalize_headers(headers_obj)
        body = _extract_body(body_obj)

        if not method or not url:
            continue

        targets.append(Target(method=str(method).upper(), url=url, headers=headers, body=body))
    return targets

# ------------------------
# Helpers to ensure attributes even if ctor didn't accept them
# ------------------------
def _ensure_attr(obj: Any, name: str, value: Any) -> None:
    """
    Ensure obj has attribute `name` readable by engine.
    Try instance assignment; if that fails (e.g., __slots__), set on class
    so attribute access (read) still works.
    """
    if getattr(obj, name, None) is not None:
        return
    try:
        setattr(obj, name, value)
        return
    except Exception:
        # fallback: class attribute
        try:
            setattr(type(obj), name, value)
        except Exception:
            pass  # last resort: engine will have to cope

# ------------------------
# CLI command
# ------------------------
def scan_postman(collection_path: Union[str, Path], env_file: Optional[Union[str, Path]], rate: Optional[float], timeout: Optional[float]) -> int:
    try:
        env = {}
        if env_file:
            raw_env = _load_json_file(env_file)
            if isinstance(raw_env, dict) and isinstance(raw_env.get("values"), list):
                env = {
                    str(it.get("key")): str(it.get("value"))
                    for it in raw_env["values"]
                    if isinstance(it, dict) and it.get("enabled", True) and it.get("key") is not None and it.get("value") is not None
                }
            elif isinstance(raw_env, dict):
                env = {str(k): str(v) for k, v in raw_env.items()}

        parser = PostmanParser(env=env)
        col = parser.load(Path(collection_path).expanduser())
        reqs = parser.to_requests(col)
        targets = _requests_to_targets(reqs)

        if not targets:
            print("No valid requests found in the Postman collection (nothing to scan).", file=sys.stderr)
            return 2

        # Build ScanContext kwargs strictly from supported params
        ctx_kwargs: Dict[str, Any] = {"targets": targets}
        if _SUPPORTS_RATE:
            ctx_kwargs["rate_per_sec"] = float(rate) if rate is not None else DEFAULT_RATE
        # Do NOT pass timeout if ctor doesn't support it

        ctx = ScanContext(**ctx_kwargs)

        # Ensure attributes are present even if ctor didn't accept them (engine might read them)
        eff_rate = float(rate) if rate is not None else DEFAULT_RATE
        eff_timeout = float(timeout) if timeout is not None else DEFAULT_TIMEOUT
        _ensure_attr(ctx, "rate_per_sec", eff_rate)
        _ensure_attr(ctx, "timeout", eff_timeout)

        result = asyncio.run(ScannerEngine(ctx).run())
        try:
            print(json.dumps(_as_dict(result), indent=2, default=str))
        except Exception:
            print(result)
        return 0

    except FileNotFoundError as e:
        print(f"File not found: {e}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"Invalid JSON file: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Aborted by user.", file=sys.stderr)
        return 130
    except Exception as e:
        print("An unexpected error occurred while scanning the Postman collection:", file=sys.stderr)
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        return 1

# ------------------------
# Argparse & entry points
# ------------------------
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="api-scan", description="Scan APIs from various sources")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan-postman", help="Scan a Postman collection JSON file")
    sp.add_argument("collection", help="Path to the Postman collection (JSON)")
    sp.add_argument("--env", help="Path to a Postman environment JSON (optional)")
    sp.add_argument("--rate", type=float, default=None, help=f"Requests per second (default: {DEFAULT_RATE})")
    sp.add_argument(
        "--timeout",
        type=float,
        default=None,
        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT}; may be injected as an attribute if ctor doesn't accept it)",
    )

    return p

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan-postman":
        return scan_postman(args.collection, args.env, args.rate, args.timeout)

    parser.print_help()
    return 2

def app() -> None:
    sys.exit(main())

if __name__ == "__main__":
    sys.exit(main())

