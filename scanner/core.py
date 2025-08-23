# scanner/core.py
import re
import json
import time
import gzip
import zlib
import math
import logging
import hashlib
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote_plus

import requests

log = logging.getLogger(__name__)

SAFE_MODE = True  # Avoids destructive tests. Toggle carefully.


# ------------------------- Models / Data -------------------------

@dataclass
class Vulnerability:
    type: str
    severity: str
    description: str
    endpoint: str
    method: str
    confidence: float = 0.6
    evidence: Optional[Dict[str, Any]] = None
    http_trace: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    priority: Optional[str] = None
    cvss: Optional[str] = None
    references: Optional[List[str]] = None
    ai_generated: Optional[bool] = False
    agentic: Optional[bool] = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VulnDBClient:
    """
    Pluggable interface to a local/offline 'vulnerability database'.
    You can point this to a local JSON/YAML with detection signatures (regexes, header smells, error messages).
    """
    def __init__(self, signatures_path: Optional[str] = None):
        self.signatures = {
            "db_errors": [
                r"SQL syntax.*MySQL",
                r"Warning: mysql_",
                r"valid PostgreSQL result",
                r"PostgreSQL.*ERROR",
                r"SQLite/JDBCDriver",
                r"SQLITE_ERROR",
                r"ORA-\d{5}",
                r"ODBC SQL Server Driver",
                r"Unclosed quotation mark after the character string",
                r"MongoError|E11000 duplicate key error",
            ],
            "xss_reflect_markers": [
                r"<xss[\-:]probe>", r"\"xss-probe\"", r"'xss-probe'",
            ],
            "sensitive_keywords": [
                "api_key", "access_token", "secret", "authorization", "password", "private_key"
            ],
            "open_redirect_params": ["redirect", "url", "next", "returnUrl", "callback", "dest"],
            "ssrf_params": ["url", "target", "callback", "image", "feed", "source"],
        }
        if signatures_path:
            try:
                if signatures_path.endswith(".json"):
                    with open(signatures_path, "r", encoding="utf-8") as f:
                        self.signatures.update(json.load(f))
                # (Add YAML support if you like)
                log.info(f"Loaded signatures from {signatures_path}")
            except Exception as e:
                log.warning(f"Failed loading signatures: {e}")

    def match_any(self, key: str, text: str) -> bool:
        for pat in self.signatures.get(key, []):
            if re.search(pat, text, re.I | re.M):
                return True
        return False


class ResponseMLClassifier:
    """
    Lightweight classifier:
      - Uses heuristics + optional ONNX/pkl model if present (plug in your fine-tuned model path).
      - Returns likelihood scores for categories (sqli_error, xss_reflect, sensitive_info, misconfig).
    """
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.model_path = model_path
        if model_path:
            try:
                # Example placeholder: load an ONNX / pickle model here
                # import onnxruntime as rt
                # self.session = rt.InferenceSession(model_path)
                pass
            except Exception as e:
                log.warning(f"ML model load failed: {e}")
                self.model = None

    def _heuristics(self, text: str) -> Dict[str, float]:
        t = text.lower()
        return {
            "sqli_error": 0.85 if any(x in t for x in ["sql syntax", "mysql", "postgresql", "sqlite", "odbc"]) else 0.05,
            "xss_reflect": 0.8 if "<xss" in t or "xss-probe" in t else 0.02,
            "sensitive_info": 0.6 if any(k in t for k in ["api_key", "access_token", "secret", "private key"]) else 0.05,
            "misconfig": 0.5 if "index of /" in t or "stack trace" in t or "whitelabel error page" in t else 0.05,
        }

    def score(self, text: str) -> Dict[str, float]:
        # If you wire a real model, use it here; else heuristics
        return self._heuristics(text or "")


class PayloadGenerator:
    """
    Generates safe probes. In SAFE_MODE we avoid destructive payloads.
    You can extend with LLMs or your fine-tuned models to craft adaptive payloads.
    """
    SQLI_SAFE = ["'", "\"", "')", "\";", " OR '1'='1", "') OR ('1'='1"]
    XSS_SAFE = ['<xss-probe>', '"xss-probe"', "'xss-probe'"]
    REDIRECTS = ["https://example.org", "//example.org"]
    SSRF_LOCAL = ["http://127.0.0.1:80", "http://[::1]:80", "file:///etc/hosts"] if not SAFE_MODE else ["http://127.0.0.1:80"]

    def __init__(self):
        pass

    def sqli(self) -> List[str]:
        return self.SQLI_SAFE

    def xss(self) -> List[str]:
        return self.XSS_SAFE

    def redirects(self) -> List[str]:
        return self.REDIRECTS

    def ssrf(self) -> List[str]:
        return self.SSRF_LOCAL


# ------------------------- Core Scanner -------------------------

class APISecurityScanner:
    """
    Core engine:
      - Baseline request
      - Targeted probes for common classes (SQLi/XSS/Open Redirect/CORS/InfoLeak)
      - Signature checks (VulnDBClient)
      - ML-assisted signal amplification (ResponseMLClassifier)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.session = requests.Session()
        self.timeout = int(self.config.get("timeout", 12))
        self.ml_enabled = bool(self.config.get("ml_enabled", True))
        self.classifier = ResponseMLClassifier(model_path=self.config.get("ml_model"))
        self.vdb = VulnDBClient(signatures_path=self.config.get("signatures_path"))
        self.payloads = PayloadGenerator()

    # --------- Public API expected by ScannerAdapter / Integrations ---------

    def scan_endpoint(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None) -> List[Vulnerability]:
        """
        High-level orchestrator. Returns a list of Vulnerability objects.
        """
        method = method.upper()
        headers = headers or {}
        data = data or {}
        vulns: List[Vulnerability] = []

        base_req, base_resp, base_body = self._http_request(url, method, headers, data)

        # CORS misconfig
        vulns += self._test_cors(url, method, headers, data)

        # Open Redirect
        vulns += self._test_open_redirect(url, method, headers, data)

        # XSS reflection (non-destructive)
        vulns += self._test_xss(url, method, headers, data)

        # SQLi error-based (non-destructive)
        vulns += self._test_sqli(url, method, headers, data)

        # Sensitive info exposure (content scan)
        vulns += self._test_sensitive_info(url, method, headers, data, base_body, base_resp)

        # Broken Auth (very conservative; relies on heuristics only)
        vulns += self._test_broken_auth(url, method, headers, data, base_resp, base_body)

        # SSRF (only signals potential; avoids exfil/destruction)
        vulns += self._test_ssrf(url, method, headers, data)

        return vulns

    # --------- HTTP & helpers ---------

    def _http_request(self, url: str, method: str, headers: Dict[str, str], data: Dict[str, Any]) -> Tuple[Dict, requests.Response, str]:
        req_info = {"url": url, "method": method, "headers": headers, "data": data}
        try:
            if method in ("GET", "DELETE"):
                resp = self.session.request(method, url, headers=headers, params=data if method == "GET" else None,
                                            timeout=self.timeout, allow_redirects=False)
            else:
                # Send JSON if body looks like JSON; else form
                if isinstance(data, dict):
                    resp = self.session.request(method, url, headers=headers, json=data,
                                                timeout=self.timeout, allow_redirects=False)
                else:
                    resp = self.session.request(method, url, headers=headers, data=data,
                                                timeout=self.timeout, allow_redirects=False)
        except Exception as e:
            # Return synthetic response object
            class R:  # minimal shim
                status_code = 0
                headers = {}
                content = b""
                text = ""
            resp = R()
            log.debug(f"Request error {method} {url}: {e}")

        body = self._read_body(resp)
        return req_info, resp, body

    def _read_body(self, resp: requests.Response) -> str:
        if not hasattr(resp, "headers"):
            return ""
        content = getattr(resp, "content", b"") or b""
        enc = (resp.headers or {}).get("Content-Encoding", "").lower()
        try:
            if "gzip" in enc:
                content = gzip.decompress(content)
            elif "deflate" in enc:
                content = zlib.decompress(content)
        except Exception:
            pass
        try:
            return (content.decode("utf-8", errors="ignore"))[:20000]
        except Exception:
            try:
                return (content.decode("latin-1", errors="ignore"))[:20000]
            except Exception:
                return ""

    def _clone_with_param(self, url: str, key: str, value: str) -> str:
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[key] = [value]
        new_q = urlencode({k: v[0] if isinstance(v, list) else v for k, v in q.items()}, doseq=False)
        return urlunparse(parsed._replace(query=new_q))

    # --------- Tests ---------

    def _test_cors(self, url, method, headers, data) -> List[Vulnerability]:
        # Send Origin and inspect ACAO/ACAC
        test_headers = dict(headers)
        test_headers["Origin"] = "https://evil.example"
        _, resp, _ = self._http_request(url, method, test_headers, data)
        h = {k.lower(): v for k, v in (getattr(resp, "headers", {}) or {}).items()}
        aco = h.get("access-control-allow-origin")
        acc = (h.get("access-control-allow-credentials") or "").lower()
        if aco:
            # '*' with credentials is high risk; reflected origin with credentials also high.
            if aco == "*" and acc == "true":
                return [Vulnerability(
                    type="CORS Misconfiguration",
                    severity="High",
                    description="ACAO '*' with credentials allowed.",
                    endpoint=url, method=method, confidence=0.9,
                    evidence={"ACAO": aco, "ACAC": acc},
                    tags=["cors"]
                )]
            if aco == "https://evil.example" and acc == "true":
                return [Vulnerability(
                    type="CORS Misconfiguration",
                    severity="High",
                    description="ACAO reflects arbitrary Origin and credentials allowed.",
                    endpoint=url, method=method, confidence=0.85,
                    evidence={"ACAO": aco, "ACAC": acc},
                    tags=["cors"]
                )]
        return []

    def _test_open_redirect(self, url, method, headers, data) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        # Scan for known redirect params
        keys = set(q.keys())
        for key in self.vdb.signatures.get("open_redirect_params", []):
            if key in keys:
                for candidate in self.payloads.redirects():
                    mutated = self._clone_with_param(url, key, candidate)
                    _, resp, _ = self._http_request(mutated, "GET", headers, {})
                    loc = (getattr(resp, "headers", {}) or {}).get("Location") or ""
                    if loc.startswith("http://") or loc.startswith("https://") or loc.startswith("//"):
                        if "example.org" in loc:
                            vulns.append(Vulnerability(
                                type="Open Redirect",
                                severity="Medium",
                                description=f"Parameter '{key}' appears to be an open redirect.",
                                endpoint=url, method=method, confidence=0.8,
                                evidence={"location": loc, "param": key},
                                tags=["redirect"]
                            ))
                            break
        return vulns

    def _test_xss(self, url, method, headers, data) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        # GET query reflection test
        if method == "GET":
            for marker in self.payloads.xss():
                mutated = self._clone_with_param(url, "q", marker)
                _, resp, body = self._http_request(mutated, "GET", headers, {})
                if self.vdb.match_any("xss_reflect_markers", body):
                    vulns.append(Vulnerability(
                        type="Reflected XSS (probe)",
                        severity="Medium",
                        description="Reflected payload detected in response (non-executable probe).",
                        endpoint=url, method=method, confidence=0.7,
                        evidence={"marker": marker},
                        tags=["xss"]
                    ))
                    break
        else:
            # JSON body probe if dict
            if isinstance(data, dict):
                marker = self.payloads.xss()[0]
                mdata = dict(data)
                mdata["_xss_probe"] = marker
                _, resp, body = self._http_request(url, method, headers, mdata)
                if self.vdb.match_any("xss_reflect_markers", body):
                    vulns.append(Vulnerability(
                        type="Reflected XSS (probe)",
                        severity="Medium",
                        description="JSON field reflection indicates potential XSS.",
                        endpoint=url, method=method, confidence=0.68,
                        evidence={"marker": marker},
                        tags=["xss"]
                    ))
        return vulns

    def _test_sqli(self, url, method, headers, data) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        # GET query params first
        if method == "GET":
            parsed = urlparse(url)
            q = parse_qs(parsed.query)
            for k in list(q.keys())[:6]:  # keep it light
                base_val = q[k][0] if isinstance(q[k], list) else q[k]
                for inj in self.payloads.sqli():
                    mutated = self._clone_with_param(url, k, f"{base_val}{inj}")
                    _, resp, body = self._http_request(mutated, "GET", headers, {})
                    if self.vdb.match_any("db_errors", body):
                        vulns.append(Vulnerability(
                            type="SQL Injection (error-based)",
                            severity="High",
                            description=f"Database error message after injecting into '{k}'.",
                            endpoint=url, method=method, confidence=0.85,
                            evidence={"param": k, "payload": inj},
                            tags=["sqli"]
                        ))
                        return vulns
        else:
            if isinstance(data, dict):
                for k, v in list(data.items())[:6]:
                    for inj in self.payloads.sqli():
                        mdata = dict(data); mdata[k] = f"{v}{inj}"
                        _, resp, body = self._http_request(url, method, headers, mdata)
                        if self.vdb.match_any("db_errors", body):
                            vulns.append(Vulnerability(
                                type="SQL Injection (error-based)",
                                severity="High",
                                description=f"Database error message after injecting into body field '{k}'.",
                                endpoint=url, method=method, confidence=0.85,
                                evidence={"field": k, "payload": inj},
                                tags=["sqli"]
                            ))
                            return vulns
        return vulns

    def _test_sensitive_info(self, url, method, headers, data, base_body, base_resp) -> List[Vulnerability]:
        # Heuristic + ML detection for secrets in body
        body = base_body or ""
        scores = self.classifier.score(body) if self.ml_enabled else {}
        if any(k in (body.lower()) for k in ["api_key", "access_token", "secret", "private key", "aws_access_key_id"]):
            return [Vulnerability(
                type="Sensitive Info Exposure",
                severity="High",
                description="Response appears to contain sensitive tokens/keys.",
                endpoint=url, method=method, confidence=max(0.7, scores.get("sensitive_info", 0.6)),
                evidence={"snippet": body[:400]},
                tags=["infoleak"]
            )]
        return []

    def _test_broken_auth(self, url, method, headers, data, base_resp, base_body) -> List[Vulnerability]:
        # If no auth header and 200 + user-identifying markers, flag as suspicious (low confidence).
        if not any(h.lower() == "authorization" for h in headers.keys()):
            code = getattr(base_resp, "status_code", 0)
            body = (base_body or "").lower()
            if code == 200 and any(k in body for k in ["email", "user_id", "set-cookie"]):
                return [Vulnerability(
                    type="Broken Authentication (heuristic)",
                    severity="Medium",
                    description="Endpoint returned user-related content without Authorization.",
                    endpoint=url, method=method, confidence=0.55,
                    evidence={"status": code, "markers": ["email/user_id/set-cookie"]},
                    tags=["auth"]
                )]
        return []

    def _test_ssrf(self, url, method, headers, data) -> List[Vulnerability]:
        # Only signals potential if SSRF-shaped parameters exist; does not attempt real exfil.
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        keys = set(q.keys())
        ssrf_keys = [k for k in self.vdb.signatures.get("ssrf_params", []) if k in keys]
        if ssrf_keys:
            return [Vulnerability(
                type="Potential SSRF",
                severity="Medium",
                description=f"Parameters {ssrf_keys} may be SSRF-prone. Manual review advised.",
                endpoint=url, method=method, confidence=0.5,
                evidence={"params": ssrf_keys},
                tags=["ssrf"]
            )]
        if isinstance(data, dict):
            keys = set(data.keys())
            ssrf_keys = [k for k in self.vdb.signatures.get("ssrf_params", []) if k in keys]
            if ssrf_keys:
                return [Vulnerability(
                    type="Potential SSRF",
                    severity="Medium",
                    description=f"Body fields {ssrf_keys} may be SSRF-prone. Manual review advised.",
                    endpoint=url, method=method, confidence=0.5,
                    evidence={"fields": ssrf_keys},
                    tags=["ssrf"]
                )]
        return []
Scanner = APISecurityScanner

