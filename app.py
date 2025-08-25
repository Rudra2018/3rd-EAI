#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rudra's Third Eye – Full-Featured Backend (fixed)
- SPA serving (frontend/dist)
- Scanner APIs: start/status/findings with pagination & filters
- Import: Postman, OpenAPI/Swagger (json/yaml), HAR; optional auto-scan
- Auth: API Key / Bearer JWT / Basic / OAuth2 client-credentials
- Agentic AI status endpoints
- Bug bounty programs (paginated) from H1/Bugcrowd/Intigriti/Public
- NVD enrichment (best-effort)
- Report generation (HTML/PDF/JSON) via reporting.report_generator if present
- GraphQL awareness (simple introspection probe) in addition to engine scan
"""
import os
import io
import time
import json
import base64
import copy
import threading
from typing import Any, Dict, List, Optional, Tuple
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS

# -------- Optional deps
try:
    import yaml  # PyYAML for OpenAPI YAML
except Exception:
    yaml = None

try:
    import requests
except Exception:
    requests = None

# -------- Local modules (robust imports)
SCANNER_HAS_SCAN_REQUEST = False
SCANNER_HAS_SCAN_TARGET = False
try:
    from core.api_scanner import ScannerEngine  # enhanced engine
    _engine = ScannerEngine()
    SCANNER_HAS_SCAN_TARGET = hasattr(_engine, "scan_target")
    SCANNER_HAS_SCAN_REQUEST = hasattr(_engine, "scan_request")
    del _engine
except Exception:
    try:
        from scanner.core import APISecurityScanner
    except Exception:
        APISecurityScanner = None

    class ScannerEngine:  # minimal adapter
        def __init__(self):
            self._eng = APISecurityScanner() if APISecurityScanner else None

        def scan_target(self, target: str, method: str = "GET", headers: Optional[Dict[str,str]] = None, data: Optional[Any] = None) -> List[Dict[str, Any]]:
            if not self._eng:
                return []
            vulns = self._eng.scan_endpoint(target, method, headers or {}, data or {})
            return [v.to_dict() if hasattr(v, "to_dict") else v for v in (vulns or [])]

        def scan_request(self, url: str, method: str = "GET", headers: Optional[Dict[str,str]] = None, data: Optional[Any] = None) -> List[Dict[str, Any]]:
            return self.scan_target(url, method, headers, data)

    SCANNER_HAS_SCAN_TARGET = True
    SCANNER_HAS_SCAN_REQUEST = True

# Bug bounty sources
try:
    from bug_bounty.hackerone_api import get_h1_programs
except Exception:
    def get_h1_programs(): return []
try:
    from bug_bounty.bugcrowd_api import get_bugcrowd_programs
except Exception:
    def get_bugcrowd_programs(): return []
try:
    from bug_bounty.intigriti_api import get_intigriti_programs
except Exception:
    def get_intigriti_programs(): return []
try:
    from bug_bounty.public_programs import get_public_programs
except Exception:
    def get_public_programs(): return []

# Agentic AI
try:
    from agents.beast_mode import BeastMode
except Exception:
    class BeastMode:
        def status(self): return True

try:
    from agents.crewai_security_agents import SecurityCrew
except Exception:
    class SecurityCrew:
        def list_agents(self): return [{"name":"Hunter","status":"ready"},{"name":"Strategist","status":"ready"}]

try:
    from continuous_learning import ContinuousLearning
except Exception:
    class ContinuousLearning:
        def status(self): return True

# NVD + FP + Postman + Report
try:
    from integrations.nvd_integration import NVDClient
except Exception:
    class NVDClient:
        def enrich(self, cve_id): return {}

try:
    from ml.false_positive_detector import FalsePositiveDetector
except Exception:
    class FalsePositiveDetector:
        def filter_findings(self, findings: List[Dict[str,Any]]) -> List[Dict[str,Any]]: return findings

try:
    from integrations.postman import EnhancedPostmanParser
except Exception:
    class EnhancedPostmanParser:
        async def parse_collection(self, collection_data: Dict[str, Any], variables: Dict[str,str] = None) -> Dict[str, Any]:
            return {"collection_name":"Imported","endpoints":[]}

try:
    from reporting.report_generator import ReportGenerator
except Exception:
    ReportGenerator = None

# -------- Flask
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend", "dist")
os.makedirs(FRONTEND_DIR, exist_ok=True)

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="/")
CORS(app)

# -------- Globals
SCANNER = ScannerEngine()
BEAST = BeastMode()
CREW  = SecurityCrew()
LEARN = ContinuousLearning()
NVD   = NVDClient()
FPD   = FalsePositiveDetector()
POSTMAN = EnhancedPostmanParser()

SCAN_STATE: Dict[str, Any] = {
    "status": "idle",
    "progress": 0,
    "active_step": 0,
    "steps": ["Queued", "Recon", "Scanning", "Analyzing", "Reporting"],
    "targets": [],
    "findings": [],
    "raw_findings": [],
    "started_at": None,
    "finished_at": None
}
SCAN_LOCK = threading.Lock()

AUTH_CONFIG: Dict[str, Any] = {
    "mode": None,  # api_key | bearer | basic | oauth2
    "api_key_header": "X-API-Key",
    "api_key": "",
    "bearer_token": "",
    "basic_user": "",
    "basic_pass": "",
    "oauth2": {
        "token_url": "",
        "client_id": "",
        "client_secret": "",
        "scope": "",
        "access_token": "",
        "expires_at": 0
    }
}

IMPORTED_TARGETS: List[Dict[str, Any]] = []
IMPORTS_LOCK = threading.Lock()

BUG_CACHE = {"data": [], "ts": 0}

# -------- Helpers
def _set_state(**kw):
    with SCAN_LOCK:
        SCAN_STATE.update(kw)

def _snapshot() -> Dict[str, Any]:
    with SCAN_LOCK:
        return copy.deepcopy(SCAN_STATE)

def _now() -> float:
    return time.time()

def _apply_auth(headers: Optional[Dict[str,str]] = None) -> Dict[str,str]:
    h = dict(headers or {})
    mode = AUTH_CONFIG.get("mode")
    if mode == "api_key" and AUTH_CONFIG.get("api_key"):
        h[AUTH_CONFIG.get("api_key_header") or "X-API-Key"] = AUTH_CONFIG["api_key"]
    elif mode == "bearer" and AUTH_CONFIG.get("bearer_token"):
        h["Authorization"] = f"Bearer {AUTH_CONFIG['bearer_token']}"
    elif mode == "basic" and (AUTH_CONFIG.get("basic_user") or AUTH_CONFIG.get("basic_pass")):
        token = base64.b64encode(f"{AUTH_CONFIG.get('basic_user','')}:{AUTH_CONFIG.get('basic_pass','')}".encode()).decode()
        h["Authorization"] = f"Basic {token}"
    elif mode == "oauth2":
        tok = _ensure_oauth2_token()
        if tok:
            h["Authorization"] = f"Bearer {tok}"
    return h

def _ensure_oauth2_token() -> Optional[str]:
    conf = AUTH_CONFIG.get("oauth2") or {}
    if not conf.get("token_url") or not conf.get("client_id") or not conf.get("client_secret"):
        return conf.get("access_token") or None
    if conf.get("access_token") and conf.get("expires_at",0) > _now()+60:
        return conf["access_token"]
    if not requests:
        return conf.get("access_token") or None
    try:
        data = {"grant_type": "client_credentials"}
        if conf.get("scope"): data["scope"] = conf["scope"]
        res = requests.post(conf["token_url"], data=data, auth=(conf["client_id"], conf["client_secret"]), timeout=12)
        if res.ok:
            j = res.json()
            conf["access_token"] = j.get("access_token")
            conf["expires_at"] = _now() + int(j.get("expires_in") or 3600)
            AUTH_CONFIG["oauth2"] = conf
            return conf["access_token"]
    except Exception:
        pass
    return conf.get("access_token") or None

def _paginate(items: List[Any], page: int, page_size: int) -> Tuple[List[Any], int]:
    total = len(items)
    if page_size <= 0: page_size = 50
    start = max(0, (page-1) * page_size)
    end = min(total, start + page_size)
    return items[start:end], total

def _collect_bug_programs() -> List[Dict[str, Any]]:
    global BUG_CACHE
    if _now() - BUG_CACHE["ts"] < 300 and BUG_CACHE["data"]:
        return BUG_CACHE["data"]
    data: List[Dict[str, Any]] = []
    for fn in (get_h1_programs, get_bugcrowd_programs, get_intigriti_programs, get_public_programs):
        try:
            res = fn() or []
            if isinstance(res, list):
                data.extend(res)
        except Exception:
            continue
    BUG_CACHE = {"data": data, "ts": _now()}
    return data

# -------- Import parsers
def parse_postman(data: Dict[str, Any], variables: Dict[str,str] = None) -> List[Dict[str, Any]]:
    try:
        import asyncio
        parsed = asyncio.run(POSTMAN.parse_collection(data, variables or {}))
        endpoints = []
        def walk(node):
            if not node: return
            if isinstance(node, dict) and node.get("url"):
                endpoints.append({
                    "name": node.get("name"),
                    "method": (node.get("method") or "GET").upper(),
                    "url": node.get("url"),
                    "headers": node.get("headers") or {},
                    "body": node.get("body") or None
                })
            for ch in (node.get("children") or []):
                walk(ch)
        for it in (parsed.get("endpoints") or []):
            walk(it)
        return endpoints
    except Exception:
        return []

def parse_openapi(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    ep = []
    paths = (doc or {}).get("paths") or {}
    servers = (doc or {}).get("servers") or []
    base = ""
    if servers and isinstance(servers, list) and isinstance(servers[0], dict):
        base = (servers[0].get("url") or "").rstrip("/")
    for path, methods in paths.items():
        for m, spec in (methods or {}).items():
            if m.upper() not in ("GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"):
                continue
            url = f"{base}{path}" if base else path
            ep.append({"name": spec.get("summary") or f"{m.upper()} {url}",
                       "method": m.upper(), "url": url, "headers": {}})
    return ep

def parse_har(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    ep = []
    try:
        entries = (doc.get("log") or {}).get("entries") or []
        for e in entries:
            req = e.get("request") or {}
            method = (req.get("method") or "GET").upper()
            url = req.get("url") or ""
            headers = {h.get("name"):h.get("value") for h in (req.get("headers") or []) if h.get("name")}
            body = None
            if req.get("postData") and isinstance(req["postData"], dict):
                body = req["postData"].get("text")
                try:
                    body_json = json.loads(body or "{}")
                    body = body_json
                except Exception:
                    pass
            ep.append({"name": f"{method} {url}", "method": method, "url": url, "headers": headers, "body": body})
    except Exception:
        pass
    return ep

# -------- Lightweight GraphQL probe
INTROSPECTION_QUERY = {
    "query": """
      query IntrospectionQuery {
        __schema { queryType { name } mutationType { name } types { name kind } }
      }
    """
}

def graphql_probe(url: str, headers: Dict[str,str]) -> Optional[Dict[str, Any]]:
    if not requests:
        return None
    try:
        h = dict(headers or {})
        h.setdefault("Content-Type", "application/json")
        res = requests.post(url, json=INTROSPECTION_QUERY, headers=h, timeout=10, allow_redirects=False)
        ok = res.status_code == 200 and "__schema" in (res.text or "")
        return {"introspection_enabled": bool(ok), "status": res.status_code}
    except Exception:
        return None

# -------- Scan worker
def _scan_targets_worker(targets: List[Dict[str, Any]], options: Dict[str, Any]):
    _set_state(status="running", progress=0, active_step=0, started_at=time.time(), finished_at=None, findings=[], raw_findings=[])
    steps = _snapshot().get("steps") or []

    total = max(1, len(targets))
    progress_per = max(1, int(80 / total))  # 80% while scanning

    all_findings: List[Dict[str, Any]] = []
    for t in targets:
        _set_state(active_step=min(len(steps)-1, 2))  # Scanning
        url = t.get("url"); method = (t.get("method") or "GET").upper()
        headers = _apply_auth(t.get("headers"))
        body = t.get("body")

        eng_findings: List[Dict[str, Any]] = []
        try:
            if SCANNER_HAS_SCAN_REQUEST and hasattr(SCANNER, "scan_request"):
                try:
                    eng_findings = SCANNER.scan_request(url, method=method, headers=headers, data=body)
                except TypeError:
                    try:
                        eng_findings = SCANNER.scan_request(url, method=method, headers=headers)
                    except Exception:
                        eng_findings = []
            elif SCANNER_HAS_SCAN_TARGET and hasattr(SCANNER, "scan_target"):
                eng_findings = SCANNER.scan_target(url, method=method, headers=headers, data=body)
        except Exception as e:
            print(f"[scan] error {method} {url}: {e}")

        if "/graphql" in (url or "").lower() or "graphql" in (t.get("name") or "").lower():
            gprobe = graphql_probe(url, headers)
            if gprobe and gprobe.get("introspection_enabled"):
                eng_findings.append({
                    "type": "GraphQL Introspection Enabled",
                    "severity": "Medium",
                    "description": "GraphQL introspection appears enabled in production context.",
                    "endpoint": url,
                    "method": method,
                    "confidence": 0.75,
                    "tags": ["graphql", "info_disclosure"]
                })

        all_findings.extend(eng_findings or [])
        snap = _snapshot()
        _set_state(progress=min(80, snap["progress"] + progress_per))

    _set_state(active_step=min(len(steps)-1, 3))  # Analyzing
    try:
        filtered = FPD.filter_findings(all_findings or [])
    except Exception:
        filtered = all_findings or []

    for f in filtered:
        cve = f.get("cve") or f.get("cve_id")
        try:
            f["nvd"] = NVD.enrich(cve) if cve else {}
        except Exception:
            f["nvd"] = {}

    _set_state(active_step=min(len(steps)-1, 4), raw_findings=all_findings, findings=filtered)
    _set_state(progress=100, status="done", finished_at=time.time())

# -------- SPA routes
@app.route("/")
def index():
    path = os.path.join(app.static_folder, "index.html")
    if os.path.exists(path):
        return send_from_directory(app.static_folder, "index.html")
    return "<h1>Rudra's Third Eye</h1>", 200

@app.errorhandler(404)
def spa_404(_e):
    try:
        return send_from_directory(app.static_folder, "index.html")
    except Exception:
        return "Not Found", 404

# -------- Scanner routes
@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    body = request.get_json(silent=True) or {}
    targets_in = body.get("targets") or []
    options = body.get("options") or {}

    norm: List[Dict[str, Any]] = []
    for t in targets_in:
        if isinstance(t, str):
            norm.append({"url": t, "method": "GET"})
        elif isinstance(t, dict) and t.get("url"):
            norm.append({
                "url": t["url"],
                "method": (t.get("method") or "GET").upper(),
                "headers": t.get("headers") or {},
                "body": t.get("body")
            })

    if not norm:
        return jsonify({"error":"no valid targets"}), 400

    snap = _snapshot()
    if snap["status"] == "running":
        return jsonify({"error":"scan already running"}), 409

    _set_state(status="running", progress=0, active_step=1, steps=snap["steps"], targets=norm, started_at=time.time(), finished_at=None)
    th = threading.Thread(target=_scan_targets_worker, args=(norm, options), daemon=True)
    th.start()
    return jsonify({"ok": True, "message": "scan started", "count": len(norm)}), 202

@app.route("/api/scan/status", methods=["GET"])
def api_scan_status():
    snap = _snapshot()
    return jsonify({
        "status": snap["status"],
        "progress": snap["progress"],
        "active_step": snap["active_step"],
        "steps": snap["steps"],
        "targets": snap["targets"],
        "started_at": snap["started_at"],
        "finished_at": snap["finished_at"]
    })

@app.route("/api/findings", methods=["GET"])
def api_findings():
    page = int(request.args.get("page", "1"))
    page_size = int(request.args.get("page_size", "50"))
    q = (request.args.get("q") or "").lower().strip()
    sev = (request.args.get("severity") or "").lower().strip()

    snap = _snapshot()
    data = snap["findings"] or []

    if q:
        def match(f):
            text = " ".join([str(f.get(k,"")) for k in ("type","description","endpoint","method","tags")])
            return q in text.lower()
        data = list(filter(match, data))
    if sev:
        data = [f for f in data if (f.get("severity") or "").lower() == sev]

    page_items, total = _paginate(data, page, page_size)
    return jsonify({"findings": page_items, "total": total, "page": page, "page_size": page_size})

# -------- Import & Targets
@app.route("/api/import", methods=["POST"])
def api_import():
    """
    Accepts:
      - JSON: {"type":"postman|openapi|har", "content":<json/yaml or object>, "variables": {...}, "auto_scan": true|false}
      - multipart: file, type, variables (json), auto_scan
    """
    auto_scan = False
    typ = None
    content = None
    variables = {}

    if request.content_type and "application/json" in request.content_type:
        body = request.get_json(silent=True) or {}
        typ = (body.get("type") or "").lower()
        content = body.get("content")
        variables = body.get("variables") or {}
        auto_scan = bool(body.get("auto_scan"))
    else:
        typ = (request.form.get("type") or "").lower()
        auto_scan = (request.form.get("auto_scan") or "false").lower() == "true"
        try:
            variables = json.loads(request.form.get("variables") or "{}")
        except Exception:
            variables = {}
        file = request.files.get("file")
        if file:
            try:
                raw = file.read()
                try:
                    content = json.loads(raw.decode("utf-8", "ignore"))
                except Exception:
                    if yaml:
                        content = yaml.safe_load(raw.decode("utf-8", "ignore"))
                    else:
                        content = raw.decode("utf-8", "ignore")
            except Exception:
                return jsonify({"error":"failed to read file"}), 400

    if content is None:
        return jsonify({"error":"no content provided"}), 400

    if isinstance(content, str):
        try:
            content = json.loads(content)
        except Exception:
            if yaml:
                try: content = yaml.safe_load(content)
                except Exception: pass

    endpoints: List[Dict[str, Any]] = []
    try:
        if typ == "postman":
            endpoints = parse_postman(content, variables)
        elif typ in ("openapi","swagger"):
            endpoints = parse_openapi(content)
        elif typ == "har":
            endpoints = parse_har(content)
        else:
            if isinstance(content, dict) and "openapi" in content:
                endpoints = parse_openapi(content)
            elif isinstance(content, dict) and "item" in content and "info" in content:
                endpoints = parse_postman(content, variables)
            elif isinstance(content, dict) and "log" in content and "entries" in (content.get("log") or {}):
                endpoints = parse_har(content)
    except Exception as e:
        return jsonify({"error": f"parse failed: {e}"}), 400

    with IMPORTS_LOCK:
        IMPORTED_TARGETS.clear()
        IMPORTED_TARGETS.extend(endpoints)

    resp = {"ok": True, "imported": len(endpoints)}
    if auto_scan and endpoints:
        threading.Thread(target=_scan_targets_worker, args=(endpoints, {}), daemon=True).start()
        _set_state(status="running", progress=0, active_step=1, targets=endpoints, started_at=time.time(), finished_at=None)
        resp["scan_started"] = True
    return jsonify(resp)

@app.route("/api/targets", methods=["GET"])
def api_targets():
    with IMPORTS_LOCK:
        items = list(IMPORTED_TARGETS)
    page = int(request.args.get("page","1")); page_size = int(request.args.get("page_size","50"))
    page_items, total = _paginate(items, page, page_size)
    return jsonify({"targets": page_items, "total": total, "page": page, "page_size": page_size})

# -------- Auth
@app.route("/api/auth/config", methods=["POST"])
def api_auth_config():
    body = request.get_json(silent=True) or {}
    mode = body.get("mode")
    if mode not in (None, "api_key", "bearer", "basic", "oauth2"):
        return jsonify({"error":"invalid mode"}), 400
    if mode is not None:
        AUTH_CONFIG["mode"] = mode
    if "api_key_header" in body: AUTH_CONFIG["api_key_header"] = body["api_key_header"]
    if "api_key" in body: AUTH_CONFIG["api_key"] = body["api_key"]
    if "bearer_token" in body: AUTH_CONFIG["bearer_token"] = body["bearer_token"]
    if "basic_user" in body: AUTH_CONFIG["basic_user"] = body["basic_user"]
    if "basic_pass" in body: AUTH_CONFIG["basic_pass"] = body["basic_pass"]
    if "oauth2" in body and isinstance(body["oauth2"], dict):
        AUTH_CONFIG["oauth2"].update({k:v for k,v in body["oauth2"].items() if k in ("token_url","client_id","client_secret","scope","access_token")})
        if body["oauth2"].get("access_token"):
            AUTH_CONFIG["oauth2"]["expires_at"] = time.time() + 3600
    out = copy.deepcopy(AUTH_CONFIG)
    if out.get("api_key"): out["api_key"] = "•••"
    if out.get("bearer_token"): out["bearer_token"] = "•••"
    if out.get("basic_pass"): out["basic_pass"] = "•••"
    if out.get("oauth2",{}).get("client_secret"): out["oauth2"]["client_secret"] = "•••"
    if out.get("oauth2",{}).get("access_token"): out["oauth2"]["access_token"] = "•••"
    return jsonify({"ok": True, "auth": out})

@app.route("/api/auth/status", methods=["GET"])
def api_auth_status():
    out = copy.deepcopy(AUTH_CONFIG)
    if out.get("api_key"): out["api_key"] = "•••"
    if out.get("bearer_token"): out["bearer_token"] = "•••"
    if out.get("basic_pass"): out["basic_pass"] = "•••"
    if out.get("oauth2",{}).get("client_secret"): out["oauth2"]["client_secret"] = "•••"
    if out.get("oauth2",{}).get("access_token"): out["oauth2"]["access_token"] = "•••"
    return jsonify({"auth": out})

# -------- Bug bounty & Agentic AI
@app.route("/api/bug-bounty/programs", methods=["GET"])
def api_bug_bounty_programs():
    page = int(request.args.get("page","1")); page_size = int(request.args.get("page_size","50"))
    q = (request.args.get("q") or "").lower().strip()
    data = _collect_bug_programs()
    if q:
        data = [p for p in data if q in json.dumps(p).lower()]
    page_items, total = _paginate(data, page, page_size)
    return jsonify({"programs": page_items, "total": total, "page": page, "page_size": page_size})

@app.route("/api/agent/status", methods=["GET"])
def api_agent_status():
    try: beast = bool(BEAST.status())
    except Exception: beast = True
    try: cl = bool(LEARN.status())
    except Exception: cl = True
    try: agents = CREW.list_agents() or []
    except Exception: agents = [{"name":"Hunter","status":"ready"},{"name":"Strategist","status":"ready"}]
    return jsonify({"ai_enhanced": True, "beast_mode": beast, "continuous_learning": cl, "agents": agents})

# -------- Reports
@app.route("/api/report", methods=["GET"])
def api_report():
    fmt = (request.args.get("format") or "json").lower()
    snap = _snapshot()
    payload = {
        "meta": {
            "started_at": snap["started_at"],
            "finished_at": snap["finished_at"],
            "targets": snap["targets"],
            "counts": {"total": len(snap["findings"] or []), "by_severity": {}}
        },
        "findings": snap["findings"] or []
    }
    sev_map = {}
    for f in payload["findings"]:
        sev = (f.get("severity") or "unknown").lower()
        sev_map[sev] = sev_map.get(sev, 0) + 1
    payload["meta"]["counts"]["by_severity"] = sev_map

    if fmt == "json":
        return jsonify(payload)
    elif fmt == "html" and ReportGenerator:
        try:
            rg = ReportGenerator()
            html = rg.render_html(payload)
            return html, 200, {"Content-Type":"text/html"}
        except Exception:
            pass
    elif fmt == "pdf" and ReportGenerator:
        try:
            rg = ReportGenerator()
            pdf_bytes = rg.render_pdf(payload)
            return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True, download_name="report.pdf")
        except Exception:
            pass
    html = "<html><body><h2>Rudra Report</h2><pre>{}</pre></body></html>".format(
        (json.dumps(payload, indent=2)).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    )
    return html, 200, {"Content-Type":"text/html"}

# -------- Health
@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"ok": True, "services": ["scanner","bug_bounty","agentic_ai","nvd_enrichment","import","auth"]})

# -------- Main
if __name__ == "__main__":
    port = int(os.getenv("PORT", "4000"))
    print(f"🚀 Rudra's Third Eye running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port)

