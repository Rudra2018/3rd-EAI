# app.py
import os, uuid, threading, json, re, logging
from datetime import datetime
from urllib.parse import urljoin

import requests
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, join_room

# --- Internal modules you already have in your repo ---
from ai_test_generator import AITestCaseGenerator
from scanner.core import APISecurityScanner
from scanner.adapter import ScannerAdapter
from integrations.postman import PostmanIntegration  # uses EnhancedPostmanParser internally
from doc_parsers.pdf_api_parser import build_postman_collection_from_pdf
from agents.beast_mode import run_beast_mode
from report_generator import ComprehensiveReportGenerator

PRODUCT_NAME = "Rudra's Third Eye (AI)"

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Trim noisy pool warnings (root cause is also fixed by pooled session in ScannerAdapter)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
logging.getLogger("engineio").setLevel(logging.WARNING)
logging.getLogger("socketio").setLevel(logging.WARNING)

# ---------- Frontend (Dashboard) discovery ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIST = os.path.join(BASE_DIR, "frontend", "dist")
SERVE_BUILD = os.path.isdir(FRONTEND_DIST) and os.path.isfile(os.path.join(FRONTEND_DIST, "index.html"))

# Serve the built dashboard if present
if SERVE_BUILD:
    app = Flask(__name__, static_folder=FRONTEND_DIST, static_url_path="/")
else:
    app = Flask(__name__)

CORS(app)

# Socket.IO: stable ping settings, no engineio noisy logs
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    ping_timeout=30,
    ping_interval=12,
    max_http_buffer_size=10_000_000,
    engineio_logger=False,
    logger=False,
)

# ---------- Storage / paths ----------
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["REPORTS_FOLDER"] = "reports"
for f in [app.config["UPLOAD_FOLDER"], app.config["REPORTS_FOLDER"]]:
    os.makedirs(f, exist_ok=True)

scan_results = {}
active_scans = {}

# ---------- Helpers ----------
def _emit(scan_id, event, payload):
    payload = dict(payload or {}); payload["scan_id"] = scan_id
    socketio.emit(event, payload)
    msg = payload.get("message")
    logger.info(f"SOCKET[{event}] {msg if msg else ''}")

def _safe_load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _load_postman_variables(env_json_path):
    if not env_json_path or not os.path.exists(env_json_path):
        return {}
    try:
        data = _safe_load_json(env_json_path)
        # Postman env (values list) or simple dict
        if isinstance(data, dict) and isinstance(data.get("values"), list):
            return {str(it.get("key")): str(it.get("value")) for it in data["values"] if it.get("key") is not None}
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception as e:
        logger.warning(f"Failed parsing variables file: {e}")
    return {}

def _safe_get(url, timeout=6):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": PRODUCT_NAME})
    except Exception:
        return None

# ---------- Recon to collection (OpenAPI -> minimal Postman) ----------
COMMON_OPENAPI_PATHS = [
    "/openapi.json","/openapi.yaml","/swagger.json","/swagger.yaml",
    "/v3/api-docs","/api-docs","/v3/api-docs.yaml","/v3/api-docs.json","/api-docs.json"
]

def try_fetch_openapi(target_base):
    base = target_base.rstrip("/")
    for path in COMMON_OPENAPI_PATHS:
        url = base + path
        r = _safe_get(url)
        if r and r.status_code == 200 and "json" in (r.headers.get("content-type","").lower()):
            try:
                return r.json(), url
            except Exception:
                continue
    return None, None

def openapi_to_simple_postman(spec, base_url):
    paths = spec.get("paths") or {}
    items = []
    for pth, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            m = str(method).upper()
            if m not in ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]:
                continue
            url = urljoin(base_url.rstrip("/") + "/", str(pth).lstrip("/"))
            name = (op or {}).get("summary") or f"{m} {pth}"
            items.append({"name": name, "request": {"method": m, "url": url, "header": []}})
    if not items:
        return None
    return {
        "info":{"name":f"{PRODUCT_NAME} (Recon Collection)","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item":items
    }

# If user removed build_minimal_postman_from_endpoints from integrations.postman, we keep a local one:
SEED_ENDPOINTS = ["/","/health","/status","/api/health","/api/status","/v1/auth/login","/v1/users/me","/graphql"]

def build_minimal_postman_from_endpoints(endpoints):
    items = []
    for ep in endpoints or []:
        items.append({
            "name": ep.get("name") or f"{ep.get('method','GET')} {ep.get('url')}",
            "request": {
                "method": ep.get("method","GET"),
                "url": ep.get("url"),
                "header": [{"key":"Accept","value":"*/*"}],
            }
        })
    return {
        "info":{"name":f"{PRODUCT_NAME} (Seed Collection)","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items
    }

def build_collection_from_seed(base_url):
    base = base_url.rstrip("/")
    eps = []
    for p in SEED_ENDPOINTS:
        eps.append({"method":"GET","url":base+p,"name":f"GET {p}"})
        if p in ("/v1/auth/login","/graphql"):
            eps.append({"method":"POST","url":base+p,"name":f"POST {p}"})
    return build_minimal_postman_from_endpoints(eps)

def recon_to_collection(target_url, upload_dir):
    spec, where = try_fetch_openapi(target_url)
    if spec:
        logger.info(f"OpenAPI discovered at {where}")
        col = openapi_to_simple_postman(spec, target_url) or build_collection_from_seed(target_url)
    else:
        logger.info("No OpenAPI found, using seeded endpoints.")
        col = build_collection_from_seed(target_url)
    out = os.path.join(upload_dir, f"{uuid.uuid4()}_recon_collection.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(col, f, indent=2)
    return out

# ---------- Anti-FP & scoring helpers (lightweight) ----------
def verify_broken_auth(v):
    t = (v.get("type") or "").lower()
    if t not in ["broken authentication","broken auth","auth bypass","idor","bola/idor"]:
        return v, True
    trace = v.get("http_trace") or {}
    unauth = trace.get("unauth") or {}
    auth = trace.get("auth") or {}
    unauth_status = unauth.get("status_code")
    loc = (unauth.get("headers") or {}).get("Location") or (unauth.get("headers") or {}).get("location")
    # 302->login means NOT broken auth
    if unauth_status in (301,302,303,307,308):
        if loc and re.search(r"login|signin|auth", str(loc), re.I):
            return v, False
    # 200->compare body markers
    if unauth_status == 200 and auth.get("status_code") == 200:
        unauth_body = (unauth.get("body") or "")[:400]
        markers = ["token","authorization","set-cookie","email","user_id"]
        if not any(m in str(unauth_body).lower() for m in markers):
            v["adjusted_confidence"] = min(0.4, float(v.get("confidence", 0.5)))
            v["note"] = "Unauth 200 but no sensitive markers; downgraded."
    return v, True

def normalize_cors(v):
    if (v.get("type") or "").lower() not in ["cors misconfiguration","cors"]:
        return v
    headers = (v.get("evidence") or {}).get("response_headers") or v.get("headers") or {}
    aco = headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin")
    acc = headers.get("Access-Control-Allow-Credentials") or headers.get("access-control-allow-credentials")
    method = (v.get("method") or "GET").upper()
    sev = v.get("severity","Medium")
    if aco == "*" and str(acc).lower() == "true":
        sev = "High"
    elif isinstance(aco, str) and "http" in aco.lower() and str(acc).lower() == "true":
        sev = "High"
    else:
        sev = "Medium" if method in ("POST","PUT","PATCH","DELETE") else "Low"
    v["severity"] = sev
    return v

VRT_PRIOR = {
    "sql injection":"P1","command injection":"P1","rce":"P1",
    "idor":"P2","bola/idor":"P2","broken authentication":"P2","auth bypass":"P2","ssrf":"P2","xxe":"P2","sensitive data exposure":"P2",
    "xss":"P3","cors misconfiguration":"P3","open redirect":"P3","csrf":"P3"
}
def assign_priority(v):
    key = (v.get("type") or "").lower()
    p = VRT_PRIOR.get(key)
    if not p:
        sev = (v.get("severity") or "").lower()
        p = "P1" if sev=="critical" else "P2" if sev=="high" else "P3" if sev=="medium" else "P4"
    v["priority"] = p
    return v

def post_verify_and_score(vulns):
    out = []
    for v in vulns or []:
        if not isinstance(v, dict) and hasattr(v, "to_dict"):
            v = v.to_dict()
        v = normalize_cors(v)
        v, ok = verify_broken_auth(v)
        if not ok:
            continue
        v = assign_priority(v)
        out.append(v)
    return out

def summarize_findings(vlist, tests, analysis):
    sev_counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
    p_counts = {"P1":0,"P2":0,"P3":0,"P4":0}
    for v in vlist:
        sev = v.get("severity")
        if sev in sev_counts: sev_counts[sev] += 1
        p = v.get("priority","P4")
        if p in p_counts: p_counts[p] += 1
    return {
        "total": len(vlist),
        "critical": sev_counts["Critical"], "high": sev_counts["High"],
        "medium": sev_counts["Medium"], "low": sev_counts["Low"],
        "p1": p_counts["P1"], "p2": p_counts["P2"], "p3": p_counts["P3"],
        "ai_generated": len([v for v in vlist if v.get("ai_generated")]),
        "agentic": len([v for v in vlist if v.get("agentic")]),
        "test_cases_executed": len(tests or []),
        "endpoints_analyzed": len((analysis or {}).get("endpoints") or []),
    }

# ---------- Socket handlers ----------
@socketio.on("connect")
def _on_c():
    logger.debug("Client connected")

@socketio.on("disconnect")
def _on_d():
    logger.debug("Client disconnected")

@socketio.on("join_scan")
def _on_j(data):
    sid = (data or {}).get("scan_id") or (data or {}).get("scan_id".lower()) or (data or {}).get("scan_id".upper())
    # frontend sends { scan_id: ... }
    sid = (data or {}).get("scan_id") or (data or {}).get("scanId")
    if sid:
        join_room(sid)
        logger.info(f"Client joined room for scan {sid}")

# ---------- API ----------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "product": PRODUCT_NAME, "time": datetime.now().isoformat()})

@app.route("/api/scan/postman-ai", methods=["POST"])
def scan_postman_ai():
    try:
        file = request.files.get("collection")
        variables_file = request.files.get("variables")
        pdf_doc = request.files.get("api_doc_pdf")
        target_url = (request.form.get("target_url") or "").strip()

        ai_enabled = (request.form.get("ai_enabled","true").lower() == "true")
        ml_enabled = (request.form.get("ml_enabled","true").lower() == "true")
        bug_bounty = (request.form.get("bug_bounty","true").lower() == "true")
        beast_mode = (request.form.get("beast_mode","true").lower() == "true") if bug_bounty else False
        selected_folders = request.form.get("folders")
        selected_folders = selected_folders.split(",") if selected_folders else None

        scan_id = str(uuid.uuid4())
        scan_results[scan_id] = {
            "id": scan_id, "status": "started", "phase": "initializing",
            "created_at": datetime.now().isoformat(), "completed_at": None,
            "progress": 0, "type": "postman-ai",
            "vulnerabilities": [], "test_cases": [], "collection_analysis": {},
            "summary": {}, "ai_enabled": ai_enabled, "ml_enabled": ml_enabled,
            "bug_bounty": bug_bounty, "beast_mode": beast_mode
        }

        # Persist uploads / recon build
        upload_path = None
        if file and file.filename:
            upload_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{scan_id}_{file.filename}")
            file.save(upload_path)
        elif pdf_doc and pdf_doc.filename:
            pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{scan_id}_{pdf_doc.filename}")
            pdf_doc.save(pdf_path)
            _emit(scan_id,"scan_update",{"progress":5,"phase":"Analysis","message":"Parsing API PDF…"})
            col = build_postman_collection_from_pdf(pdf_path, base_override=target_url or None)
            upload_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{scan_id}_pdf_collection.json")
            with open(upload_path,"w",encoding="utf-8") as f: json.dump(col,f,indent=2)
        elif target_url:
            _emit(scan_id,"scan_update",{"progress":5,"phase":"Recon","message":"Recon: discovering OpenAPI/seed endpoints…"})
            upload_path = recon_to_collection(target_url, app.config["UPLOAD_FOLDER"])
        else:
            return jsonify({"error":"Provide a Postman collection OR target_url OR api_doc_pdf"}), 400

        variables_path = None
        if variables_file and variables_file.filename:
            variables_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{scan_id}_variables_{variables_file.filename}")
            variables_file.save(variables_path)
        variables_map = _load_postman_variables(variables_path)

        def worker():
            try:
                # ---- Phase: Analysis ----
                _emit(scan_id, "scan_update", {"progress": 12, "phase": "Analysis", "message": "Analyzing collection…"})
                ai_gen = AITestCaseGenerator()
                # Prefer the robust parser in PostmanIntegration for consistent endpoint extraction
                analysis = PostmanIntegration(scanner=None, ai_enabled=False, environment=variables_map).get_collection_analysis(upload_path)
                # Fallback: if that returns empty, try previous analyzer
                if not analysis.get("endpoints"):
                    analysis = ai_gen.analyze_collection_deeply(_safe_load_json(upload_path))
                scan_results[scan_id]["collection_analysis"] = analysis
                _emit(scan_id, "scan_update", {"progress": 20, "message": f"Found {len(analysis.get('endpoints',[]))} endpoints. Complexity {analysis.get('api_complexity_score',0)}"})

                # ---- Phase: AI TestGen ----
                _emit(scan_id, "scan_update", {"progress": 24, "phase": "AI TestGen", "message": "Generating AI/ML test cases…"})
                all_tests = []
                for ep in analysis.get("endpoints") or []:
                    tcs = ai_gen.generate_comprehensive_test_cases(ep)
                    all_tests.extend(tcs)
                scan_results[scan_id]["test_cases"] = all_tests
                _emit(scan_id, "scan_update", {"progress": 34, "message": f"{len(all_tests)} AI tests ready."})

                # ---- Phase: Parsing/Standard Tests ----
                _emit(scan_id, "scan_update", {"progress": 40, "phase": "Parsing", "message": "Parsing & running standard tests…"})
                base_scanner = APISecurityScanner({"ml_enabled": ml_enabled})
                adapter = ScannerAdapter(base_scanner, http_fallback=True, timeout=12.0, pool_maxsize=200)

                # PostmanIntegration will skip unresolved endpoints safely and call adapter.scan_endpoint
                integration = PostmanIntegration(adapter, ai_enabled=False, environment=variables_map)
                std_vulns = integration.run_security_scan(upload_path, selected_folders=selected_folders)

                # ---- Phase: Agentic (Beast Mode) ----
                agentic_v = []
                if beast_mode and (analysis.get("endpoints") or []):
                    _emit(scan_id, "scan_update", {"progress": 58, "phase": "Agentic", "message": "Beast Mode: context-aware testing…"})
                    agentic_v = run_beast_mode(analysis.get("endpoints"), adapter, max_workers=12)
                    # mark
                    for v in agentic_v or []: v["agentic"] = True

                # ---- Phase: AI Exec ----
                ai_vulns = []
                if ai_enabled and all_tests:
                    _emit(scan_id, "scan_update", {"progress": 70, "phase": "AI Exec", "message": "Executing AI-generated tests…"})
                    # Keep fast: cap sample size
                    sample = all_tests if len(all_tests) <= 800 else all_tests[:800]
                    for tc in sample:
                        ep_url = tc.get("endpoint") or tc.get("url")
                        if not ep_url:
                            continue
                        res = adapter.call(ep_url, tc.get("method","GET"), headers=None, data=tc.get("payload"))
                        for v in (res or []):
                            v["ai_generated"] = True
                            v["test_case_name"] = tc.get("test_name")
                        ai_vulns.extend(res)

                # ---- Phase: Verify / Report ----
                all_v = (std_vulns or []) + (agentic_v or []) + (ai_vulns or [])
                _emit(scan_id, "scan_update", {"progress": 84, "phase": "Verify", "message": "Verifying & de-duplicating…"})
                verified = post_verify_and_score(all_v)

                if bug_bounty:
                    verified = [v for v in verified if v.get("priority") in ("P1","P2","P3")]

                summary = summarize_findings(verified, all_tests, analysis)
                scan_results[scan_id].update({"vulnerabilities": verified, "summary": summary})

                _emit(scan_id, "scan_update", {"progress": 92, "phase": "Report", "message": "Generating industry-grade PDF…"})
                report = ComprehensiveReportGenerator().generate_enhanced_report(
                    scan_id=scan_id,
                    collection_analysis=analysis,
                    test_cases=all_tests,
                    vulnerabilities=verified,
                    ai_enabled=ai_enabled
                )
                scan_results[scan_id].update({"status":"completed","phase":"completed","progress":100,"report_path":report,"completed_at":datetime.now().isoformat()})
                _emit(scan_id, "scan_complete", {"vulnerabilities": len(verified)})
            except Exception as e:
                logger.exception("Scan failed")
                scan_results[scan_id].update({"status":"failed","error":str(e),"completed_at":datetime.now().isoformat()})
                _emit(scan_id, "scan_error", {"error": str(e)})
            finally:
                active_scans.pop(scan_id, None)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        active_scans[scan_id] = t
        return jsonify({"scan_id": scan_id, "status":"started", "bug_bounty": bug_bounty, "beast_mode": beast_mode})
    except Exception as e:
        logger.exception("Error starting scan")
        return jsonify({"error": f"Internal error: {e}"}), 500

@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    data = scan_results.get(scan_id)
    if not data:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(data)

@app.route("/api/scan/<scan_id>/report", methods=["GET"])
def download_report(scan_id):
    data = scan_results.get(scan_id)
    if not data or data.get("status") != "completed":
        return jsonify({"error": "Report not available"}), 404
    path = data.get("report_path")
    if not path or not os.path.exists(path):
        return jsonify({"error": "Report not found"}), 404
    return send_file(path, as_attachment=True, download_name=f"rudra_scan_report_{scan_id}.pdf", mimetype="application/pdf")

# ---------- Dashboard routes ----------
@app.route("/")
@app.route("/dashboard")
def dashboard():
    if SERVE_BUILD:
        # Serve the React build
        return send_file(os.path.join(FRONTEND_DIST, "index.html"))
    # Dev helper page: point to your Vite server
    html = f"""
    <html><head><title>{PRODUCT_NAME} – Dev</title></head>
    <body style="font-family: ui-sans-serif, system-ui; background:#0b1220; color:#e2e8f0">
      <div style="max-width:760px;margin:40px auto">
        <h1>{PRODUCT_NAME}</h1>
        <p>Dashboard is in <code>frontend/</code>. Start Vite dev server:</p>
        <pre style="background:#0f172a;padding:12px;border-radius:8px">cd frontend
npm run dev</pre>
        <p>Then open: <a href="http://localhost:5173" style="color:#ef4444">http://localhost:5173</a></p>
      </div>
    </body></html>
    """
    return html

# ---------- Errors ----------
@app.errorhandler(404)
def _404(e): return jsonify({"error":"Endpoint not found"}), 404
@app.errorhandler(400)
def _400(e): return jsonify({"error":"Bad request"}), 400
@app.errorhandler(413)
def _413(e): return jsonify({"error":"File too large. Maximum size is 32MB."}), 413
@app.errorhandler(500)
def _500(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error":"Internal server error"}), 500

# ---------- Main ----------
if __name__ == "__main__":
    print(f"🚀 Starting {PRODUCT_NAME}")
    print("📊 Dashboard (React): http://localhost:4000/dashboard")
    print("🔍 Health:             http://localhost:4000/health")
    print("\n🤖 Stable & Fast:")
    print("  ✅ Comprehensive Postman parser (v2.x, vars, auth, graphql, legacy)")
    print("  ✅ Agentic Beast Mode (Bug Bounty, context-aware)")
    print("  ✅ AI/ML verification with anti-FP & VRT P1–P3")

    # IMPORTANT: debug=False and use_reloader=False → sockets stay stable
    socketio.run(app, debug=False, host="0.0.0.0", port=4000, use_reloader=False)

