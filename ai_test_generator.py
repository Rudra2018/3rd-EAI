import os
import re
import json
import logging
from copy import deepcopy
from typing import Dict, List, Any

# Optional: .env support
try:
    from dotenv import load_dotenv
    load_dotenv()
    ENV_LOADED = True
except Exception:
    ENV_LOADED = False

log = logging.getLogger("ai_test_generator")
logging.basicConfig(level=logging.INFO)
if ENV_LOADED:
    log.info("Loaded environment variables from .env")

# Optional LLM backends (safe to miss)
OPENAI_OK = False
GEMINI_OK = False
try:
    import openai
    key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY_BETA") or os.getenv("OPENAI_KEY")
    if key:
        openai.api_key = key
        OPENAI_OK = True
        log.info("OpenAI client initialized successfully")
except Exception:
    pass

try:
    import google.generativeai as genai
    gk = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    if gk:
        genai.configure(api_key=gk)
        GEMINI_OK = True
        log.info("Gemini client initialized successfully")
except Exception:
    pass

# Speed lever
FAST_MODE = os.getenv("RUDRA_FAST_MODE", "").lower() in ("1", "true", "yes", "on")
if FAST_MODE:
    log.info("🚀 FAST_MODE enabled: skipping AI and using minimal payloads")

# -------- Helpers for Postman-like structures (collection analyzer) --------

def _flatten_items(items, parent=None):
    flat = []
    for it in items or []:
        it = dict(it or {})
        it["_parent"] = parent
        if isinstance(it.get("item"), list):
            flat.extend(_flatten_items(it["item"], parent=it))
        else:
            flat.append(it)
    return flat

def _url_from_request(req) -> str:
    url = req.get("url")
    if isinstance(url, str):
        return url
    if isinstance(url, dict):
        raw = url.get("raw")
        if raw:
            return raw
        # build if host/path arrays exist
        host = url.get("host")
        path = url.get("path")
        proto = url.get("protocol") or "https"
        if isinstance(host, list): host = ".".join(host)
        if isinstance(path, list): path = "/" + "/".join(path)
        if host and path:
            qs = url.get("query") or []
            if qs:
                from urllib.parse import urlencode
                qd = {q.get("key"): q.get("value") for q in qs if q.get("key") is not None}
                return f"{proto}://{host}{path}?{urlencode(qd, doseq=True)}"
            return f"{proto}://{host}{path}"
    return ""

def _guess_content_type(req) -> str:
    hdrs = req.get("header") or []
    for h in hdrs:
        if (h.get("key") or "").lower() == "content-type":
            return (h.get("value") or "").lower()
    body = req.get("body") or {}
    mode = body.get("mode")
    if mode == "graphql": return "application/json"
    if mode == "urlencoded": return "application/x-www-form-urlencoded"
    if mode == "formdata": return "multipart/form-data"
    raw = (body.get("raw") or "").strip()
    if raw.startswith("{"): return "application/json"
    return ""

def _resolve_variables(value, variables):
    if isinstance(value, str):
        for var in variables:
            value = value.replace(f'{{{{{var["key"]}}}}}', var["value"])
    return value

def _parse_auth(req):
    auth = req.get("auth")
    if auth:
        if auth["type"] == "bearer":
            return {"Authorization": f"Bearer {auth['bearer'][0]['value']}"}
        # Add basic, apikey, etc.
        if auth["type"] == "basic":
            from base64 import b64encode
            username = auth["basic"][0]["value"]
            password = auth["basic"][1]["value"]
            return {"Authorization": f"Basic {b64encode(f'{username}:{password}'.encode()).decode()}"}
    return {}

def _parse_body(req):
    body = req.get("body", {})
    mode = body.get("mode")
    if mode == "raw":
        return body.get("raw")
    elif mode == "graphql":
        return json.dumps({"query": body["graphql"]["query"], "variables": body["graphql"]["variables"]})
    elif mode == "formdata":
        return {p["key"]: p["value"] for p in body["formdata"] if not p.get("disabled")}  # Handle multipart, ignore disabled
    elif mode == "urlencoded":
        return {p["key"]: p["value"] for p in body["urlencoded"] if not p.get("disabled")}
    return None

def _extract_endpoints_from_collection(col_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    variables = col_json.get("variable", [])
    items = col_json.get("item") or []
    if not items and isinstance(col_json.get("requests"), list):
        items = [{"name": r.get("name") or r.get("url"), "request": r} for r in col_json["requests"]]

    flat = _flatten_items(items)
    endpoints = []
    for it in flat:
        req = it.get("request") or {k: it.get(k) for k in ("method","url","header","body") if it.get(k) is not None}
        if not req:
            continue
        method = (req.get("method") or "GET").upper()
        url = _resolve_variables(_url_from_request(req), variables)
        if not url:
            continue
        headers = {h["key"]: h["value"] for h in req.get("header", []) if not h.get("disabled")}
        headers.update(_parse_auth(req))
        body = _parse_body(req)
        endpoints.append({
            "name": it.get("name") or f"{method} {url}",
            "method": method,
            "url": url,
            "content_type": _guess_content_type(req),
            "is_graphql": (req.get("body") or {}).get("mode") == "graphql" or "/graphql" in (url.lower()),
            "headers": headers,
            "body": body
        })
    # dedupe
    seen = set(); uniq = []
    for ep in endpoints:
        k = (ep["method"], ep["url"])
        if k in seen: continue
        seen.add(k); uniq.append(ep)
    return uniq

def _complexity_score(endpoints: List[Dict[str, Any]]) -> int:
    score = len(endpoints)
    for ep in endpoints:
        m = ep.get("method","GET").upper()
        if m in ("POST","PUT","PATCH","DELETE"): score += 2
        path = ep.get("url","").lower()
        if any(k in path for k in ("/admin","/internal","/credentials","/token","/transfer","/payment")):
            score += 3
        if ep.get("is_graphql"): score += 4
    return min(100, score)

# -------- VRT alignment and payload builders --------

VRT_P_MAP = {
    "sqli":"P1","cmdi":"P1","rce":"P1",
    "idor":"P2","brokenauth":"P2","ssrf":"P2","xxe":"P2","sensitive":"P2",
    "xss":"P3","cors":"P3","open-redirect":"P3","csrf":"P3","nosqli":"P3","mass-assignment":"P3"
}

SQLI_STRINGS = ["' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "') OR ('1'='1"]
TIME_SINKS = [";SELECT pg_sleep(3)--", "';WAITFOR DELAY '0:0:3'--"]
NOSQLI = [{"$ne": None}, {"$gt": ""}]
PATH_TRAVERSAL = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
SSRF_URLS = ["http://169.254.169.254/latest/meta-data/", "http://localhost:80/", "http://127.0.0.1/"]
XSS_STRS = ['"><svg onload=alert(1)>', "<img src=x onerror=alert(1)>"]
OPEN_REDIRECTS = ["//evil.example.com", "https://evil.example.com/%2f.."]
BIG_NUMBER = 10**12

GRAPHQL_INTROSPECTION = {
    "query": "query IntrospectionQuery { __schema { types { name } } }",
    "variables": {}
}

def _prio(tag: str) -> str:
    return VRT_P_MAP.get(tag, "P3")

def _base_headers(ct: str):
    h = {}
    if ct:
        h["Content-Type"] = ct
        if ct == "application/json":
            h["Accept"] = "application/json"
    return h

# -------- Public API --------

class AITestCaseGenerator:
    """
    Produces high-quality, context-aware test cases for REST & GraphQL endpoints.
    - FAST_MODE (env RUDRA_FAST_MODE=true) yields a tight but potent set.
    - With OPENAI/Gemini keys set, can augment with extra targeted cases.
    """

    def analyze_collection_deeply(self, collection_json: Dict[str, Any]) -> Dict[str, Any]:
        endpoints = _extract_endpoints_from_collection(collection_json)
        score = _complexity_score(endpoints)
        return {
            "endpoints": endpoints,
            "api_complexity_score": score
        }

    # ---- Main generator ----
    def generate_comprehensive_test_cases(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Returns a list of test case dicts:
        { test_name, method, url, endpoint, headers, payload, tags, priority_hint }
        """
        url = endpoint.get("url")
        method = (endpoint.get("method") or "GET").upper()
        ct = endpoint.get("content_type") or ("application/json" if method in ("POST","PUT","PATCH") else "")
        is_gql = bool(endpoint.get("is_graphql"))
        name = endpoint.get("name") or f"{method} {url}"

        tests: List[Dict[str, Any]] = []

        # GraphQL specialized cases
        if is_gql:
            tests.extend(self._graphql_tests(url, ct))
            tests.extend(self._generic_write_tamper(url, method, ct))
            return self._limit_for_speed(name, tests)

        # REST tests
        flavor_tags = self._classify(url)
        tests.extend(self._auth_bypass_tests(url, method, ct, flavor_tags))
        tests.extend(self._idor_bola_tests(url, method, ct))
        tests.extend(self._injection_tests(url, method, ct, flavor_tags))
        tests.extend(self._file_path_tests(url, method, ct, flavor_tags))
        tests.extend(self._open_redirect_csrf_tests(url, method, ct, flavor_tags))
        tests.extend(self._generic_write_tamper(url, method, ct))

        # LLM augmentation (optional & bounded)
        if not FAST_MODE and (OPENAI_OK or GEMINI_OK):
            try:
                tests.extend(self._llm_aug(url, method, ct, flavor_tags))
            except Exception:
                pass

        return self._limit_for_speed(name, tests)

    def _graphql_tests(self, url, ct) -> List[Dict[str, Any]]:
        tests = []
        # 1) Introspection
        tests.append(self._tc(
            "GraphQL Introspection",
            "POST", url, _base_headers("application/json"),
            payload=json.dumps(GRAPHQL_INTROSPECTION),
            tags=["graphql","introspection"], prio=_prio("sensitive")
        ))
        # 2) Alias-based field duplication (DoS-ish / auth bypass hints)
        alias_query = """
        query($id: ID!) {
          a:user(id:$id){id email}
          b:user(id:$id){id email}
          c:user(id:$id){id email}
        }
        """
        tests.append(self._tc(
            "GraphQL Alias Duplication",
            "POST", url, _base_headers("application/json"),
            payload=json.dumps({"query": alias_query, "variables":{"id":"1"}}),
            tags=["graphql","authz"], prio="P2"
        ))
        # 3) Batch query (mutation + query)
        batch = {"query":"mutation { updateUser(id:1, role:\"admin\"){ id role } } query { me{ id role } }", "variables":{}}
        tests.append(self._tc(
            "GraphQL Mixed Mutation+Query",
            "POST", url, _base_headers("application/json"),
            payload=json.dumps(batch),
            tags=["graphql","mass-assignment"], prio=_prio("mass-assignment")
        ))
        # 4) Boolean auth bypass (no token)
        tests.append(self._tc(
            "GraphQL No-Token Access",
            "POST", url, _base_headers("application/json"),
            payload=json.dumps({"query":"{ me { id email } }", "variables":{}}),
            tags=["graphql","broken-auth"], prio=_prio("brokenauth")
        ))
        # Add more: Overly deep queries for DoS
        deep_query = "query { user { friends { friends { name } } } }"
        tests.append(self._tc(
            "GraphQL Depth Attack",
            "POST", url, _base_headers("application/json"),
            payload=json.dumps({"query": deep_query}),
            tags=["graphql","dos"], prio="P3"
        ))
        return tests

    def _auth_bypass_tests(self, url, method, ct, tags) -> List[Dict[str, Any]]:
        tests = []
        if method in ("GET","POST","PUT","PATCH","DELETE"):
            tests.append(self._tc("No-Token Request", method, url, headers={}, payload=None,
                                  tags=["auth","broken-auth"], prio=_prio("brokenauth")))
            tests.append(self._tc("Invalid Token", method, url, headers={"Authorization":"Bearer invalid.invalid"},
                                  payload=None, tags=["auth","broken-auth"], prio=_prio("brokenauth")))
            # Cookie strip
            tests.append(self._tc("Strip Cookies", method, url, headers={"Cookie":""}, payload=None,
                                  tags=["auth","broken-auth"], prio=_prio("brokenauth")))
            # Role escalation
            tests.append(self._tc("Role Escalation", method, url, headers={"X-Role": "admin"},
                                  payload=None, tags=["auth","broken-auth"], prio=_prio("brokenauth")))
        return tests

    def _idor_bola_tests(self, url, method, ct) -> List[Dict[str, Any]]:
        tests = []
        # Path id like /users/123 or /orders/9/items/1
        ids = re.findall(r"/(\d+)(?=/|$|\?)", url)
        if ids:
            for raw in ids[:2]:  # Limit to first 2 IDs
                num = int(raw)
                tests.append(self._tc(
                    f"IDOR Low ID {num-1}",
                    method, url.replace(raw, str(num-1)), _base_headers(ct),
                    payload=None, tags=["idor","bola"], prio=_prio("idor")
                ))
                tests.append(self._tc(
                    f"IDOR High ID {BIG_NUMBER}",
                    method, url.replace(raw, str(BIG_NUMBER)), _base_headers(ct),
                    payload=None, tags=["idor","bola"], prio=_prio("idor")
                ))
                tests.append(self._tc(
                    f"IDOR GUID Swap",
                    method, url.replace(raw, "00000000-0000-0000-0000-000000000000"), _base_headers(ct),
                    payload=None, tags=["idor","bola"], prio=_prio("idor")
                ))
        # Query param IDs
        query_ids = re.findall(r"(\w+)=(\d+)", url)
        for key, val in query_ids[:2]:
            tests.append(self._tc(
                f"IDOR Query Low {key}",
                method, re.sub(f"{key}=\\d+", f"{key}={int(val)-1}", url), _base_headers(ct),
                payload=None, tags=["idor"], prio=_prio("idor")
            ))
        return tests

    def _injection_tests(self, url, method, ct, tags) -> List[Dict[str, Any]]:
        tests = []
        # SQLi in URL params
        for sqli in SQLI_STRINGS:
            tests.append(self._tc(
                f"SQLi {sqli[:10]}...",
                method, f"{url}?q={sqli}", _base_headers(ct),
                payload=None, tags=["sqli","injection"], prio=_prio("sqli")
            ))
        # Time-based blind
        for sink in TIME_SINKS:
            tests.append(self._tc(
                f"Blind SQLi {sink[:10]}...",
                method, f"{url}?q={sink}", _base_headers(ct),
                payload=None, tags=["sqli","blind"], prio=_prio("sqli")
            ))
        # NoSQLi for JSON APIs
        if "json" in ct:
            for nosql in NOSQLI:
                tests.append(self._tc(
                    "NoSQLi",
                    method, url, _base_headers(ct),
                    payload=json.dumps(nosql), tags=["nosqli","injection"], prio=_prio("nosqli")
                ))
        # XSS
        for xss in XSS_STRS:
            tests.append(self._tc(
                f"XSS {xss[:10]}...",
                method, f"{url}?input={xss}", _base_headers(ct),
                payload=None, tags=["xss","injection"], prio=_prio("xss")
            ))
        # SSRF
        for ssrf in SSRF_URLS:
            tests.append(self._tc(
                f"SSRF {ssrf[:10]}...",
                method, f"{url}?url={ssrf}", _base_headers(ct),
                payload=None, tags=["ssrf"], prio=_prio("ssrf")
            ))
        return tests

    def _file_path_tests(self, url, method, ct, tags) -> List[Dict[str, Any]]:
        tests = []
        if "file" in url.lower() or "path" in url.lower():
            for trav in PATH_TRAVERSAL:
                tests.append(self._tc(
                    f"Path Traversal {trav[:10]}...",
                    method, f"{url}?file={trav}", _base_headers(ct),
                    payload=None, tags=["lfi","rfi"], prio=_prio("xxe")  # Similar priority
                ))
        return tests

    def _open_redirect_csrf_tests(self, url, method, ct, tags) -> List[Dict[str, Any]]:
        tests = []
        if "redirect" in url.lower() or "next" in url.lower():
            for redir in OPEN_REDIRECTS:
                tests.append(self._tc(
                    f"Open Redirect {redir[:10]}...",
                    method, f"{url}?next={redir}", _base_headers(ct),
                    payload=None, tags=["open-redirect"], prio=_prio("open-redirect")
                ))
        # CSRF: Invalid/missing token
        tests.append(self._tc(
            "CSRF Missing Token",
            method, url, headers={"X-CSRF-Token": ""}, payload=None,
            tags=["csrf"], prio=_prio("csrf")
        ))
        return tests

    def _generic_write_tamper(self, url, method, ct) -> List[Dict[str, Any]]:
        tests = []
        if method in ("POST", "PUT", "PATCH"):
            # Mass assignment
            tamper_payload = {"role": "admin", "is_admin": True}
            tests.append(self._tc(
                "Mass Assignment",
                method, url, _base_headers("application/json"),
                payload=json.dumps(tamper_payload), tags=["mass-assignment"], prio=_prio("mass-assignment")
            ))
            # CORS misconfig
            tests.append(self._tc(
                "CORS Preflight",
                "OPTIONS", url, headers={"Origin": "http://evil.com"}, payload=None,
                tags=["cors"], prio=_prio("cors")
            ))
        return tests

    def _classify(self, url: str) -> List[str]:
        tags = []
        if "/auth" in url or "/login" in url:
            tags.append("auth")
        if "/user" in url or "/profile" in url:
            tags.append("user")
        # Add more classifications
        return tags

    def _tc(self, name: str, method: str, url: str, headers: Dict, payload: Any, tags: List[str], prio: str) -> Dict[str, Any]:
        return {
            "test_name": name,
            "method": method,
            "url": url,
            "headers": headers,
            "payload": payload,
            "tags": tags,
            "priority_hint": prio
        }

    def _limit_for_speed(self, name: str, tests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if FAST_MODE:
            return tests[:5]  # Limit for speed
        return tests

    def _llm_aug(self, url: str, method: str, ct: str, tags: List[str]) -> List[Dict[str, Any]]:
        prompt = f"Generate 3 additional security test cases for {method} {url} with tags {tags}"
        if OPENAI_OK:
            response = openai.ChatCompletion.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
            return json.loads(response.choices[0].message.content)  # Assume JSON output
        elif GEMINI_OK:
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            return json.loads(response.text)
        return []
