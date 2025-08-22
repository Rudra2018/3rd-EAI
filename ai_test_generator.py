# ai_test_generator.py
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
    # Support both legacy and new clients gracefully
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

def _extract_endpoints_from_collection(col_json: Dict[str, Any]) -> List[Dict[str, Any]]:
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
        url = _url_from_request(req)
        if not url:
            continue
        endpoints.append({
            "name": it.get("name") or f"{method} {url}",
            "method": method,
            "url": url,
            "content_type": _guess_content_type(req),
            "is_graphql": (req.get("body") or {}).get("mode") == "graphql" or "/graphql" in (url.lower()),
        })
    # dedupe
    seen = set(); uniq = []
    for ep in endpoints:
        k = (ep["method"], ep["url"])
        if k in seen: continue
        seen.add(k); uniq.append(ep)
    return uniq

def _complexity_score(endpoints: List[Dict[str, Any]]) -> int:
    # Simple heuristic: endpoints count + weight for mutating methods + presence of admin/payments/graphql
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
            # Also add generic HTTP hardening around /graphql
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

    # ---- Feature blocks ----

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
        return tests

    def _idor_bola_tests(self, url, method, ct) -> List[Dict[str, Any]]:
        tests = []
        # Path id like /users/123 or /orders/9/items/1
        ids = re.findall(r"/(\d+)(?=/|$|\?)", url)
        if ids:
            for raw in ids[:2]:
                try:
                    n = int(raw)
                    for probe in (n+1, max(1, n-1)):
                        tampered = url.replace(f"/{raw}", f"/{probe}", 1)
                        tests.append(self._tc(
                            f"BOLA/IDOR path probe ({raw}->{probe})",
                            "GET" if method == "GET" else method, tampered,
                            headers={}, payload=None, tags=["idor","authz"], prio=_prio("idor")
                        ))
                except Exception:
                    continue
        # Query id=? pattern
        if re.search(r"[?&](id|user_id|account_id|order_id)=", url, re.I):
            tests.append(self._tc("BOLA/IDOR query probe (+1)", method,
                                  re.sub(r"((?:^|[?&])(id|user_id|account_id|order_id)=)(\d+)",
                                         lambda m: f"{m.group(1)}{int(m.group(3))+1}", url, count=1, flags=re.I),
                                  headers={}, payload=None, tags=["idor","authz"], prio=_prio("idor")))
        return tests

    def _injection_tests(self, url, method, ct, tags) -> List[Dict[str, Any]]:
        tests = []
        # SQLi in query
        if "?" in url and method in ("GET","DELETE"):
            for inj in SQLI_STRINGS[:2] + (TIME_SINKS[:1] if not FAST_MODE else []):
                crafted = re.sub(r"=([^&]+)", lambda m: "="+inj, url, count=1)
                tests.append(self._tc(f"SQLi param probe ({inj[:8]}…)", method, crafted, {}, None,
                                      tags=["sqli"], prio=_prio("sqli")))
        # JSON body injections for write methods
        if method in ("POST","PUT","PATCH"):
            # NoSQLi
            tests.append(self._tc("NoSQLi JSON object", method, url, _base_headers("application/json"),
                                  payload=json.dumps({"username": {"$ne": None}, "password": {"$ne": ""}}),
                                  tags=["nosqli"], prio=_prio("nosqli")))
            # SQLi fields
            tests.append(self._tc("SQLi JSON string", method, url, _base_headers("application/json"),
                                  payload=json.dumps({"q": SQLI_STRINGS[0]}),
                                  tags=["sqli"], prio=_prio("sqli")))
            if not FAST_MODE:
                tests.append(self._tc("Time-based SQLi JSON", method, url, _base_headers("application/json"),
                                      payload=json.dumps({"q": TIME_SINKS[0]}),
                                      tags=["sqli"], prio=_prio("sqli")))
            # Mass assignment (role escalation)
            tests.append(self._tc("Mass-assignment role escalation", method, url, _base_headers("application/json"),
                                  payload=json.dumps({"role": "admin", "is_admin": True, "isSuperuser": True}),
                                  tags=["mass-assignment"], prio=_prio("mass-assignment")))
        return tests

    def _file_path_tests(self, url, method, ct, tags) -> List[Dict[str, Any]]:
        tests = []
        # SSRF hints by param names
        if re.search(r"(url|uri|callback|redirect|webhook|feed|image|avatar)=", url, re.I) or method in ("POST","PUT","PATCH"):
            for u in (SSRF_URLS[:1] if FAST_MODE else SSRF_URLS):
                if method in ("POST","PUT","PATCH"):
                    tests.append(self._tc("SSRF JSON url", method, url, _base_headers("application/json"),
                                          payload=json.dumps({"url": u}), tags=["ssrf"], prio=_prio("ssrf")))
                else:
                    crafted = re.sub(r"((?:^|[?&])(url|uri|callback|redirect|webhook|feed|image|avatar)=)[^&]*",
                                     lambda m: m.group(1)+u, url, count=1, flags=re.I)
                    tests.append(self._tc("SSRF query url", method, crafted, {}, None, tags=["ssrf"], prio=_prio("ssrf")))
        # Path traversal on filenames
        if re.search(r"(file|path|dir)=", url, re.I) or method in ("POST","PUT","PATCH"):
            tr = PATH_TRAVERSAL[0] if FAST_MODE else PATH_TRAVERSAL[0:2]
            for p in tr:
                if method in ("POST","PUT","PATCH"):
                    tests.append(self._tc("Path traversal body", method, url, _base_headers("application/json"),
                                          payload=json.dumps({"path": p}), tags=["sensitive"], prio=_prio("sensitive")))
                else:
                    crafted = re.sub(r"((?:^|[?&])(file|path|dir)=)[^&]*",
                                     lambda m: m.group(1)+p, url, count=1, flags=re.I)
                    tests.append(self._tc("Path traversal query", method, crafted, {}, None, tags=["sensitive"], prio=_prio("sensitive")))
        return tests

    def _open_redirect_csrf_tests(self, url, method, ct, tags) -> List[Dict[str, Any]]:
        tests = []
        # Open redirect
        if re.search(r"(redirect|return|next|destination|continue|url)=", url, re.I):
            crafted = re.sub(r"((?:^|[?&])(redirect|return|next|destination|continue|url)=)[^&]*",
                             lambda m: m.group(1)+OPEN_REDIRECTS[0], url, count=1, flags=re.I)
            tests.append(self._tc("Open Redirect", "GET", crafted, {}, None, tags=["open-redirect"], prio=_prio("open-redirect")))
        # CSRF (write without auth headers)
        if method in ("POST","PUT","PATCH","DELETE"):
            tests.append(self._tc("CSRF (no token, write verb)", method, url, headers={}, payload=None,
                                  tags=["csrf"], prio=_prio("csrf")))
        return tests

    def _generic_write_tamper(self, url, method, ct) -> List[Dict[str, Any]]:
        tests = []
        # Method tampering (HEAD/OPTIONS/GET on POST)
        if method == "POST":
            tests.append(self._tc("Verb tamper: GET instead of POST", "GET", url, {}, None, tags=["hardening"], prio="P3"))
            tests.append(self._tc("Verb tamper: HEAD instead of POST", "HEAD", url, {}, None, tags=["hardening"], prio="P3"))
        # Numeric overflow / negative amount for payments
        if re.search(r"(amount|price|qty|quantity|total)=", url, re.I):
            crafted = re.sub(r"((?:^|[?&])(amount|price|qty|quantity|total)=)[^&]*",
                             lambda m: m.group(1)+str(BIG_NUMBER), url, count=1, flags=re.I)
            tests.append(self._tc("Business logic: huge amount", "GET", crafted, {}, None, tags=["sensitive"], prio="P2"))
        if method in ("POST","PUT","PATCH"):
            tests.append(self._tc("Business logic: negative amount", method, url, _base_headers("application/json"),
                                  payload=json.dumps({"amount": -100}), tags=["sensitive"], prio="P2"))
        return tests

    # ---- Optional LLM augmentation ----
    def _llm_aug(self, url, method, ct, tags) -> List[Dict[str, Any]]:
        prompt = (
            "Generate 3 high-impact API security probes for this endpoint.\n"
            f"Endpoint: {method} {url}\n"
            f"Context tags: {', '.join(tags)}\n"
            "Return a compact JSON array of objects with: test_name, method, url, headers (dict), payload (string or null), priority_hint (P1|P2|P3), tags (array).\n"
            "Keep it concise and safe. No explanations."
        )
        content = None
        if OPENAI_OK:
            try:
                # Support both Chat Completions and Responses APIs; keep compatibility broad
                resp = openai.ChatCompletion.create(
                    model=os.getenv("OPENAI_MODEL","gpt-4o-mini"),
                    messages=[{"role":"user","content":prompt}],
                    temperature=0.2,
                    max_tokens=400
                )
                content = resp.choices[0].message["content"]
            except Exception:
                content = None
        if content is None and GEMINI_OK:
            try:
                model = genai.GenerativeModel(os.getenv("GEMINI_MODEL","gemini-1.5-pro"))
                resp = model.generate_content(prompt)
                content = resp.text
            except Exception:
                content = None

        out = []
        if content:
            try:
                # Extract JSON array
                jtxt = content.strip()
                start = jtxt.find("["); end = jtxt.rfind("]")
                if start >= 0 and end > start:
                    data = json.loads(jtxt[start:end+1])
                    for o in data[:3]:
                        headers = o.get("headers") or {}
                        out.append(self._tc(
                            o.get("test_name","LLM case"),
                            o.get("method", method), o.get("url", url),
                            headers, o.get("payload"),
                            tags=list(set((o.get("tags") or []) + ["llm-aug"])),
                            prio=o.get("priority_hint","P3")
                        ))
            except Exception:
                pass
        return out

    # ---- Utilities ----

    def _classify(self, url) -> List[str]:
        s = url.lower()
        tags = []
        if any(k in s for k in ("/auth","/login","/token","/oauth","/sessions")): tags.append("auth")
        if any(k in s for k in ("/admin","/internal","/credentials")): tags.append("admin")
        if any(k in s for k in ("/payment","/transfer","/payout","/withdraw")): tags.append("payments")
        if "/graphql" in s: tags.append("graphql")
        if any(k in s for k in ("/user","/account","/profile")): tags.append("user")
        return tags

    def _tc(self, test_name, method, url, headers, payload, tags, prio) -> Dict[str, Any]:
        # Normalize headers to dict
        hdict = {}
        if isinstance(headers, dict):
            hdict = deepcopy(headers)
        elif isinstance(headers, list):
            for h in headers:
                k = h.get("key"); v = h.get("value")
                if k: hdict[k] = v
        tc = {
            "test_name": test_name,
            "method": method.upper(),
            "url": url,
            "endpoint": url,
            "headers": hdict,
            "payload": payload,
            "tags": list(dict.fromkeys(tags or [])),
            "priority_hint": prio
        }
        return tc

    def _limit_for_speed(self, ep_name: str, tests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Keep quality high but cap volume for speed. In FAST_MODE ~8-10 per endpoint.
        Otherwise ~12-16 with diversity preserved.
        """
        if not tests:
            return []
        # Always prioritize P1>P2>P3 and unique tag coverage
        order = {"P1":0,"P2":1,"P3":2}
        tests = sorted(tests, key=lambda t: (order.get(t.get("priority_hint","P3"), 2), len(t.get("tags") or [])))
        cap = 10 if FAST_MODE else 16
        trimmed = tests[:cap]
        log.debug(f"AI TestGen: {len(trimmed)}/{len(tests)} kept for '{ep_name}' (FAST_MODE={FAST_MODE})")
        return trimmed

