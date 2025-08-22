# integrations/postman.py
import json
import os
import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote, urlencode

try:
    import openai  # optional; only used if ai_enabled=True and key present
except Exception:
    openai = None

logger = logging.getLogger(__name__)

# --------------------- Utilities ---------------------

PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_\-\.]+)\s*\}\}")
ENCODED_PLACEHOLDER_RE = re.compile(r"%7B%7B\s*([A-Za-z0-9_\-\.]+)\s*%7D%7D", re.IGNORECASE)
COLON_PARAM_RE = re.compile(r"/:([A-Za-z0-9_\-]+)(?=/|$)")
DEFAULT_PARAM_VALUE = "1"


def _has_unresolved_placeholders(s: str) -> bool:
    if not isinstance(s, str):
        return False
    return ("{{" in s and "}}" in s) or ("%7B%7B" in s.upper() and "%7D%7D" in s.upper())


def _resolve_placeholders(value: str, variables: Dict[str, str]) -> Tuple[str, List[str]]:
    """Resolve both {{var}} and %7B%7Bvar%7D%7D in a string. Returns (resolved, unresolved_vars)."""
    if not isinstance(value, str):
        return value, []

    unresolved: List[str] = []
    decoded = unquote(value)

    def repl(match):
        key = match.group(1)
        if key in variables and variables[key] is not None:
            return str(variables[key])
        unresolved.append(key)
        return f"__UNRESOLVED__{key}__"

    resolved = PLACEHOLDER_RE.sub(repl, decoded)
    resolved = ENCODED_PLACEHOLDER_RE.sub(
        lambda m: repl(type("M", (), {"group": lambda _, i=m.group(1): i})()), resolved
    )
    resolved = re.sub(r"(?<!:)/{2,}", "/", resolved)
    return resolved, unresolved


def _fill_colon_params(path: str, param_values: Dict[str, str]) -> str:
    """Replace Express-style /:param with provided values or DEFAULT_PARAM_VALUE."""
    if not isinstance(path, str):
        return path

    def repl(m):
        key = m.group(1)
        val = param_values.get(key, DEFAULT_PARAM_VALUE)
        return f"/{val}"

    return COLON_PARAM_RE.sub(repl, path)

# --------------------- Minimal Collection Builder (needed by app.py) ---------------------

def build_minimal_postman_from_endpoints(endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a Postman v2.1 collection dict from a list of simple endpoint dicts like:
      {"method":"GET","url":"https://api.example.com/health","name":"GET /health","header":[...], "body": {...}}
    """
    items = []
    for ep in endpoints or []:
        method = (ep.get("method") or "GET").upper()
        url = ep.get("url") or ep.get("full_url")
        if not url:
            # allow "base + path" shape
            base = ep.get("base", "").rstrip("/")
            path = ep.get("path", "")
            url = f"{base}{path}"
        if not url:
            continue

        item = {
            "name": ep.get("name") or f"{method} {url}",
            "request": {
                "method": method,
                "url": url,
                "header": ep.get("header") or ep.get("headers") or [],
            },
        }
        body = ep.get("body")
        if isinstance(body, dict) and body:
            item["request"]["body"] = body
        items.append(item)

    return {
        "info": {
            "name": "Seeded Recon Collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }

# --------------------- Enhanced Parser ---------------------

class EnhancedPostmanParser:
    """
    Robust Postman collection parser:
      - Unwraps/export variants
      - Extracts & resolves variables
      - Produces endpoint dicts usable by the scanner
    """

    def __init__(self, ai_enabled: bool = False, environment: Optional[Dict[str, str]] = None):
        self.ai_enabled = ai_enabled and bool(openai)
        self.environment = environment or {}
        self.openai_client = None
        if self.ai_enabled:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                try:
                    self.openai_client = openai
                    logger.info("AI-enhanced parsing enabled")
                except Exception as e:
                    logger.warning(f"OpenAI init failed, disabling AI: {e}")
                    self.ai_enabled = False
            else:
                logger.warning("OpenAI API key not found. AI features disabled.")
                self.ai_enabled = False

        self.variables: Dict[str, str] = {}

    # ---------- public API ----------

    def parse_collection_robustly(self, collection_data: Dict) -> Dict:
        try:
            logger.info("Starting enhanced collection parsing...")
            actual_collection = self._unwrap_collection(collection_data)
            self.variables = self._gather_variables(actual_collection)

            analysis = {
                "collection_name": self._extract_collection_name(actual_collection),
                "collection_id": actual_collection.get("id", "unknown"),
                "endpoints": [],
                "auth_patterns": [],
                "parameter_patterns": {},
                "security_risks": [],
                "business_logic_flows": [],
                "data_schemas": {},
                "api_complexity_score": 0,
                "folders": [],
                "variables": self.variables,
                "events": self._extract_events(actual_collection),
            }

            raw_endpoints: List[Dict] = []
            self._extract_all_items(actual_collection, raw_endpoints)
            if not raw_endpoints:
                logger.warning("No endpoints found in collection")
                return analysis

            logger.info(f"Found {len(raw_endpoints)} raw endpoints")

            auth_patterns_set = set()
            for i, raw in enumerate(raw_endpoints):
                ep = self._analyze_endpoint_comprehensively(raw, i)
                if not ep:
                    continue
                ep["unresolved_placeholders"] = self._list_unresolved(ep["url"])
                ep["resolvable"] = (
                    len(ep["unresolved_placeholders"]) == 0
                    and ep["url"].startswith(("http://", "https://"))
                )
                analysis["endpoints"].append(ep)
                auth_type = ep.get("auth", {}).get("type", "none")
                auth_patterns_set.add(auth_type)
                for param in ep.get("url_params", {}):
                    analysis["parameter_patterns"][param] = (
                        analysis["parameter_patterns"].get(param, 0) + 1
                    )

            analysis["auth_patterns"] = list(auth_patterns_set)
            analysis["api_complexity_score"] = self._calculate_complexity_score(analysis)

            if self.ai_enabled and self.openai_client:
                analysis = self._enhance_with_ai(analysis)

            logger.info(
                f"Collection parsing complete: {len(analysis['endpoints'])} endpoints processed"
            )
            return analysis
        except Exception as e:
            logger.error(f"Collection parsing failed: {e}")
            return self._create_empty_analysis()

    # ---------- helpers ----------

    def _unwrap_collection(self, data: Dict) -> Dict:
        if "collection" in data:
            return data["collection"]
        for k in ["postman_collection", "data", "content"]:
            if k in data:
                return data[k]
        return data

    def _gather_variables(self, collection_data: Dict) -> Dict[str, str]:
        variables: Dict[str, str] = {}

        def add_vars(var_list: Any):
            if isinstance(var_list, list):
                for v in var_list:
                    if isinstance(v, dict):
                        k = v.get("key")
                        val = v.get("value")
                        if k:
                            variables[str(k)] = "" if val is None else str(val)

        add_vars(collection_data.get("variable", []))
        info = collection_data.get("info", {})
        if isinstance(info, dict):
            add_vars(info.get("variable", []))

        for k, v in (self.environment or {}).items():
            variables[str(k)] = "" if v is None else str(v)

        for k in list(variables.keys()):
            if not variables[k]:
                env_key = k.upper()
                if env_key in os.environ:
                    variables[k] = os.environ[env_key]

        return variables

    def _extract_all_items(self, data: Any, endpoints: List, folder_path: List[str] = None) -> None:
        if folder_path is None:
            folder_path = []

        items = []
        if isinstance(data, dict):
            if "item" in data:
                items = data["item"]
            elif "requests" in data:
                items = data["requests"]
            elif "children" in data:
                items = data["children"]
            elif "request" in data:
                items = [data]
        elif isinstance(data, list):
            items = data

        if not items:
            return

        for item in items:
            if not isinstance(item, dict):
                continue

            if "request" in item and item["request"]:
                entry = item.copy()
                entry["_folder_path"] = folder_path.copy()
                endpoints.append(entry)
            elif any(k in item for k in ["item", "children", "requests"]):
                folder_name = item.get("name", f"Folder_{len(folder_path)}")
                self._extract_all_items(item, endpoints, folder_path + [folder_name])

    def _analyze_endpoint_comprehensively(self, endpoint_item: Dict, index: int) -> Optional[Dict]:
        try:
            request = endpoint_item.get("request", {})
            if not request:
                return None

            name = endpoint_item.get("name", f"Endpoint_{index}")
            description = endpoint_item.get("description", "")
            folder_path = endpoint_item.get("_folder_path", [])

            url_info = self._parse_url_robustly(request.get("url"))
            method = str(request.get("method", "GET")).upper()

            headers = self._parse_headers(request.get("header", []))
            auth = self._parse_auth(request.get("auth", {}))
            body_info = self._parse_body(request.get("body", {}))
            events = self._parse_events(endpoint_item.get("event", []))

            security_implications = self._assess_security_implications(
                {
                    "url": url_info.get("full_url", ""),
                    "method": method,
                    "auth": auth,
                    "headers": headers,
                    "folder_path": folder_path,
                }
            )
            business_function = self._infer_business_function(
                name, url_info.get("full_url", ""), method
            )
            risk_score = self._calculate_endpoint_risk_score(
                {
                    "method": method,
                    "auth": auth,
                    "url": url_info.get("full_url", ""),
                    "security_implications": security_implications,
                }
            )

            return {
                "name": name,
                "description": description,
                "method": method,
                "url": url_info.get("full_url", ""),
                "protocol": url_info.get("protocol", "https"),
                "host": url_info.get("host", ""),
                "port": url_info.get("port", ""),
                "path": url_info.get("path", ""),
                "url_params": url_info.get("query_params", {}),
                "path_params": url_info.get("path_params", []),
                "headers": headers,
                "auth": auth,
                "body": body_info,
                "events": events,
                "folder_path": folder_path,
                "security_implications": security_implications,
                "business_function": business_function,
                "risk_score": risk_score,
                "complexity_indicators": self._get_complexity_indicators(
                    url_info, headers, body_info
                ),
            }
        except Exception as e:
            logger.error(f"Failed to analyze endpoint {index}: {e}")
            return None

    def _parse_url_robustly(self, url_data: Any) -> Dict:
        result = {
            "full_url": "",
            "protocol": "https",
            "host": "",
            "port": "",
            "path": "",
            "query_params": {},
            "path_params": [],
        }
        try:
            if isinstance(url_data, str):
                raw = url_data
                resolved, _ = _resolve_placeholders(raw, self.variables)
                resolved = _fill_colon_params(resolved, self.variables)
                parsed = urlparse(resolved)
                result.update(
                    {
                        "full_url": resolved,
                        "protocol": parsed.scheme or "https",
                        "host": parsed.netloc.split(":")[0],
                        "port": str(parsed.port or ""),
                        "path": parsed.path,
                        "query_params": {
                            k: v[0] if isinstance(v, list) else v
                            for k, v in parse_qs(parsed.query).items()
                        },
                    }
                )
            elif isinstance(url_data, dict):
                protocol = url_data.get("protocol", "https")
                host_parts = url_data.get("host", [])
                if isinstance(host_parts, list):
                    host = ".".join(str(p) for p in host_parts if p)
                else:
                    host = str(host_parts) if host_parts else ""

                path_parts = url_data.get("path", [])
                if isinstance(path_parts, list):
                    path = "/" + "/".join(str(p) for p in path_parts if p)
                else:
                    path = "/" + str(path_parts) if path_parts else "/"

                port = url_data.get("port", "")
                port_str = f":{port}" if port else ""

                query_params: Dict[str, str] = {}
                for q in url_data.get("query", []) or []:
                    if isinstance(q, dict) and not q.get("disabled", False):
                        k = q.get("key", "")
                        v = q.get("value", "")
                        if k:
                            query_params[str(k)] = "" if v is None else str(v)

                path_params = []
                for var in url_data.get("variable", []) or []:
                    if isinstance(var, dict):
                        k = var.get("key", "")
                        v = var.get("value", "")
                        if k:
                            path_params.append({"key": k, "value": v})

                query_string = ("?" + urlencode(query_params)) if query_params else ""
                full_url = f"{protocol}://{host}{port_str}{path}{query_string}"

                full_url, _ = _resolve_placeholders(full_url, self.variables)
                full_url = _fill_colon_params(full_url, self.variables)

                parsed = urlparse(full_url)
                result.update(
                    {
                        "full_url": full_url,
                        "protocol": parsed.scheme or protocol,
                        "host": parsed.netloc.split(":")[0],
                        "port": str(parsed.port or port or ""),
                        "path": parsed.path,
                        "query_params": {
                            k: v[0] if isinstance(v, list) else v
                            for k, v in parse_qs(parsed.query).items()
                        },
                        "path_params": path_params,
                    }
                )
        except Exception as e:
            logger.warning(f"URL parsing failed: {e}")
        return result

    def _parse_headers(self, headers_data: List) -> Dict:
        headers = {}
        if not isinstance(headers_data, list):
            return headers
        for header in headers_data:
            if isinstance(header, dict) and not header.get("disabled", False):
                k = header.get("key", "")
                v = header.get("value", "")
                if k:
                    val, _ = _resolve_placeholders(str(v or ""), self.variables)
                    headers[k] = val
        return headers

    def _parse_auth(self, auth_data: Dict) -> Dict:
        if not isinstance(auth_data, dict):
            return {"type": "none"}
        auth_type = auth_data.get("type", "none")
        result = {"type": auth_type}
        if auth_type != "none" and auth_type in auth_data:
            details = auth_data.get(auth_type, [])
            if isinstance(details, list):
                for d in details:
                    if isinstance(d, dict):
                        k = d.get("key", "")
                        v = d.get("value", "")
                        if k:
                            val, _ = _resolve_placeholders(str(v or ""), self.variables)
                            result[k] = val
        return result

    def _parse_body(self, body_data: Dict) -> Dict:
        if not isinstance(body_data, dict):
            return {"mode": "none"}
        mode = body_data.get("mode", "none")
        result = {"mode": mode}
        if mode == "raw":
            raw = body_data.get("raw", "")
            resolved, _ = _resolve_placeholders(str(raw or ""), self.variables)
            result["content"] = resolved
            result["content_type"] = "application/json"
        elif mode == "formdata":
            form = []
            for f in body_data.get("formdata", []) or []:
                if isinstance(f, dict) and not f.get("disabled", False):
                    key = f.get("key", "")
                    val = f.get("value", "")
                    if key:
                        r, _ = _resolve_placeholders(str(val or ""), self.variables)
                        form.append({"key": key, "value": r})
            result["form_data"] = form
        elif mode == "urlencoded":
            fields = []
            for f in body_data.get("urlencoded", []) or []:
                if isinstance(f, dict) and not f.get("disabled", False):
                    key = f.get("key", "")
                    val = f.get("value", "")
                    if key:
                        r, _ = _resolve_placeholders(str(val or ""), self.variables)
                        fields.append({"key": key, "value": r})
            result["urlencoded"] = fields
        elif mode == "file":
            result["file"] = body_data.get("file", {})
        return result

    def _parse_events(self, events_data: List) -> Dict:
        events = {"prerequest": [], "test": []}
        if not isinstance(events_data, list):
            return events
        for event in events_data:
            if isinstance(event, dict):
                listen = event.get("listen", "")
                script = event.get("script", {})
                if listen in events and isinstance(script, dict):
                    exec_lines = script.get("exec", [])
                    if isinstance(exec_lines, list):
                        events[listen] = exec_lines
        return events

    def _list_unresolved(self, url: str) -> List[str]:
        if not isinstance(url, str):
            return []
        unresolved = [m.group(1) for m in PLACEHOLDER_RE.finditer(url)]
        unresolved += [m.group(1) for m in ENCODED_PLACEHOLDER_RE.finditer(url)]
        unresolved += [m.group(1) for m in COLON_PARAM_RE.finditer(url)]
        return sorted(set(unresolved))

    # ---- scoring / insights ----

    def _assess_security_implications(self, endpoint_data: Dict) -> List[str]:
        implications = []
        method = endpoint_data.get("method", "").upper()
        url = endpoint_data.get("url", "").lower()
        auth = endpoint_data.get("auth", {})
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            implications.append("State-changing operation")
        if any(k in url for k in ["admin", "manage", "config"]):
            implications.append("Administrative function")
        if any(k in url for k in ["user", "profile", "account"]):
            implications.append("User data access")
        if any(k in url for k in ["password", "secret", "key", "token"]):
            implications.append("Sensitive data handling")
        if any(k in url for k in ["payment", "billing", "transaction"]):
            implications.append("Financial operation")
        if auth.get("type") == "none":
            implications.append("No authentication required")
        elif auth.get("type") in ["basic", "digest"]:
            implications.append("Basic authentication")
        elif auth.get("type") in ["bearer", "oauth2"]:
            implications.append("Token-based authentication")
        return implications

    def _infer_business_function(self, name: str, url: str, method: str) -> str:
        n, u = name.lower(), url.lower()
        if any(k in n or k in u for k in ["doctor", "patient", "medical", "health", "prescription", "diagnosis"]):
            return "Healthcare & Medical Services"
        elif any(k in n or k in u for k in ["pharmacy", "medicine", "drug", "prescription"]):
            return "Pharmacy Services"
        elif any(k in n or k in u for k in ["payment", "billing", "transaction", "fund", "transfer"]):
            return "Financial Operations"
        elif any(k in n or k in u for k in ["auth", "login", "signin", "signup", "register", "token"]):
            return "Authentication & Authorization"
        elif any(k in n or k in u for k in ["job", "workflow", "execute", "trigger"]):
            return "Workflow & Job Management"
        elif any(k in n or k in u for k in ["recon", "reconcile", "aggregation"]):
            return "Data Reconciliation"
        elif any(k in n or k in u for k in ["admin", "manage", "config", "setting"]):
            return "Administrative Functions"
        else:
            return "General API Operation"

    def _calculate_endpoint_risk_score(self, endpoint_data: Dict) -> int:
        score = 1
        method = endpoint_data.get("method", "")
        auth = endpoint_data.get("auth", {})
        url = endpoint_data.get("url", "").lower()
        implications = endpoint_data.get("security_implications", [])
        if method in ["POST", "PUT", "PATCH"]:
            score += 2
        elif method == "DELETE":
            score += 3
        if auth.get("type") == "none":
            score += 2
        elif auth.get("type") in ["basic", "digest"]:
            score += 1
        if any(k in url for k in ["admin", "manage", "config"]):
            score += 3
        if any(k in url for k in ["password", "secret", "key"]):
            score += 2
        if any(k in url for k in ["payment", "billing"]):
            score += 2
        score += len(
            [imp for imp in implications if any(k in imp.lower() for k in ["admin", "sensitive", "financial"])]
        )
        return min(score, 10)

    def _get_complexity_indicators(self, url_info: Dict, headers: Dict, body_info: Dict) -> Dict:
        return {
            "has_query_params": bool(url_info.get("query_params")),
            "has_path_params": bool(url_info.get("path_params")),
            "has_custom_headers": any(h.lower() not in ["content-type", "accept", "user-agent"] for h in headers.keys()),
            "has_body": body_info.get("mode", "none") != "none",
            "auth_required": bool(headers.get("Authorization") or headers.get("x-app-token")),
        }

    def _calculate_complexity_score(self, analysis: Dict) -> int:
        base = len(analysis["endpoints"])
        auth_variety = len(analysis["auth_patterns"])
        param_variety = len(analysis["parameter_patterns"])
        bonus = sum(
            sum(1 for v in ep.get("complexity_indicators", {}).values() if v)
            for ep in analysis["endpoints"]
        )
        return base + (auth_variety * 2) + param_variety + bonus

    def _extract_collection_name(self, collection_data: Dict) -> str:
        info = collection_data.get("info", {})
        if isinstance(info, dict):
            return info.get("name", "Unknown Collection")
        return collection_data.get("name", "Unknown Collection")

    def _extract_events(self, collection_data: Dict) -> Dict:
        events = {"prerequest": [], "test": []}
        for event in collection_data.get("event", []) or []:
            if isinstance(event, dict):
                listen = event.get("listen", "")
                script = event.get("script", {})
                if listen in events and isinstance(script, dict):
                    exec_lines = script.get("exec", [])
                    if isinstance(exec_lines, list):
                        events[listen] = exec_lines
        return events

    def _create_empty_analysis(self) -> Dict:
        return {
            "collection_name": "Failed Collection",
            "collection_id": "unknown",
            "endpoints": [],
            "auth_patterns": [],
            "parameter_patterns": {},
            "security_risks": [],
            "business_logic_flows": [],
            "data_schemas": {},
            "api_complexity_score": 0,
            "folders": [],
            "variables": {},
            "events": {"prerequest": [], "test": []},
        }

    def _enhance_with_ai(self, analysis: Dict) -> Dict:
        # Stub for future AI-based enrichment
        return analysis

# --------------------- Integration (adds legacy API expected by app.py) ---------------------

class PostmanIntegration:
    """
    Postman integration with variable resolution + safe skipping of unresolved endpoints.

    Provides both:
      - Newer high-level 'run_security_scan'
      - Legacy shims: 'parse_collection' and 'run_scan_from_endpoints'
    """

    def __init__(self, scanner, ai_enabled: bool = False, environment: Optional[Dict[str, str]] = None):
        self.scanner = scanner
        self.parser = EnhancedPostmanParser(ai_enabled=ai_enabled, environment=environment)
        self.logger = logging.getLogger(__name__)

    # ---- Legacy shim used by app.py ----
    def parse_collection(self, collection_path: str, selected_folders: Optional[List[str]] = None, variables: Optional[Dict[str, str]] = None) -> List[Dict]:
        """
        Load a Postman collection file and return a list of fully-resolved endpoints suitable for scanning.
        Honors 'selected_folders' filtering and skips endpoints with unresolved placeholders.
        """
        # If variables are passed at call-time, refresh parser with those env vars
        if variables is not None:
            self.parser.environment = variables

        with open(collection_path, "r", encoding="utf-8") as f:
            collection_data = json.load(f)

        analysis = self.parser.parse_collection_robustly(collection_data)
        endpoints = []
        for ep in analysis.get("endpoints", []):
            # Folder filter
            if selected_folders and ep.get("folder_path"):
                if not any(f in ep["folder_path"] for f in selected_folders):
                    continue
            # Skip unresolved placeholders to avoid DNS/name resolution failures
            if not ep.get("resolvable", False):
                self.logger.info(
                    f"Skipping unresolved endpoint {ep.get('method')} {ep.get('url')} "
                    f"(unresolved: {ep.get('unresolved_placeholders')})"
                )
                continue
            endpoints.append(ep)
        return endpoints

    # ---- Legacy shim used by app.py ----
    def run_scan_from_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """
        Run the scanner on a list of endpoints (output of 'parse_collection').
        Returns a flat list of vulnerability dicts.
        """
        all_vulns: List[Dict] = []
        successful = failed = 0

        for i, ep in enumerate(endpoints, 1):
            try:
                url = ep["url"]
                method = ep["method"]
                self.logger.info(f"Scanning {i}/{len(endpoints)}: {method} {url}")
                vulns = self.scanner.scan_endpoint(
                    url,
                    method,
                    headers=ep.get("headers", {}),
                    data=self._prepare_scan_data(ep),
                )
                for v in (vulns or []):
                    vdict = v.to_dict() if hasattr(v, "to_dict") else v
                    vdict["endpoint_name"] = ep.get("name", "")
                    vdict["business_function"] = ep.get("business_function", "")
                    vdict["folder_path"] = ep.get("folder_path", [])
                    all_vulns.append(vdict)
                successful += 1
            except Exception as e:
                self.logger.error(f"Failed to scan endpoint {ep.get('name','')} ({ep.get('method')} {ep.get('url')}): {e}")
                failed += 1

        self.logger.info(f"Scan complete: {successful} successful, {failed} failed")
        self.logger.info(f"Total vulnerabilities found: {len(all_vulns)}")
        return all_vulns

    # ---- Existing high-level API (still supported) ----
    def run_security_scan(self, collection_path: str, selected_folders: Optional[List[str]] = None) -> List[Dict]:
        try:
            self.logger.info(f"Starting Postman collection scan: {collection_path}")
            with open(collection_path, "r", encoding="utf-8") as f:
                collection_data = json.load(f)

            analysis = self.parser.parse_collection_robustly(collection_data)
            endpoints = analysis.get("endpoints", [])
            if not endpoints:
                self.logger.warning("No valid endpoints found in collection")
                return []

            self.logger.info(f"Found {len(endpoints)} endpoints to evaluate")
            return self.run_scan_from_endpoints(
                [
                    ep
                    for ep in endpoints
                    if (not selected_folders or not ep.get("folder_path") or any(f in ep["folder_path"] for f in selected_folders))
                    and ep.get("resolvable", False)
                ]
            )
        except Exception as e:
            self.logger.error(f"Postman integration failed: {e}")
            return []

    def _prepare_scan_data(self, endpoint: Dict) -> Dict:
        scan_data: Dict[str, Any] = {}
        if endpoint.get("url_params"):
            scan_data.update(endpoint["url_params"])

        body = endpoint.get("body", {})
        mode = body.get("mode")
        if mode == "raw":
            raw = body.get("content", "")
            try:
                scan_data.update(json.loads(raw))
            except Exception:
                scan_data["raw_body"] = raw
        elif mode == "formdata":
            for field in body.get("form_data", []):
                if isinstance(field, dict):
                    k, v = field.get("key", ""), field.get("value", "")
                    if k:
                        scan_data[k] = v
        elif mode == "urlencoded":
            for field in body.get("urlencoded", []):
                if isinstance(field, dict):
                    k, v = field.get("key", ""), field.get("value", "")
                    if k:
                        scan_data[k] = v
        return scan_data

    def get_collection_analysis(self, collection_path: str) -> Dict:
        try:
            with open(collection_path, "r", encoding="utf-8") as f:
                collection_data = json.load(f)
            return self.parser.parse_collection_robustly(collection_data)
        except Exception as e:
            self.logger.error(f"Collection analysis failed: {e}")
            return self.parser._create_empty_analysis()

