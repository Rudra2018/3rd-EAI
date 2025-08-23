#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced PDF API Parser with optional AI integration.

- Extracts API endpoints from PDF documentation using multiple regex strategies.
- (Optionally) enriches with lightweight NLP if NLTK is available.
- Can build a Postman collection from discovered endpoints.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# -------------------------
# Optional Dependencies
# -------------------------
# PDF processing – PyMuPDF
try:
    import fitz  # PyMuPDF
    PDF_AVAILABLE = True
except Exception:  # pragma: no cover
    PDF_AVAILABLE = False

# AI integration (optional; your project can supply these)
AI_AVAILABLE = False
try:
    # Example expected interface if present in your repo:
    # from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    # AI_AVAILABLE = True
    pass
except Exception:
    AI_AVAILABLE = False

# NLP for advanced tokenization (optional)
NLP_AVAILABLE = False
try:
    import nltk  # noqa: F401
    from nltk.tokenize import sent_tokenize  # noqa: F401
    NLP_AVAILABLE = True
except Exception:
    NLP_AVAILABLE = False


# -------------------------
# Dataclasses
# -------------------------
@dataclass
class APIEndpointInfo:
    method: str
    url: str
    description: Optional[str] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    response_format: Optional[Dict[str, Any]] = None
    authentication: Optional[str] = None
    rate_limiting: Optional[str] = None
    examples: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    source_page: int = 0


# -------------------------
# Parser
# -------------------------
class EnhancedPDFAPIParser:
    """
    Advanced PDF API documentation parser with optional AI assistance.

    Features:
    - Multi-pattern endpoint detection
    - Parameter extraction (path/query/body)
    - Authentication & rate limit hints
    - Example snippet harvesting
    - Postman collection builder
    """

    def __init__(self) -> None:
        # Regex patterns for endpoints
        self.endpoint_patterns: Dict[str, re.Pattern] = {
            # e.g., GET /api/v1/users or POST https://api.example.com/v1/auth
            "standard": re.compile(
                r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+"
                r"(https?://[^\s\"'<>]+|/[A-Za-z0-9_\-./{}:@]+)",
                re.IGNORECASE,
            ),
            # e.g., curl -X POST "https://api.example.com/auth"
            "curl_command": re.compile(
                r"\bcurl\s+(?:-X\s+)?(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)?\s*"
                r"['\"]?(https?://[^\s\"'<>]+|/[A-Za-z0-9_\-./{}:@]+)['\"]?",
                re.IGNORECASE,
            ),
            # e.g., method in JSON-RPC payloads
            "json_rpc": re.compile(r'"method"\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE),
            # GraphQL operation name (less useful but indicative)
            "graphql": re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)", re.IGNORECASE),
            # e.g., GET /users — Fetch users
            "rest_description": re.compile(
                r"\b(GET|POST|PUT|PATCH|DELETE)\s+([A-Za-z0-9_\-./{}:@]+)\s*[-–—]\s*(.{1,200})",
                re.IGNORECASE,
            ),
        }

        # Parameter patterns
        self.param_patterns: Dict[str, re.Pattern] = {
            "path_param": re.compile(r"\{([^}]+)\}"),
            "query_param": re.compile(r"[?&]([a-zA-Z0-9_]+)="),
            "header_param": re.compile(r"(^|\n)([A-Za-z\-]+):\s*([^\r\n]+)", re.MULTILINE),
            "json_field": re.compile(r'"([a-zA-Z0-9_]+)"\s*:\s*([^,\r\n}]+)'),
        }

        # Authentication patterns
        self.auth_patterns: Dict[str, re.Pattern] = {
            "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
            "api_key": re.compile(r"\b(API[_\s-]?Key|X-API-KEY|apikey)\b", re.IGNORECASE),
            "basic_auth": re.compile(r"Basic\s+[A-Za-z0-9+/=]+", re.IGNORECASE),
            "oauth": re.compile(r"\bOAuth\b|oauth_token|client_id", re.IGNORECASE),
        }

        # Optional AI coordinator handle (if your project provides one)
        self.ai_coordinator = None
        if AI_AVAILABLE:
            try:
                # self.ai_coordinator = AdvancedAICoordinator()
                pass
            except Exception as e:  # pragma: no cover
                log.warning(f"AI coordinator initialization failed: {e}")

    # -------------------------
    # Public API
    # -------------------------
    def parse_pdf_to_endpoints(self, pdf_path: str, base_url: Optional[str] = None) -> List[APIEndpointInfo]:
        """Parse a PDF file and return a list of APIEndpointInfo objects."""
        if not PDF_AVAILABLE:
            raise RuntimeError("PyMuPDF not installed. Install with: pip install pymupdf")

        try:
            doc_text, page_texts = self._extract_text_with_pages(pdf_path)
            endpoints = self._extract_endpoints_by_patterns(doc_text, page_texts)

            # Optionally, an AI pass could be added here if you wire in your coordinator
            # if self.ai_coordinator and len(endpoints) < 5:
            #     endpoints.extend(self._ai_extract_endpoints_sync(doc_text[:10000]))

            endpoints = self._enhance_endpoints_with_context(endpoints, doc_text)

            if base_url:
                endpoints = self._apply_base_url(endpoints, base_url)

            final_endpoints = self._deduplicate_and_score(endpoints)
            log.info("📄 Extracted %d API endpoints from PDF", len(final_endpoints))
            return final_endpoints
        except Exception as e:
            log.error("PDF parsing failed: %s", e)
            return []

    def build_postman_collection_from_pdf(self, pdf_path: str, base_url: Optional[str] = None) -> Dict[str, Any]:
        """Build a Postman collection dictionary from extracted endpoints."""
        endpoints = self.parse_pdf_to_endpoints(pdf_path, base_url)
        items: List[Dict[str, Any]] = []

        for ep in endpoints:
            request: Dict[str, Any] = {
                "method": ep.method.upper(),
                "url": ep.url,
                "header": [],
            }

            # Authentication hints
            if ep.authentication:
                if "Bearer" in ep.authentication:
                    request["header"].append({"key": "Authorization", "value": "Bearer {{token}}", "type": "text"})
                elif "API Key" in ep.authentication:
                    request["header"].append({"key": "X-API-Key", "value": "{{api_key}}", "type": "text"})

            # Simple body assembly for non-GET
            if ep.method.upper() in {"POST", "PUT", "PATCH"}:
                body_params = [p for p in (ep.parameters or []) if p.get("type") == "body"]
                if body_params:
                    body_object = {param["name"]: param.get("example", "") for param in body_params}
                    request["body"] = {
                        "mode": "raw",
                        "raw": json.dumps(body_object, indent=2),
                        "options": {"raw": {"language": "json"}},
                    }

            item: Dict[str, Any] = {"name": ep.description or f"{ep.method} {ep.url}", "request": request}

            meta_lines = [
                f"// Source: PDF page {ep.source_page}",
                f"// Confidence: {ep.confidence_score:.2f}",
            ]
            if ep.description:
                meta_lines.insert(0, f"// {ep.description}")

            item["event"] = [{
                "listen": "prerequest",
                "script": {"exec": meta_lines},
            }]

            items.append(item)

        collection: Dict[str, Any] = {
            "info": {
                "name": f"PDF-derived API Collection - {os.path.basename(pdf_path)}",
                "description": f"API endpoints extracted from {pdf_path} using enhanced parsing",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                "_postman_id": f"pdf-{abs(hash(pdf_path)) % 1_000_000}",
                "version": {"major": 1, "minor": 0, "patch": 0},
            },
            "item": items,
            "variable": [
                {"key": "base_url", "value": base_url or "https://api.example.com", "type": "string"},
                {"key": "api_key", "value": "your-api-key-here", "type": "string"},
                {"key": "token", "value": "your-bearer-token-here", "type": "string"},
            ],
        }
        return collection

    def get_extraction_statistics(self, endpoints: List[APIEndpointInfo]) -> Dict[str, Any]:
        """Compute simple statistics over extracted endpoints."""
        if not endpoints:
            return {"total_endpoints": 0}

        stats: Dict[str, Any] = {
            "total_endpoints": len(endpoints),
            "methods_distribution": {},
            "authentication_methods": {},
            "avg_confidence": 0.0,
            "endpoints_with_parameters": 0,
            "endpoints_with_examples": 0,
            "endpoints_with_auth": 0,
            "pages_covered": 0,
        }

        pages = set()
        conf_sum = 0.0

        for ep in endpoints:
            m = ep.method.upper()
            stats["methods_distribution"][m] = stats["methods_distribution"].get(m, 0) + 1

            if ep.authentication:
                a = ep.authentication
                stats["authentication_methods"][a] = stats["authentication_methods"].get(a, 0) + 1
                stats["endpoints_with_auth"] += 1

            if ep.parameters:
                stats["endpoints_with_parameters"] += 1
            if ep.examples:
                stats["endpoints_with_examples"] += 1

            conf_sum += ep.confidence_score
            pages.add(ep.source_page)

        stats["avg_confidence"] = conf_sum / len(endpoints)
        stats["pages_covered"] = len(pages)
        return stats

    # -------------------------
    # Internals
    # -------------------------
    def _extract_text_with_pages(self, pdf_path: str) -> Tuple[str, List[Tuple[int, str]]]:
        """Extract full text and per-page text from a PDF."""
        doc = fitz.open(pdf_path)
        all_text_parts: List[str] = []
        page_texts: List[Tuple[int, str]] = []

        try:
            for i in range(len(doc)):
                page = doc.load_page(i)
                text = page.get_text("text") or ""
                page_no = i + 1
                all_text_parts.append(f"\n--- PAGE {page_no} ---\n{text}")
                page_texts.append((page_no, text))
        finally:
            doc.close()

        return "".join(all_text_parts), page_texts

    def _extract_endpoints_by_patterns(self, doc_text: str, page_texts: List[Tuple[int, str]]) -> List[APIEndpointInfo]:
        """Apply multiple extraction strategies over each page."""
        endpoints: List[APIEndpointInfo] = []

        for page_num, text in page_texts:
            # Standard + curl + description variants
            for name, pattern in self.endpoint_patterns.items():
                try:
                    matches = pattern.findall(text)
                except re.error as rex:
                    log.debug("Regex %s failed on page %d: %s", name, page_num, rex)
                    continue

                for match in matches:
                    method: str = "GET"
                    url: str = ""
                    desc: Optional[str] = None

                    if name == "rest_description":
                        # (METHOD, path, description)
                        # example: GET /users — Fetch users
                        if isinstance(match, tuple) and len(match) >= 3:
                            method = str(match[0]).upper()
                            url = str(match[1])
                            desc = str(match[2]).strip()
                    elif name in ("standard",):
                        # (METHOD, URL_OR_PATH)
                        if isinstance(match, tuple) and len(match) >= 2:
                            method = str(match[0]).upper()
                            url = str(match[1])
                    elif name == "curl_command":
                        # (METHOD?, URL)
                        # method may be empty in curl commands; default GET
                        if isinstance(match, tuple) and len(match) >= 2:
                            if match[0]:
                                method = str(match[0]).upper()
                            url = str(match[1])
                    elif name == "json_rpc":
                        # JSON-RPC "method" is not an HTTP endpoint; skip creating URL
                        # but can be used as a hint if we find /rpc or similar around.
                        continue
                    elif name == "graphql":
                        # Not a concrete URL, but note presence might guide context scoring.
                        continue
                    else:
                        # Fallback: direct string match
                        if isinstance(match, str):
                            url = match

                    if not url:
                        continue

                    if self._is_valid_endpoint(url):
                        endpoints.append(
                            APIEndpointInfo(
                                method=method,
                                url=url,
                                description=desc,
                                source_page=page_num,
                                confidence_score=self._calculate_pattern_confidence(name, url),
                            )
                        )

        return endpoints

    def _is_valid_endpoint(self, url: str) -> bool:
        """Heuristic validity check for candidate API endpoints."""
        if not url or len(url) < 2:
            return False

        u = url.strip().lower()

        # Disallow obvious non-API assets
        if any(ext in u for ext in (".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".pdf", ".svg", ".ico")):
            return False
        if u.startswith(("mailto:", "tel:", "ftp://")):
            return False

        # Looks like a path that could be API-ish
        api_indicators = ("/api/", "/v1/", "/v2/", "/rest/", "/graphql", ".json", "/auth", "/users")
        if url.startswith("/") or any(ind in u for ind in api_indicators):
            return True

        # Full URLs should contain a dot and not be excessively long
        if u.startswith(("http://", "https://")) and "." in u and len(u) < 300:
            return True

        return False

    def _calculate_pattern_confidence(self, pattern_name: str, url: str) -> float:
        base = {
            "standard": 0.90,
            "curl_command": 0.80,
            "rest_description": 0.75,
            "json_rpc": 0.50,
            "graphql": 0.60,
        }.get(pattern_name, 0.50)

        u = url.lower()
        if "/api/" in u:
            base += 0.10
        if any(v in u for v in ("/v1/", "/v2/", "/v3/")):
            base += 0.10
        if url.count("/") > 2:
            base += 0.05
        return min(base, 1.0)

    def _enhance_endpoints_with_context(self, endpoints: List[APIEndpointInfo], doc_text: str) -> List[APIEndpointInfo]:
        """Extract parameters/auth/examples/rate-limits using windowed context."""
        enhanced: List[APIEndpointInfo] = []

        for ep in endpoints:
            context = self._find_endpoint_context(ep.url, doc_text, context_size=600)

            # Parameters
            ep.parameters = self._extract_parameters(context, ep.url)

            # Authentication
            auth = self._extract_authentication(context)
            if auth:
                ep.authentication = auth

            # Examples (curl/JSON)
            ep.examples = self._extract_examples(context)

            # Rate limiting
            rate = self._extract_rate_limiting(context)
            if rate:
                ep.rate_limiting = rate

            enhanced.append(ep)

        return enhanced

    def _find_endpoint_context(self, url: str, doc_text: str, context_size: int = 500) -> str:
        pos = doc_text.find(url)
        if pos == -1:
            return ""
        start = max(0, pos - context_size)
        end = min(len(doc_text), pos + len(url) + context_size)
        return doc_text[start:end]

    def _extract_parameters(self, context: str, url: str) -> List[Dict[str, Any]]:
        params: List[Dict[str, Any]] = []

        # Path params
        for p in self.param_patterns["path_param"].findall(url):
            params.append(
                {"name": p, "type": "path", "required": True, "description": f"Path parameter: {p}"}
            )

        # Query params
        for q in self.param_patterns["query_param"].findall(context):
            if q not in (p["name"] for p in params):
                params.append(
                    {"name": q, "type": "query", "required": False, "description": f"Query parameter: {q}"}
                )

        # JSON body fields (best-effort)
        for field_name, field_value in self.param_patterns["json_field"].findall(context):
            if field_name not in (p["name"] for p in params):
                example = field_value.strip().strip('"\'')
                params.append(
                    {
                        "name": field_name,
                        "type": "body",
                        "required": False,
                        "description": f"JSON field: {field_name}",
                        "example": example,
                    }
                )

        return params

    def _extract_authentication(self, context: str) -> Optional[str]:
        ctx = context or ""
        ctx_lower = ctx.lower()

        if self.auth_patterns["bearer_token"].search(ctx):
            return "Bearer Token"
        if self.auth_patterns["api_key"].search(ctx):
            return "API Key"
        if self.auth_patterns["basic_auth"].search(ctx):
            return "Basic Auth"
        if self.auth_patterns["oauth"].search(ctx):
            return "OAuth"

        # Generic keywords
        if any(k in ctx_lower for k in ("authentication", "authorization", "token", "api key", "client_id")):
            return "Authentication Required"
        return None

    def _extract_examples(self, context: str) -> List[str]:
        examples: List[str] = []
        if not context:
            return examples

        # Curl commands (greedy until a blank line or line that doesn't start with space/dash)
        curl_re = re.compile(r"\bcurl\s+.*?(?=\n\S|\n\n|\Z)", re.IGNORECASE | re.DOTALL)
        examples.extend([m.strip() for m in curl_re.findall(context)])

        # JSON blobs (best-effort validation)
        json_re = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)
        for candidate in json_re.findall(context):
            try:
                json.loads(candidate)
                examples.append(candidate.strip())
            except Exception:
                continue

        # Limit to 3 to keep collection tidy
        return examples[:3]

    def _extract_rate_limiting(self, context: str) -> Optional[str]:
        if not context:
            return None

        rate_patterns = [
            r"\b(\d+)\s+requests?\s+per\s+(minute|hour|day|second)\b",
            r"\brate\s*limit[^.]*?(\d+[^.]*(?:per|/)[^.]*(?:minute|hour|day|second))",
            r"\blimit[^.]*?(\d+[^.]*(?:per|/)[^.]*(?:minute|hour|day|second))",
        ]

        for pat in rate_patterns:
            m = re.search(pat, context, re.IGNORECASE)
            if m:
                # Return the matched phrase
                return m.group(0).strip()
        return None

    def _apply_base_url(self, endpoints: List[APIEndpointInfo], base_url: str) -> List[APIEndpointInfo]:
        base = (base_url or "").rstrip("/")
        if not base:
            return endpoints

        for ep in endpoints:
            if ep.url.startswith("/") and not ep.url.startswith("//"):
                ep.url = base + ep.url
        return endpoints

    def _deduplicate_and_score(self, endpoints: List[APIEndpointInfo]) -> List[APIEndpointInfo]:
        seen: Dict[Tuple[str, str], APIEndpointInfo] = {}
        for ep in endpoints:
            key = (ep.method.upper(), ep.url)
            if key in seen:
                if ep.confidence_score > seen[key].confidence_score:
                    seen[key] = ep
            else:
                seen[key] = ep
        return sorted(seen.values(), key=lambda e: e.confidence_score, reverse=True)


# -------------------------
# CLI Usage (manual test)
# -------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    parser = EnhancedPDFAPIParser()

    pdf_path = "api_documentation.pdf"  # replace with actual path
    base_url = "https://api.example.com"

    if os.path.exists(pdf_path):
        eps = parser.parse_pdf_to_endpoints(pdf_path, base_url)
        print(f"Extracted {len(eps)} endpoints")
        for i, ep in enumerate(eps[:3], 1):
            print(f"{i}. {ep.method} {ep.url} (p.{ep.source_page}, conf={ep.confidence_score:.2f})")

        collection = parser.build_postman_collection_from_pdf(pdf_path, base_url)
        out = "extracted_api_collection.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(collection, f, indent=2)
        print(f"Saved Postman collection: {out}")

        stats = parser.get_extraction_statistics(eps)
        print("Stats:", json.dumps(stats, indent=2))
    else:
        print("PDF file not found. Please provide a valid PDF path.")

