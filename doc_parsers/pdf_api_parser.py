# doc_parsers/pdf_api_parser.py
import re
import json
import logging

try:
    import fitz  # PyMuPDF (fast, reliable)
except Exception:
    fitz = None

logger = logging.getLogger(__name__)

ENDPOINT_RE = re.compile(
    r"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(https?://[^\s\"'<>]+|/[A-Za-z0-9_\-./{}:]+)",
    re.IGNORECASE
)
GRAPHQL_HINT = re.compile(r"\bgraphql\b", re.IGNORECASE)

def _extract_text(path):
    if not fitz:
        raise RuntimeError("PyMuPDF not installed. pip install pymupdf")
    doc = fitz.open(path)
    texts = []
    for p in doc:
        texts.append(p.get_text())
    return "\n".join(texts)

def parse_pdf_to_endpoints(pdf_path):
    text = _extract_text(pdf_path)
    endpoints = []
    for m in ENDPOINT_RE.finditer(text):
        method = m.group(1).upper()
        url = m.group(2)
        # normalize base if relative
        if url.startswith("/"):
            url = "https://example.com" + url  # placeholder, caller should rewrite base
        endpoints.append({"name": f"{method} {url}", "method": method, "url": url})

    # GraphQL?
    has_gql = bool(GRAPHQL_HINT.search(text))
    if has_gql and not any("/graphql" in ep["url"].lower() for ep in endpoints):
        endpoints.append({"name": "POST /graphql", "method": "POST", "url": "https://example.com/graphql"})

    # dedupe by method+url
    seen = set(); uniq = []
    for ep in endpoints:
        key = (ep["method"], ep["url"])
        if key in seen: continue
        seen.add(key); uniq.append(ep)
    return uniq

def build_postman_collection_from_pdf(pdf_path, base_override=None):
    eps = parse_pdf_to_endpoints(pdf_path)
    if base_override:
        # rewrite host for relative placeholders
        for ep in eps:
            if "example.com" in ep["url"]:
                ep["url"] = ep["url"].replace("https://example.com", base_override.rstrip("/"))
    items = []
    for ep in eps:
        items.append({
            "name": ep["name"],
            "request": {"method": ep["method"], "url": ep["url"], "header": []}
        })
    return {
        "info": {"name": "Rudra PDF-derived Collection", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items
    }

