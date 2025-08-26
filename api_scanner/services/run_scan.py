"""
Unified scan runner that:
- Ingests API spec (OpenAPI/Postman/GraphQL) where possible
- Calls the appropriate scanner
- Returns a normalized list of raw findings
"""

from typing import Dict, Any, List
from importers.openapi_parser import parse_openapi
from importers.postman_parser import parse_postman
from importers.graphql_importer import parse_graphql
from scanners.rest_scanner import run_rest_scan
from scanners.graphql_scanner import run_graphql_scan

# TODO hooks: run_grpc_scan, run_ws_scan, etc.


async def run_program_scan(target: Dict[str, Any], mode: str = "incremental") -> List[Dict[str, Any]]:
    findings_all: List[Dict[str, Any]] = []
    for scope in target["scopes"]:
        url = scope["url"]
        kind = (scope.get("kind") or "rest").lower()

        spec = {}
        try:
            if kind == "graphql":
                spec = await parse_graphql(url) or {}
            else:
                spec = await parse_openapi(url) or {}
                if not spec:
                    spec = await parse_postman(url) or {}
        except Exception:
            spec = {}

        if kind == "graphql":
            f = await run_graphql_scan(url, spec, mode=mode)
        elif kind == "rest":
            f = await run_rest_scan(url, spec, mode=mode)
        else:
            f = []  # stubs for grpc/ws can be added later

        for item in f:
            item.update({
                "program": target["program"],
                "platform": target["platform"],
                "scope_url": url
            })
        findings_all.extend(f)

    return findings_all

