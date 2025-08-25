#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Postman Collection Parser with complete parsing and variable resolution.
"""

import json
import asyncio
import logging
from typing import Dict, List, Any, Optional

log = logging.getLogger(__name__)

class EnhancedPostmanParser:
    def __init__(self, *args, **kwargs):
        # Tolerate unknown kwargs passed by app.py wiring
        self.ai_enabled = bool(kwargs.get("ai_enabled", False))

    async def parse_collection(self, collection_data: Dict[str, Any], variables: Dict[str, str] = None) -> Dict[str, Any]:
        variables = variables or {}
        items = collection_data.get("item", [])

        parsed_items = []
        for idx, item in enumerate(items):
            parsed = await self._parse_item(item, variables, [])
            if parsed is not None:
                parsed_items.append(parsed)

        return {
            "collection_name": collection_data.get("info", {}).get("name", "Unnamed Collection"),
            "endpoints": parsed_items,
            "api_complexity_score": len(parsed_items),
            "ai_insights": {}
        }

    async def _parse_item(self, item: Dict[str, Any], variables: Dict[str, str], folder_path: List[str]) -> Optional[Dict[str, Any]]:
        try:
            if 'item' in item:
                # Folder
                current_path = folder_path + [item.get("name", "Unnamed Folder")]
                children = []
                for child in item.get('item', []):
                    parsed_child = await self._parse_item(child, variables, current_path)
                    if parsed_child is not None:
                        children.append(parsed_child)
                return {
                    "folderName": item.get('name'),
                    "folderPath": current_path,
                    "children": children
                }
            else:
                # Request
                request = item.get("request", {})
                if not request:
                    return None

                name = item.get("name", "Unnamed Request")
                description = item.get("description", "")
                folder_path_safe = folder_path

                url = self._resolve_url(request.get("url", {}), variables)
                method = request.get("method", "GET").upper()
                headers = self._resolve_headers(request.get("header", []), variables)
                auth = self._resolve_auth(request.get("auth", {}), variables)
                body = self._resolve_body(request.get("body", {}), variables)

                return {
                    "name": name,
                    "description": description,
                    "folderPath": folder_path_safe,
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "auth": auth,
                    "body": body
                }

        except Exception as e:
            log.error(f"Error parsing Postman item: {e}")
            return None

    def _resolve_url(self, url_info: Any, variables: Dict[str, str]) -> str:
        if isinstance(url_info, str):
            url = url_info
        else:
            url = url_info.get("raw", "")
            if not url:
                protocol = url_info.get("protocol", "https")
                host = ".".join(url_info.get("host", []))
                path = "/".join(url_info.get("path", []))
                url = f"{protocol}://{host}/{path}"

            for var, val in variables.items():
                url = url.replace(f"{{{{{var}}}}}", val)
        return url

    def _resolve_headers(self, headers_list: List[Dict[str, str]], variables: Dict[str, str]) -> Dict[str, str]:
        headers = {}
        for header in headers_list:
            key = header.get("key")
            value = header.get("value")
            if key and value:
                for var, val in variables.items():
                    value = value.replace(f"{{{{{var}}}}}", val)
                headers[key] = value
        return headers

    def _resolve_auth(self, auth_info: Dict[str, Any], variables: Dict[str, str]) -> Dict[str, Any]:
        auth_type = auth_info.get("type")
        auth_data = auth_info.get(auth_type, {}) if auth_type else {}
        resolved = {"type": auth_type} if auth_type else {}
        for key, val in auth_data.items():
            if isinstance(val, str):
                for var, rep in variables.items():
                    val = val.replace(f"{{{{{var}}}}}", rep)
            resolved[key] = val
        return resolved

    def _resolve_body(self, body_info: Dict[str, Any], variables: Dict[str, str]) -> Optional[Any]:
        mode = body_info.get("mode")
        if not mode:
            return None

        if mode == "raw":
            raw = body_info.get("raw", "")
            for var, val in variables.items():
                raw = raw.replace(f"{{{{{var}}}}}", val)
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw

        if mode == "urlencoded":
            urlencoded = body_info.get("urlencoded", [])
            result = {}
            for param in urlencoded:
                key = param.get("key")
                value = param.get("value") or ""
                for var, val in variables.items():
                    value = value.replace(f"{{{{{var}}}}}", val)
                if key:
                    result[key] = value
            return result

        if mode == "formdata":
            formdata = body_info.get("formdata", [])
            result = {}
            for param in formdata:
                key = param.get("key")
                if "value" in param:
                    value = param.get("value") or ""
                    for var, val in variables.items():
                        value = value.replace(f"{{{{{var}}}}}", val)
                    if key:
                        result[key] = value
                elif "src" in param and key:
                    result[key] = param.get("src")
            return result

        return None

