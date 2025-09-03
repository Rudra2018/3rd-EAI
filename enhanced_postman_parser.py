#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Postman Collection Parser - Production Ready
"""

import json
import re
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

logger = logging.getLogger(__name__)

class PostmanCollectionParser:
    """Enhanced Postman Collection Parser that handles all collection formats"""
    
    def __init__(self):
        self.endpoints = []
        self.variables = {}
        self.auth_config = {}
        self.collections = []
        self.security_risks = {"high": [], "medium": [], "low": [], "info": []}
        logger.info("✅ Postman Collection Parser initialized")
        
    def parse_collection_file(self, file_content: str, filename: str) -> Dict[str, Any]:
        """Main entry point for parsing Postman collection files"""
        try:
            self._reset_state()
            
            # Parse JSON
            data = json.loads(file_content)
            
            # Extract collection data from different formats
            collection_data = self._extract_collection_data(data)
            
            if not collection_data:
                logger.warning(f"No valid collection data found in {filename}")
                return self._create_empty_result(filename)
            
            # Extract collection info
            info = collection_data.get('info', {})
            collection_name = info.get('name', filename.replace('.json', ''))
            
            logger.info(f"Parsing collection: {collection_name}")
            
            # Extract variables
            self._extract_variables(collection_data)
            
            # Extract authentication config
            self._extract_auth_config(collection_data)
            
            # Extract all endpoints
            items = collection_data.get('item', [])
            self._extract_endpoints_recursive(items, collection_name)
            
            # Analyze security risks
            self._analyze_security_risks()
            
            # Generate AI insights
            ai_insights = self._generate_ai_insights()
            
            result = {
                "endpoints_found": len(self.endpoints),
                "collections": [collection_name],
                "variables": len(self.variables),
                "auth_configured": bool(self.auth_config),
                "security_risks": self.security_risks,
                "ai_insights": ai_insights
            }
            
            logger.info(f"Successfully parsed {len(self.endpoints)} endpoints from {collection_name}")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error in {filename}: {str(e)}")
            return self._create_error_result(filename, f"Invalid JSON: {str(e)}")
        except Exception as e:
            logger.error(f"Parsing error in {filename}: {str(e)}")
            return self._create_error_result(filename, f"Parsing error: {str(e)}")
    
    def get_detailed_data(self) -> Dict[str, Any]:
        """Get detailed parsed data"""
        return {
            "info": {"total_endpoints": len(self.endpoints)},
            "endpoints": self.endpoints,
            "variables": self.variables,
            "auth_config": self.auth_config,
            "collections": self.collections,
            "total_requests": len(self.endpoints)
        }
    
    def _reset_state(self):
        """Reset parser state"""
        self.endpoints = []
        self.variables = {}
        self.auth_config = {}
        self.collections = []
        self.security_risks = {"high": [], "medium": [], "low": [], "info": []}
    
    def _extract_collection_data(self, data: Dict) -> Optional[Dict]:
        """Extract collection data from different formats"""
        # Format 1: Wrapped with "collection" key
        if "collection" in data and isinstance(data["collection"], dict):
            logger.debug("Detected wrapped collection format")
            return data["collection"]
        
        # Format 2: Direct collection (has "info" and "item")
        elif "info" in data and "item" in data:
            logger.debug("Detected direct collection format")
            return data
        
        # Format 3: Search for collection-like structure
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and "info" in value and "item" in value:
                    logger.debug(f"Found collection data under key: {key}")
                    return value
        
        logger.warning("No valid collection structure found")
        return None
    
    def _extract_endpoints_recursive(self, items: List[Dict], parent_folder: str = "", depth: int = 0):
        """Recursively extract endpoints from items"""
        if depth > 20:  # Prevent infinite recursion
            logger.warning("Maximum recursion depth reached")
            return
        
        for item in items:
            try:
                item_name = item.get('name', 'Unnamed Item')
                
                # Check if this is a folder (has sub-items)
                if 'item' in item and isinstance(item['item'], list):
                    folder_path = f"{parent_folder}/{item_name}" if parent_folder else item_name
                    logger.debug(f"Processing folder: {folder_path}")
                    self._extract_endpoints_recursive(item['item'], folder_path, depth + 1)
                
                # Check if this is a request
                elif 'request' in item:
                    endpoint = self._parse_request_item(item, parent_folder)
                    if endpoint:
                        self.endpoints.append(endpoint)
                        logger.debug(f"Parsed endpoint: {endpoint['method']} {endpoint['name']}")
                
            except Exception as e:
                logger.error(f"Error processing item {item.get('name', 'unknown')}: {str(e)}")
                continue
    
    def _parse_request_item(self, item: Dict, folder_path: str = "") -> Optional[Dict]:
        """Parse individual request item"""
        try:
            request_data = item.get('request', {})
            
            # Handle string request (just URL)
            if isinstance(request_data, str):
                return {
                    'id': item.get('id', ''),
                    'name': item.get('name', 'Unnamed Request'),
                    'description': item.get('description', ''),
                    'folder': folder_path,
                    'method': 'GET',
                    'url': request_data,
                    'headers': {},
                    'query_params': [],
                    'body': None,
                    'auth': None,
                    'variables_used': self._extract_variables_from_text(request_data)
                }
            
            # Handle object request
            elif isinstance(request_data, dict):
                method = request_data.get('method', 'GET').upper()
                
                # Parse URL
                url_data = request_data.get('url', {})
                url, query_params = self._parse_url(url_data)
                
                # Parse headers
                headers = self._parse_headers(request_data.get('header', []))
                
                # Parse body
                body = self._parse_body(request_data.get('body', {}))
                
                # Parse auth
                auth = self._parse_auth(request_data.get('auth', {}))
                
                # Extract variables used
                variables_used = self._extract_variables_from_request(url, headers, body)
                
                return {
                    'id': item.get('id', ''),
                    'name': item.get('name', 'Unnamed Request'),
                    'description': item.get('description', ''),
                    'folder': folder_path,
                    'method': method,
                    'url': url,
                    'headers': headers,
                    'query_params': query_params,
                    'body': body,
                    'auth': auth,
                    'variables_used': variables_used
                }
            
        except Exception as e:
            logger.error(f"Failed to parse request {item.get('name', 'unknown')}: {str(e)}")
            
        return None
    
    def _parse_url(self, url_data: Union[str, Dict]) -> tuple[str, List[Dict]]:
        """Parse URL from different formats"""
        query_params = []
        
        if isinstance(url_data, str):
            url = url_data
        elif isinstance(url_data, dict):
            raw_url = url_data.get('raw', '')
            
            if raw_url:
                url = raw_url
            else:
                # Build URL from components
                protocol = url_data.get('protocol', 'https')
                host = url_data.get('host', [])
                path = url_data.get('path', [])
                port = url_data.get('port', '')
                
                # Handle host
                if isinstance(host, list):
                    host_str = '.'.join(str(h) for h in host if h)
                else:
                    host_str = str(host) if host else 'localhost'
                
                # Handle path
                if isinstance(path, list):
                    path_str = '/' + '/'.join(str(p) for p in path if p) if path else ''
                else:
                    path_str = '/' + str(path) if path else ''
                
                # Handle port
                port_str = f":{port}" if port else ""
                
                url = f"{protocol}://{host_str}{port_str}{path_str}"
            
            # Extract query parameters
            query_params = url_data.get('query', [])
        else:
            url = str(url_data) if url_data else ''
        
        return url, query_params
    
    def _parse_headers(self, headers_list: List[Dict]) -> Dict[str, str]:
        """Parse headers from list format"""
        headers = {}
        for header in headers_list:
            if isinstance(header, dict) and not header.get('disabled', False):
                key = header.get('key', '')
                value = header.get('value', '')
                if key:
                    headers[key] = value
        return headers
    
    def _parse_body(self, body_data: Dict) -> Optional[Dict]:
        """Parse request body"""
        if not body_data:
            return None
        
        mode = body_data.get('mode', 'none')
        
        if mode == 'raw':
            return {
                'type': 'raw',
                'content': body_data.get('raw', ''),
                'language': body_data.get('options', {}).get('raw', {}).get('language', 'text')
            }
        elif mode == 'formdata':
            formdata = []
            for item in body_data.get('formdata', []):
                if not item.get('disabled', False):
                    formdata.append({
                        'key': item.get('key', ''),
                        'value': item.get('value', ''),
                        'type': item.get('type', 'text')
                    })
            return {'type': 'formdata', 'content': formdata}
        elif mode == 'urlencoded':
            urlencoded = []
            for item in body_data.get('urlencoded', []):
                if not item.get('disabled', False):
                    urlencoded.append({
                        'key': item.get('key', ''),
                        'value': item.get('value', '')
                    })
            return {'type': 'urlencoded', 'content': urlencoded}
        
        return {'type': mode, 'content': body_data}
    
    def _parse_auth(self, auth_data: Dict) -> Optional[Dict]:
        """Parse authentication configuration"""
        if not auth_data:
            return None
        
        auth_type = auth_data.get('type', 'none')
        if auth_type == 'none':
            return None
        
        return {
            'type': auth_type,
            'config': auth_data.get(auth_type, {})
        }
    
    def _extract_variables(self, collection_data: Dict):
        """Extract variables from collection"""
        variables = collection_data.get('variable', [])
        for var in variables:
            if isinstance(var, dict):
                key = var.get('key', '')
                if key:
                    self.variables[key] = {
                        'value': var.get('value', ''),
                        'type': var.get('type', 'string'),
                        'scope': 'collection'
                    }
    
    def _extract_auth_config(self, collection_data: Dict):
        """Extract authentication configuration"""
        auth = collection_data.get('auth', {})
        if auth:
            auth_type = auth.get('type', 'none')
            if auth_type != 'none':
                self.auth_config['collection_auth'] = {
                    'type': auth_type,
                    'config': auth.get(auth_type, {})
                }
    
    def _extract_variables_from_text(self, text: str) -> List[str]:
        """Extract Postman variables from text"""
        if not text:
            return []
        pattern = r'\{\{([^}]+)\}\}'
        matches = re.findall(pattern, text)
        return list(set(matches))
    
    def _extract_variables_from_request(self, url: str, headers: Dict, body: Optional[Dict]) -> List[str]:
        """Extract all variables used in a request"""
        variables = []
        variables.extend(self._extract_variables_from_text(url))
        
        for key, value in headers.items():
            variables.extend(self._extract_variables_from_text(key))
            variables.extend(self._extract_variables_from_text(value))
        
        if body and body.get('content'):
            content = body['content']
            if isinstance(content, str):
                variables.extend(self._extract_variables_from_text(content))
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        for key, value in item.items():
                            variables.extend(self._extract_variables_from_text(str(key)))
                            variables.extend(self._extract_variables_from_text(str(value)))
        
        return list(set(variables))
    
    def _analyze_security_risks(self):
        """Analyze security risks in the collection"""
        for endpoint in self.endpoints:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET')
            headers = endpoint.get('headers', {})
            auth = endpoint.get('auth')
            name = endpoint.get('name', 'Unknown')
            
            # High Risk: HTTP instead of HTTPS
            if url.startswith('http://') and not url.startswith('https://'):
                self.security_risks['high'].append(f"{method} {name} - Using HTTP instead of HTTPS")
            
            # Medium Risk: No authentication for modifying requests
            if not auth and method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                self.security_risks['medium'].append(f"{method} {name} - No authentication configured")
            
            # Medium Risk: Hardcoded credentials in headers
            for header_key, header_value in headers.items():
                if header_key.lower() in ['authorization', 'x-api-key', 'api-key']:
                    if header_value and not header_value.startswith('{{'):
                        self.security_risks['medium'].append(f"{method} {name} - Hardcoded credential in {header_key}")
            
            # Info: Variables used
            variables_used = endpoint.get('variables_used', [])
            if variables_used:
                self.security_risks['info'].append(f"{method} {name} - Uses variables: {', '.join(variables_used)}")
    
    def _generate_ai_insights(self) -> Dict[str, Any]:
        """Generate AI insights about the collection"""
        total_endpoints = len(self.endpoints)
        
        if total_endpoints == 0:
            return {
                "strategy_confidence": 0,
                "recommended_tests": 0,
                "risk_level": "Unknown",
                "analysis": "No endpoints found"
            }
        
        # Calculate metrics
        auth_endpoints = sum(1 for ep in self.endpoints if ep.get('auth'))
        http_endpoints = sum(1 for ep in self.endpoints if ep.get('url', '').startswith('http://'))
        
        auth_ratio = auth_endpoints / total_endpoints if total_endpoints > 0 else 0
        http_ratio = http_endpoints / total_endpoints if total_endpoints > 0 else 0
        
        # Determine risk level
        high_risks = len(self.security_risks['high'])
        medium_risks = len(self.security_risks['medium'])
        
        if high_risks > 0 or http_ratio > 0.5:
            risk_level = "High"
        elif medium_risks > 2 or auth_ratio < 0.3:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Calculate confidence
        confidence = min(0.95, 0.5 + (auth_ratio * 0.3) + ((1 - http_ratio) * 0.2))
        
        return {
            "strategy_confidence": round(confidence, 2),
            "recommended_tests": min(total_endpoints * 5, 100),
            "risk_level": risk_level,
            "analysis": f"Analyzed {total_endpoints} endpoints with {auth_endpoints} authenticated"
        }
    
    def _create_empty_result(self, filename: str) -> Dict[str, Any]:
        """Create empty result structure"""
        return {
            "endpoints_found": 0,
            "collections": [filename],
            "variables": 0,
            "auth_configured": False,
            "security_risks": {"high": [], "medium": [], "low": [], "info": []},
            "ai_insights": {
                "strategy_confidence": 0,
                "recommended_tests": 0,
                "risk_level": "Unknown",
                "analysis": "No valid collection data found"
            }
        }
    
    def _create_error_result(self, filename: str, error_msg: str) -> Dict[str, Any]:
        """Create error result structure"""
        return {
            "endpoints_found": 0,
            "collections": [filename],
            "variables": 0,
            "auth_configured": False,
            "security_risks": {"high": [error_msg], "medium": [], "low": [], "info": []},
            "ai_insights": {
                "strategy_confidence": 0,
                "recommended_tests": 0,
                "risk_level": "Error",
                "analysis": f"Error parsing collection: {error_msg}"
            }
        }
