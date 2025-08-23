#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced API Scanner - Core async scanner with AI guidance
Advanced HTTP/GraphQL API scanner with intelligent vulnerability detection
"""

import asyncio
import aiohttp
import json
import logging
import time
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import ssl
import certifi

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# ML integration
try:
    from ml.response_classifier import EnhancedResponseClassifier
    from ml.false_positive_detector import EnhancedFalsePositiveDetector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

log = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Enhanced scan result with AI insights"""
    endpoint: str
    method: str
    status_code: int
    response_body: str
    response_headers: Dict[str, str]
    response_time: float
    vulnerabilities: List[Dict[str, Any]]
    ai_insights: Dict[str, Any]
    scan_metadata: Dict[str, Any]
    timestamp: datetime
    
class EnhancedAPIScanner:
    """
    Advanced asynchronous API security scanner with AI guidance
    Features:
    - High-performance async HTTP scanning
    - AI-powered vulnerability detection and prioritization
    - ML-based false positive reduction
    - GraphQL and REST API support
    - Real-time scan optimization and adaptation
    - Comprehensive security test coverage
    """
    
    def __init__(self, 
                 max_concurrent: int = 10,
                 timeout: int = 30,
                 ai_enhanced: bool = True,
                 ml_enhanced: bool = True):
        
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.ai_enhanced = ai_enhanced and AI_AVAILABLE
        self.ml_enhanced = ml_enhanced and ML_AVAILABLE
        
        # Session management
        self.session = None
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # AI and ML components
        self.ai_coordinator = None
        self.response_classifier = None
        self.fp_detector = None
        
        # Scan statistics
        self.scan_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "vulnerabilities_found": 0,
            "false_positives_filtered": 0,
            "scan_start_time": None,
            "scan_end_time": None
        }
        
        self._initialize_components()

    def _initialize_components(self):
        """Initialize AI and ML components"""
        try:
            if self.ai_enhanced:
                self.ai_coordinator = AdvancedAICoordinator()
                log.info("✅ AI-enhanced scanning enabled")
            
            if self.ml_enhanced:
                self.response_classifier = EnhancedResponseClassifier()
                self.fp_detector = EnhancedFalsePositiveDetector()
                log.info("✅ ML-enhanced analysis enabled")
                
        except Exception as e:
            log.warning(f"Component initialization failed: {e}")
            self.ai_enhanced = False
            self.ml_enhanced = False

    async def __aenter__(self):
        """Async context manager entry"""
        # Create SSL context for secure connections
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        # Configure connector with security settings
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=self.max_concurrent,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        
        # Create session with comprehensive headers
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                'User-Agent': 'Rudra-Enhanced-Scanner/3.0.0',
                'Accept': 'application/json, text/html, application/xml, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
        )
        
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def scan_endpoints(self, endpoints: List[Dict[str, Any]], 
                           scan_config: Optional[Dict[str, Any]] = None) -> List[ScanResult]:
        """Scan multiple endpoints with enhanced analysis"""
        try:
            log.info(f"🚀 Starting enhanced scan of {len(endpoints)} endpoints")
            self.scan_stats["scan_start_time"] = datetime.now()
            self.scan_stats["total_requests"] = len(endpoints)
            
            # Generate AI-powered scan plan if enabled
            if self.ai_enhanced:
                scan_plan = await self._generate_ai_scan_plan(endpoints, scan_config)
                log.info(f"🧠 AI scan plan generated: {scan_plan.get('strategy', 'standard')}")
            else:
                scan_plan = {"strategy": "standard"}
            
            # Create scan tasks
            scan_tasks = []
            for endpoint in endpoints:
                task = asyncio.create_task(
                    self._scan_single_endpoint(endpoint, scan_plan, scan_config)
                )
                scan_tasks.append(task)
            
            # Execute scans with concurrency control
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Process results and handle exceptions
            successful_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    log.error(f"Scan failed for endpoint {i}: {result}")
                    self.scan_stats["failed_requests"] += 1
                else:
                    successful_results.append(result)
                    self.scan_stats["successful_requests"] += 1
                    self.scan_stats["vulnerabilities_found"] += len(result.vulnerabilities)
            
            # Post-process results with AI enhancement
            if self.ai_enhanced and successful_results:
                enhanced_results = await self._enhance_results_with_ai(successful_results)
                successful_results = enhanced_results
            
            self.scan_stats["scan_end_time"] = datetime.now()
            scan_duration = (self.scan_stats["scan_end_time"] - self.scan_stats["scan_start_time"]).total_seconds()
            
            log.info(f"✅ Scan completed: {len(successful_results)} results in {scan_duration:.2f}s")
            return successful_results
            
        except Exception as e:
            log.error(f"Endpoint scanning failed: {e}")
            return []

    async def _generate_ai_scan_plan(self, endpoints: List[Dict[str, Any]], 
                                   config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate AI-powered scan plan"""
        if not self.ai_coordinator:
            return {"strategy": "standard"}
        
        try:
            # Analyze endpoints for optimal scanning strategy
            endpoint_summary = []
            for ep in endpoints[:20]:  # Limit for prompt
                endpoint_summary.append({
                    "method": ep.get("method", "GET"),
                    "url": ep.get("url", ""),
                    "has_auth": bool(ep.get("headers", {}).get("Authorization")),
                    "business_function": ep.get("business_function", ""),
                    "risk_score": ep.get("risk_score", 1)
                })
            
            prompt = f"""Generate an optimal API scanning strategy for these endpoints:

Endpoints: {json.dumps(endpoint_summary, indent=2)}
Config: {config or {}}
Total Endpoints: {len(endpoints)}

Create scanning strategy as JSON:
{{
  "strategy": "comprehensive|focused|rapid|adaptive",
  "scan_priorities": {{
    "high_priority": ["endpoint_indices"],
    "medium_priority": ["endpoint_indices"],  
    "low_priority": ["endpoint_indices"]
  }},
  "testing_techniques": {{
    "injection_testing": true,
    "authentication_testing": true,
    "business_logic_testing": true,
    "performance_testing": false
  }},
  "optimization_settings": {{
    "concurrent_requests": {min(self.max_concurrent, 15)},
    "request_delay_ms": 100,
    "retry_failed": true,
    "adaptive_timing": true
  }},
  "expected_findings": {{
    "vulnerability_likelihood": 0.3,
    "false_positive_rate": 0.2,
    "scan_efficiency": "high|medium|low"
  }}
}}
"""
            
            request = AIRequest(
                task_type="scan_planning",
                prompt=prompt,
                temperature=0.2,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_scan_plan(response.content)
            
        except Exception as e:
            log.error(f"AI scan planning failed: {e}")
        
        return {"strategy": "standard"}

    def _parse_scan_plan(self, content: str) -> Dict[str, Any]:
        """Parse AI scan plan response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse scan plan: {e}")
        
        return {"strategy": "standard"}

    async def _scan_single_endpoint(self, endpoint: Dict[str, Any], 
                                  scan_plan: Dict[str, Any],
                                  scan_config: Optional[Dict[str, Any]]) -> ScanResult:
        """Scan single endpoint with comprehensive analysis"""
        async with self.semaphore:
            start_time = time.time()
            
            method = endpoint.get("method", "GET").upper()
            url = endpoint.get("url", "")
            headers = endpoint.get("headers", {}).copy()
            data = endpoint.get("data")
            
            try:
                # Execute HTTP request
                response_data = await self._execute_http_request(method, url, headers, data)
                
                # Analyze response for vulnerabilities
                vulnerabilities = await self._analyze_response_for_vulnerabilities(
                    response_data, endpoint, scan_plan
                )
                
                # Filter false positives if ML enabled
                if self.ml_enhanced and vulnerabilities:
                    filtered_vulns = await self._filter_false_positives(
                        vulnerabilities, response_data, endpoint
                    )
                    false_positives_removed = len(vulnerabilities) - len(filtered_vulns)
                    self.scan_stats["false_positives_filtered"] += false_positives_removed
                    vulnerabilities = filtered_vulns
                
                # Generate AI insights
                ai_insights = {}
                if self.ai_enhanced:
                    ai_insights = await self._generate_ai_insights(response_data, vulnerabilities, endpoint)
                
                # Create scan result
                result = ScanResult(
                    endpoint=url,
                    method=method,
                    status_code=response_data.get("status_code", 0),
                    response_body=response_data.get("body", ""),
                    response_headers=response_data.get("headers", {}),
                    response_time=time.time() - start_time,
                    vulnerabilities=vulnerabilities,
                    ai_insights=ai_insights,
                    scan_metadata={
                        "scan_plan_strategy": scan_plan.get("strategy"),
                        "endpoint_metadata": endpoint,
                        "ml_enhanced": self.ml_enhanced,
                        "ai_enhanced": self.ai_enhanced
                    },
                    timestamp=datetime.now()
                )
                
                return result
                
            except Exception as e:
                log.error(f"Single endpoint scan failed for {method} {url}: {e}")
                
                # Return error result
                return ScanResult(
                    endpoint=url,
                    method=method,
                    status_code=0,
                    response_body="",
                    response_headers={},
                    response_time=time.time() - start_time,
                    vulnerabilities=[],
                    ai_insights={"error": str(e)},
                    scan_metadata={"error": True, "error_message": str(e)},
                    timestamp=datetime.now()
                )

    async def _execute_http_request(self, method: str, url: str, 
                                  headers: Dict[str, str], data: Any) -> Dict[str, Any]:
        """Execute HTTP request with error handling"""
        try:
            # Prepare request parameters
            kwargs = {}
            
            if data is not None:
                if isinstance(data, dict):
                    if headers.get("Content-Type", "").startswith("application/json"):
                        kwargs["json"] = data
                    else:
                        kwargs["data"] = data
                else:
                    kwargs["data"] = data
            
            # Execute request
            async with self.session.request(method, url, headers=headers, **kwargs) as response:
                # Read response
                try:
                    body = await response.text()
                except Exception:
                    body = await response.read()
                    body = str(body)
                
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "url": str(response.url)
                }
                
        except asyncio.TimeoutError:
            log.warning(f"Request timeout for {method} {url}")
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "error": "timeout",
                "url": url
            }
        except Exception as e:
            log.error(f"HTTP request failed for {method} {url}: {e}")
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "error": str(e),
                "url": url
            }

    async def _analyze_response_for_vulnerabilities(self, response_data: Dict[str, Any], 
                                                  endpoint: Dict[str, Any],
                                                  scan_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze HTTP response for security vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Basic vulnerability detection
            basic_vulns = self._detect_basic_vulnerabilities(response_data, endpoint)
            vulnerabilities.extend(basic_vulns)
            
            # ML-enhanced detection if available
            if self.ml_enhanced and self.response_classifier:
                ml_analysis = self.response_classifier.classify_response(
                    response_data.get("body", ""),
                    {"url": endpoint.get("url"), "method": endpoint.get("method")}
                )
                
                ml_vulns = self._convert_ml_analysis_to_vulnerabilities(ml_analysis, response_data)
                vulnerabilities.extend(ml_vulns)
            
            # AI-powered detection for complex cases
            if self.ai_enhanced and len(vulnerabilities) == 0:
                ai_vulns = await self._detect_ai_vulnerabilities(response_data, endpoint)
                vulnerabilities.extend(ai_vulns)
            
            return vulnerabilities
            
        except Exception as e:
            log.error(f"Vulnerability analysis failed: {e}")
            return []

    def _detect_basic_vulnerabilities(self, response_data: Dict[str, Any], 
                                    endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect basic vulnerabilities using pattern matching"""
        vulnerabilities = []
        
        status_code = response_data.get("status_code", 0)
        body = response_data.get("body", "").lower()
        headers = response_data.get("headers", {})
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET")
        
        # SQL Injection indicators
        sql_indicators = [
            "mysql_fetch_array", "ora-01756", "microsoft ole db",
            "syntax error", "sql syntax", "database error"
        ]
        
        if any(indicator in body for indicator in sql_indicators):
            vulnerabilities.append({
                "type": "SQL Injection",
                "severity": "High",
                "confidence": 0.8,
                "description": f"Potential SQL injection vulnerability detected in response",
                "endpoint": url,
                "method": method,
                "evidence": "Database error messages found in response"
            })
        
        # XSS reflection indicators
        xss_indicators = ["<script", "javascript:", "onerror=", "onload="]
        
        if any(indicator in body for indicator in xss_indicators):
            vulnerabilities.append({
                "type": "Cross-Site Scripting (XSS)",
                "severity": "Medium",
                "confidence": 0.7,
                "description": f"Potential XSS vulnerability detected",
                "endpoint": url,
                "method": method,
                "evidence": "Script tags or JavaScript code found in response"
            })
        
        # Information disclosure
        sensitive_info = [
            "debug", "stack trace", "exception", "internal server error",
            "database", "password", "secret", "token"
        ]
        
        if any(info in body for info in sensitive_info):
            vulnerabilities.append({
                "type": "Information Disclosure",
                "severity": "Low",
                "confidence": 0.6,
                "description": f"Sensitive information disclosed in response",
                "endpoint": url,
                "method": method,
                "evidence": "Sensitive keywords found in response body"
            })
        
        # Security headers analysis
        security_headers = {
            "x-frame-options": "Clickjacking protection",
            "x-content-type-options": "MIME type sniffing protection", 
            "x-xss-protection": "XSS protection",
            "strict-transport-security": "HTTPS enforcement",
            "content-security-policy": "Content Security Policy"
        }
        
        missing_headers = []
        for header, purpose in security_headers.items():
            if header not in [h.lower() for h in headers.keys()]:
                missing_headers.append(f"{header} ({purpose})")
        
        if missing_headers and status_code == 200:
            vulnerabilities.append({
                "type": "Missing Security Headers",
                "severity": "Low",
                "confidence": 0.9,
                "description": f"Missing security headers detected",
                "endpoint": url,
                "method": method,
                "evidence": f"Missing headers: {', '.join(missing_headers[:3])}"
            })
        
        return vulnerabilities

    def _convert_ml_analysis_to_vulnerabilities(self, ml_analysis, response_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert ML analysis results to vulnerability format"""
        vulnerabilities = []
        
        if not hasattr(ml_analysis, 'vulnerability_scores'):
            return vulnerabilities
        
        for vuln_type, score in ml_analysis.vulnerability_scores.items():
            if score > 0.5:  # Threshold for considering it a vulnerability
                
                # Map ML types to standard vulnerability types
                type_mapping = {
                    "sql_injection": "SQL Injection",
                    "xss": "Cross-Site Scripting (XSS)",
                    "command_injection": "Command Injection",
                    "information_disclosure": "Information Disclosure",
                    "misconfiguration": "Security Misconfiguration"
                }
                
                vuln_name = type_mapping.get(vuln_type, vuln_type.title())
                
                # Determine severity based on score
                if score >= 0.8:
                    severity = "High"
                elif score >= 0.6:
                    severity = "Medium"
                else:
                    severity = "Low"
                
                vulnerabilities.append({
                    "type": vuln_name,
                    "severity": severity,
                    "confidence": score,
                    "description": f"ML-detected {vuln_name.lower()} vulnerability",
                    "endpoint": response_data.get("url", ""),
                    "method": "Unknown",
                    "evidence": f"ML classifier confidence: {score:.2f}",
                    "ml_enhanced": True,
                    "patterns_detected": getattr(ml_analysis, 'patterns_detected', [])
                })
        
        return vulnerabilities

    async def _detect_ai_vulnerabilities(self, response_data: Dict[str, Any], 
                                       endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use AI to detect complex vulnerabilities"""
        if not self.ai_coordinator:
            return []
        
        try:
            body_sample = response_data.get("body", "")[:2000]  # First 2000 chars
            
            prompt = f"""Analyze this HTTP response for security vulnerabilities:

Request: {endpoint.get('method', 'GET')} {endpoint.get('url', '')}
Status Code: {response_data.get('status_code', 0)}
Response Body (sample): {body_sample}

Look for:
1. Injection vulnerabilities (SQL, NoSQL, Command, etc.)
2. Authentication/Authorization issues
3. Business logic flaws
4. Information disclosure
5. Security misconfigurations

Return findings as JSON array:
[
  {{
    "type": "vulnerability_type",
    "severity": "Low|Medium|High|Critical", 
    "confidence": 0.0-1.0,
    "description": "detailed_description",
    "evidence": "specific_evidence_from_response"
  }}
]

Only return actual vulnerabilities with high confidence. Return empty array if no clear vulnerabilities found.
"""
            
            request = AIRequest(
                task_type="vulnerability_detection",
                prompt=prompt,
                temperature=0.1,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                ai_vulns = self._parse_ai_vulnerabilities(response.content, endpoint)
                return ai_vulns
            
        except Exception as e:
            log.error(f"AI vulnerability detection failed: {e}")
        
        return []

    def _parse_ai_vulnerabilities(self, content: str, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse AI vulnerability detection response"""
        try:
            start = content.find('[')
            end = content.rfind(']') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                ai_vulns = json.loads(json_str)
                
                # Enhance with endpoint information
                for vuln in ai_vulns:
                    vuln["endpoint"] = endpoint.get("url", "")
                    vuln["method"] = endpoint.get("method", "GET")
                    vuln["ai_detected"] = True
                
                return ai_vulns
                
        except Exception as e:
            log.error(f"Failed to parse AI vulnerabilities: {e}")
        
        return []

    async def _filter_false_positives(self, vulnerabilities: List[Dict[str, Any]], 
                                    response_data: Dict[str, Any],
                                    endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Filter false positives using ML"""
        if not self.fp_detector:
            return vulnerabilities
        
        filtered_vulnerabilities = []
        
        for vuln in vulnerabilities:
            try:
                # Prepare data for FP analysis
                vuln_data = {
                    "http_trace": {
                        "request": {
                            "method": endpoint.get("method", "GET"),
                            "url": endpoint.get("url", ""),
                            "headers": endpoint.get("headers", {}),
                            "payload": endpoint.get("data")
                        },
                        "response": {
                            "status_code": response_data.get("status_code", 0),
                            "headers": response_data.get("headers", {}),
                            "body": response_data.get("body", "")
                        }
                    },
                    "type": vuln.get("type", "unknown"),
                    "confidence": vuln.get("confidence", 0.5),
                    "severity": vuln.get("severity", "medium")
                }
                
                # Analyze for false positive
                fp_analysis = self.fp_detector.analyze_vulnerability(vuln_data)
                
                # Keep vulnerability if it's not a false positive
                if not fp_analysis.is_false_positive or fp_analysis.confidence < 0.7:
                    # Add FP analysis to vulnerability
                    vuln["fp_analysis"] = {
                        "is_false_positive": fp_analysis.is_false_positive,
                        "fp_confidence": fp_analysis.confidence,
                        "fp_reasons": fp_analysis.reasons
                    }
                    filtered_vulnerabilities.append(vuln)
                
            except Exception as e:
                log.error(f"False positive analysis failed: {e}")
                # Keep vulnerability if analysis fails
                filtered_vulnerabilities.append(vuln)
        
        return filtered_vulnerabilities

    async def _generate_ai_insights(self, response_data: Dict[str, Any], 
                                  vulnerabilities: List[Dict[str, Any]],
                                  endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI insights about the scan result"""
        if not self.ai_coordinator:
            return {}
        
        try:
            insights_prompt = f"""Provide security insights for this API endpoint scan:

Endpoint: {endpoint.get('method', 'GET')} {endpoint.get('url', '')}
Status: {response_data.get('status_code', 0)}
Vulnerabilities Found: {len(vulnerabilities)}

Vulnerability Summary:
{json.dumps([{'type': v.get('type'), 'severity': v.get('severity')} for v in vulnerabilities], indent=2)}

Provide insights as JSON:
{{
  "security_posture": "excellent|good|moderate|poor|critical",
  "risk_level": "low|medium|high|critical",
  "key_concerns": ["concern1", "concern2"],
  "recommendations": ["recommendation1", "recommendation2"],
  "business_impact": "description",
  "remediation_priority": "immediate|high|medium|low"
}}
"""
            
            request = AIRequest(
                task_type="security_insights",
                prompt=insights_prompt,
                temperature=0.2,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_insights(response.content)
            
        except Exception as e:
            log.error(f"AI insights generation failed: {e}")
        
        return {}

    def _parse_ai_insights(self, content: str) -> Dict[str, Any]:
        """Parse AI insights response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse AI insights: {e}")
        
        return {}

    async def _enhance_results_with_ai(self, results: List[ScanResult]) -> List[ScanResult]:
        """Enhance scan results with AI analysis"""
        if not self.ai_coordinator:
            return results
        
        try:
            # Perform cross-result analysis
            result_summary = []
            for result in results[:20]:  # Limit for prompt size
                result_summary.append({
                    "endpoint": result.endpoint,
                    "method": result.method,
                    "status_code": result.status_code,
                    "vulnerabilities": len(result.vulnerabilities),
                    "response_time": result.response_time
                })
            
            # Get AI analysis of overall results
            overall_analysis = await self._get_overall_ai_analysis(result_summary)
            
            # Apply insights to individual results
            for result in results:
                if not result.ai_insights:
                    result.ai_insights = {}
                result.ai_insights["overall_analysis"] = overall_analysis
            
            return results
            
        except Exception as e:
            log.error(f"AI result enhancement failed: {e}")
            return results

    async def _get_overall_ai_analysis(self, result_summary: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get AI analysis of overall scan results"""
        try:
            prompt = f"""Analyze these API scan results for overall security assessment:

Scan Results Summary:
{json.dumps(result_summary, indent=2)}

Provide overall analysis as JSON:
{{
  "overall_security_grade": "A|B|C|D|F",
  "total_risk_score": 1-10,
  "patterns_identified": ["pattern1", "pattern2"],
  "systemic_issues": ["issue1", "issue2"],
  "security_highlights": ["highlight1", "highlight2"],
  "improvement_areas": ["area1", "area2"],
  "compliance_concerns": ["concern1", "concern2"]
}}
"""
            
            request = AIRequest(
                task_type="overall_analysis",
                prompt=prompt,
                temperature=0.2,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_insights(response.content)
            
        except Exception as e:
            log.error(f"Overall AI analysis failed: {e}")
        
        return {}

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics"""
        scan_duration = 0
        if (self.scan_stats["scan_start_time"] and 
            self.scan_stats["scan_end_time"]):
            scan_duration = (self.scan_stats["scan_end_time"] - 
                           self.scan_stats["scan_start_time"]).total_seconds()
        
        return {
            **self.scan_stats,
            "scan_duration_seconds": scan_duration,
            "success_rate": (
                self.scan_stats["successful_requests"] / 
                max(self.scan_stats["total_requests"], 1)
            ),
            "requests_per_second": (
                self.scan_stats["total_requests"] / max(scan_duration, 1)
            ),
            "ai_enhanced": self.ai_enhanced,
            "ml_enhanced": self.ml_enhanced,
            "max_concurrent": self.max_concurrent,
            "timeout": self.timeout
        }

# Usage example
if __name__ == "__main__":
    async def main():
        # Example endpoints
        test_endpoints = [
            {
                "method": "GET",
                "url": "https://httpbin.org/get",
                "headers": {"Accept": "application/json"}
            },
            {
                "method": "POST", 
                "url": "https://httpbin.org/post",
                "headers": {"Content-Type": "application/json"},
                "data": {"test": "data"}
            }
        ]
        
        # Scan with enhanced scanner
        async with EnhancedAPIScanner(max_concurrent=5, ai_enhanced=True) as scanner:
            results = await scanner.scan_endpoints(test_endpoints)
            
            print(f"🎯 Scan Results: {len(results)} endpoints scanned")
            
            for result in results:
                print(f"\n📍 {result.method} {result.endpoint}")
                print(f"   Status: {result.status_code}")
                print(f"   Response Time: {result.response_time:.2f}s")
                print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
                
                if result.vulnerabilities:
                    for vuln in result.vulnerabilities:
                        print(f"   🚨 {vuln.get('type')} ({vuln.get('severity')})")
                
                if result.ai_insights:
                    security_posture = result.ai_insights.get("security_posture")
                    if security_posture:
                        print(f"   🧠 AI Security Posture: {security_posture}")
            
            # Print scan statistics
            stats = scanner.get_scan_statistics()
            print(f"\n📊 Scan Statistics:")
            print(f"   Success Rate: {stats['success_rate']:.1%}")
            print(f"   Total Vulnerabilities: {stats['vulnerabilities_found']}")
            print(f"   False Positives Filtered: {stats['false_positives_filtered']}")
            print(f"   Scan Duration: {stats['scan_duration_seconds']:.2f}s")

    asyncio.run(main())

