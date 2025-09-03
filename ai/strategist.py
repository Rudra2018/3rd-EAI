#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced AI Strategist - Multi-Model Security Strategy and Triage
Advanced AI-powered security analysis, payload generation, and vulnerability explanation
"""

import os
import json
import logging
import hashlib
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Caching utility
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

log = logging.getLogger(__name__)

@dataclass
class SecurityStrategy:
    """Comprehensive security testing strategy"""
    target_analysis: Dict[str, Any]
    attack_vectors: List[Dict[str, Any]]
    payload_recommendations: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    testing_timeline: Dict[str, Any]
    success_metrics: List[str]
    ai_confidence: float
    generated_at: datetime

@dataclass
class PayloadSuggestion:
    """AI-generated payload suggestion"""
    payload_type: str
    payload_value: Any
    target_parameter: str
    attack_technique: str
    success_probability: float
    detection_evasion: Dict[str, Any]
    context: Dict[str, Any]

class EnhancedFileCache:
    """Enhanced file-based caching system"""
    
    def __init__(self, cache_dir: str = ".ai_cache", default_ttl: int = 12*3600):
        self.cache_dir = cache_dir
        self.default_ttl = default_ttl
        os.makedirs(cache_dir, exist_ok=True)
    
    def _get_cache_path(self, key: str) -> str:
        """Get cache file path for key"""
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{safe_key}.json")
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        try:
            cache_path = self._get_cache_path(key)
            if os.path.exists(cache_path):
                with open(cache_path, 'r') as f:
                    cache_data = json.load(f)
                
                # Check expiration
                expires_at = datetime.fromisoformat(cache_data['expires_at'])
                if datetime.now().isoformat() < expires_at:
                    return cache_data['value']
                else:
                    os.remove(cache_path)  # Remove expired cache
        except Exception as e:
            log.debug(f"Cache read error: {e}")
        
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set cached value"""
        try:
            cache_path = self._get_cache_path(key)
            expires_at = datetime.now().isoformat() + timedelta(seconds=ttl or self.default_ttl)
            
            cache_data = {
                'value': value,
                'expires_at': expires_at.isoformat(),
                'created_at': datetime.now().isoformat().isoformat()
            }
            
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except Exception as e:
            log.error(f"Cache write error: {e}")

class EnhancedAIStrategist:
    """
    Advanced AI-powered security strategist and triage system
    Features:
    - Multi-model AI coordination for comprehensive analysis
    - Intelligent endpoint prediction and attack surface mapping
    - Context-aware payload generation and optimization
    - Advanced vulnerability triage and impact assessment
    - Real-time threat intelligence integration
    - Adaptive learning from scan results and feedback
    """
    
    def __init__(self, cache_dir: str = ".ai_cache", 
                 model_preferences: Dict[str, str] = None,
                 enable_caching: bool = True):
        
        self.cache = EnhancedFileCache(cache_dir=cache_dir) if enable_caching else None
        self.model_preferences = model_preferences or {
            "endpoint_analysis": "gpt-4o",
            "payload_generation": "gpt-4o-mini", 
            "vulnerability_triage": "gpt-4o",
            "threat_intelligence": "gemini-1.5-pro"
        }
        
        # AI coordinator
        self.ai_coordinator = None
        if AI_AVAILABLE:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
                log.info("✅ Enhanced AI Strategist initialized")
            except Exception as e:
                log.error(f"AI coordinator initialization failed: {e}")
                raise

        # Strategy templates and knowledge base
        self.attack_patterns = self._load_attack_patterns()
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        self.payload_templates = self._load_payload_templates()

    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load attack pattern knowledge base"""
        return {
            "injection_patterns": {
                "sql": {
                    "error_based": ["'", '"', "\\", "1' OR '1'='1"],
                    "time_based": ["'; WAITFOR DELAY '00:00:05'--", "' AND SLEEP(5)--"],
                    "union_based": ["' UNION SELECT NULL--", "' UNION SELECT 1,2,3--"]
                },
                "xss": {
                    "reflected": ["<script>alert(1)</script>", "javascript:alert(1)"],
                    "stored": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
                    "dom": ["#<script>alert(1)</script>", "location.hash"]
                },
                "command": {
                    "linux": ["; ls", "| whoami", "&& id", "`uname -a`"],
                    "windows": ["; dir", "| whoami", "&& systeminfo"]
                }
            },
            "authentication_bypass": {
                "jwt_attacks": ["none_algorithm", "weak_secret", "key_confusion"],
                "session_attacks": ["fixation", "hijacking", "prediction"],
                "oauth_attacks": ["redirect_uri", "state_parameter", "implicit_flow"]
            },
            "authorization_bypass": {
                "idor_patterns": ["sequential_ids", "predictable_uuids", "encoded_references"],
                "privilege_escalation": ["role_parameter", "permission_flags", "group_membership"]
            }
        }

    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signature patterns"""
        return {
            "error_signatures": {
                "sql_errors": [
                    "mysql_fetch_array", "ORA-01756", "Microsoft OLE DB",
                    "PostgreSQL query failed", "SQLite3::SQLException"
                ],
                "application_errors": [
                    "stack trace", "debug mode", "exception", "error 500",
                    "internal server error", "unhandled exception"
                ]
            },
            "success_indicators": {
                "authentication_bypass": ["welcome", "dashboard", "profile", "admin"],
                "data_extraction": ["users", "records", "results", "data"],
                "command_execution": ["root", "administrator", "system", "kernel"]
            }
        }

    def _load_payload_templates(self) -> Dict[str, Any]:
        """Load payload generation templates"""
        return {
            "context_aware": {
                "login_forms": {
                    "sql_injection": ["admin'--", "' OR '1'='1'--", "' OR 1=1#"],
                    "credential_stuffing": ["admin:admin", "root:root", "test:test"]
                },
                "search_forms": {
                    "xss": ["<script>alert('XSS')</script>", "javascript:alert('XSS')"],
                    "sql_injection": ["' UNION SELECT version()--"]
                },
                "file_uploads": {
                    "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
                    "malicious_files": ["shell.php", "cmd.jsp", "backdoor.aspx"]
                }
            },
            "evasion_techniques": {
                "encoding": ["url_encoding", "html_encoding", "unicode_encoding"],
                "obfuscation": ["comment_insertion", "case_variation", "whitespace_manipulation"],
                "fragmentation": ["parameter_pollution", "header_splitting", "request_smuggling"]
            }
        }

    async def develop_comprehensive_strategy(self, target_info: Dict[str, Any]) -> SecurityStrategy:
        """Develop comprehensive security testing strategy"""
        try:
            log.info(f"🧠 Developing comprehensive strategy for {target_info.get('name', 'target')}")
            
            # Generate cache key
            cache_key = f"strategy:{hashlib.md5(json.dumps(target_info, sort_keys=True).encode()).hexdigest()}"
            
            # Check cache
            if self.cache:
                cached_result = self.cache.get(cache_key)
                if cached_result:
                    log.info("📦 Using cached strategy")
                    return SecurityStrategy(**cached_result)
            
            # AI-powered target analysis
            target_analysis = await self._analyze_target_with_ai(target_info)
            
            # Generate attack vectors
            attack_vectors = await self._generate_attack_vectors(target_info, target_analysis)
            
            # Create payload recommendations
            payload_recommendations = await self._recommend_payloads(target_info, attack_vectors)
            
            # Assess risks
            risk_assessment = await self._assess_target_risks(target_info, target_analysis)
            
            # Create testing timeline
            testing_timeline = self._create_testing_timeline(attack_vectors, risk_assessment)
            
            # Define success metrics
            success_metrics = self._define_success_metrics(target_info, risk_assessment)
            
            # Calculate AI confidence
            ai_confidence = self._calculate_strategy_confidence(target_analysis, attack_vectors)
            
            strategy = SecurityStrategy(
                target_analysis=target_analysis,
                attack_vectors=attack_vectors,
                payload_recommendations=payload_recommendations,
                risk_assessment=risk_assessment,
                testing_timeline=testing_timeline,
                success_metrics=success_metrics,
                ai_confidence=ai_confidence,
                generated_at=datetime.now().isoformat()
            )
            
            # Cache result
            if self.cache:
                self.cache.set(cache_key, strategy.__dict__, ttl=6*3600)  # 6 hours
            
            log.info(f"✅ Strategy developed with {len(attack_vectors)} attack vectors")
            # Convert SecurityStrategy object to dict if needed
            
        except Exception as e:
            log.error(f"Strategy development failed: {e}")
            # Return minimal strategy
            return SecurityStrategy(
                target_analysis={"error": str(e)},
                attack_vectors=[],
                payload_recommendations=[],
                risk_assessment={"risk_level": "unknown"},
                testing_timeline={},
                success_metrics=[],
                ai_confidence=0.0,
                generated_at=datetime.now().isoformat()
            )

    async def _analyze_target_with_ai(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive AI-powered target analysis"""
        if not self.ai_coordinator:
            return {"error": "AI coordinator not available"}
        
        try:
            prompt = f"""Analyze this API security target for comprehensive testing strategy:

Target Information:
{json.dumps(target_info, indent=2)}

Provide detailed analysis as JSON:
{{
  "target_classification": {{
    "application_type": "web_api|mobile_api|internal_api|public_api",
    "technology_stack": ["technologies"],
    "architecture_pattern": "rest|graphql|grpc|soap",
    "authentication_methods": ["methods"],
    "business_criticality": "critical|high|medium|low"
  }},
  "attack_surface_analysis": {{
    "exposed_endpoints": {{"count": 0, "risk_level": "high|medium|low"}},
    "authentication_points": ["points"],
    "data_processing_endpoints": ["endpoints"],
    "administrative_interfaces": ["interfaces"],
    "file_handling_capabilities": ["capabilities"]
  }},
  "vulnerability_likelihood": {{
    "injection_vulnerabilities": {{"probability": 0.8, "types": ["sql", "nosql", "ldap"]}},
    "authentication_issues": {{"probability": 0.6, "types": ["bypass", "weak_implementation"]}},
    "authorization_flaws": {{"probability": 0.7, "types": ["idor", "privilege_escalation"]}},
    "business_logic_issues": {{"probability": 0.5, "types": ["workflow_bypass", "race_conditions"]}},
    "information_disclosure": {{"probability": 0.4, "types": ["debug_info", "error_messages"]}}
  }},
  "testing_priorities": {{
    "critical_tests": ["test_types"],
    "recommended_sequence": ["phase1", "phase2", "phase3"],
    "resource_allocation": {{"automated": 70, "manual": 30}}
  }},
  "threat_modeling": {{
    "primary_threats": ["threats"],
    "attack_scenarios": ["scenarios"],
    "data_flow_risks": ["risks"]
  }}
}}
"""
            
            request = AIRequest(
                task_type="target_analysis",
                prompt=prompt,
                temperature=0.2,
                model_override=self.model_preferences.get("endpoint_analysis"),
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_response(response.content)
            
        except Exception as e:
            log.error(f"AI target analysis failed: {e}")
        
        return {"error": "AI analysis failed"}

    async def _generate_attack_vectors(self, target_info: Dict[str, Any], analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prioritized attack vectors based on analysis"""
        vectors = []
        
        vulnerability_likelihood = analysis.get("vulnerability_likelihood", {})
        
        # Generate vectors based on vulnerability probabilities
        for vuln_category, details in vulnerability_likelihood.items():
            probability = details.get("probability", 0.5)
            vuln_types = details.get("types", [])
            
            if probability > 0.6:  # High probability vulnerabilities
                for vuln_type in vuln_types:
                    vector = await self._create_attack_vector(vuln_category, vuln_type, target_info, probability)
                    if vector:
                        vectors.append(vector)
        
        # Sort by priority and probability
        vectors.sort(key=lambda x: (x.get("priority", 3), -x.get("probability", 0)))
        
        return vectors[:20]  # Limit to top 20 vectors

    async def _create_attack_vector(self, category: str, vuln_type: str, target_info: Dict[str, Any], probability: float) -> Optional[Dict[str, Any]]:
        """Create specific attack vector"""
        try:
            vector = {
                "category": category,
                "vulnerability_type": vuln_type,
                "probability": probability,
                "priority": self._calculate_vector_priority(category, probability),
                "attack_techniques": self._get_attack_techniques(category, vuln_type),
                "target_components": self._identify_target_components(target_info, category),
                "success_indicators": self._get_success_indicators(category, vuln_type),
                "testing_approach": await self._generate_testing_approach(category, vuln_type, target_info)
            }
            return vector
        except Exception as e:
            log.error(f"Failed to create attack vector for {category}:{vuln_type}: {e}")
            return None

    def _calculate_vector_priority(self, category: str, probability: float) -> int:
        """Calculate priority for attack vector"""
        base_priorities = {
            "injection_vulnerabilities": 1,
            "authentication_issues": 1,
            "authorization_flaws": 2,
            "business_logic_issues": 2,
            "information_disclosure": 3
        }
        
        base_priority = base_priorities.get(category, 3)
        
        # Adjust based on probability
        if probability > 0.8:
            return max(1, base_priority - 1)
        elif probability < 0.4:
            return min(3, base_priority + 1)
        
        return base_priority

    def _get_attack_techniques(self, category: str, vuln_type: str) -> List[str]:
        """Get specific attack techniques for vulnerability type"""
        technique_map = {
            "injection_vulnerabilities": {
                "sql": ["error_based", "time_based", "union_based", "boolean_based"],
                "nosql": ["operator_injection", "javascript_injection", "authentication_bypass"],
                "ldap": ["attribute_injection", "filter_injection", "bind_bypass"]
            },
            "authentication_issues": {
                "bypass": ["credential_stuffing", "default_credentials", "weak_passwords"],
                "weak_implementation": ["jwt_vulnerabilities", "session_fixation", "brute_force"]
            },
            "authorization_flaws": {
                "idor": ["parameter_tampering", "reference_prediction", "horizontal_escalation"],
                "privilege_escalation": ["role_manipulation", "permission_bypass", "vertical_escalation"]
            }
        }
        
        return technique_map.get(category, {}).get(vuln_type, ["generic_testing"])

    def _identify_target_components(self, target_info: Dict[str, Any], category: str) -> List[str]:
        """Identify target components for specific vulnerability category"""
        components = []
        
        endpoints = target_info.get("endpoints", [])
        
        if category == "injection_vulnerabilities":
            # Look for endpoints that accept parameters
            components.extend([ep.get("url", "") for ep in endpoints 
                             if ep.get("method") in ["POST", "PUT", "PATCH"] or "?" in ep.get("url", "")])
        
        elif category == "authentication_issues":
            # Look for auth-related endpoints
            components.extend([ep.get("url", "") for ep in endpoints 
                             if any(term in ep.get("url", "").lower() 
                                  for term in ["login", "auth", "signin", "token"])])
        
        elif category == "authorization_flaws":
            # Look for endpoints with IDs or user-specific operations
            components.extend([ep.get("url", "") for ep in endpoints 
                             if any(char in ep.get("url", "") for char in ["/", "?id=", "user", "account"])])
        
        return list(set(components))  # Remove duplicates

    def _get_success_indicators(self, category: str, vuln_type: str) -> List[str]:
        """Get success indicators for vulnerability testing"""
        indicators_map = {
            "injection_vulnerabilities": {
                "sql": ["error messages", "database dumps", "query results", "time delays"],
                "nosql": ["authentication bypass", "data extraction", "error responses"],
                "ldap": ["user enumeration", "authentication bypass", "data disclosure"]
            },
            "authentication_issues": {
                "bypass": ["successful login", "access tokens", "session cookies"],
                "weak_implementation": ["predictable tokens", "session reuse", "password reset"]
            },
            "authorization_flaws": {
                "idor": ["unauthorized data access", "other user data", "privilege elevation"],
                "privilege_escalation": ["admin access", "elevated permissions", "restricted functions"]
            }
        }
        
        return indicators_map.get(category, {}).get(vuln_type, ["unexpected responses"])

    async def _generate_testing_approach(self, category: str, vuln_type: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-powered testing approach"""
        if not self.ai_coordinator:
            return {"approach": "manual", "steps": []}
        
        try:
            prompt = f"""Generate a detailed testing approach for:
Category: {category}
Vulnerability Type: {vuln_type}
Target: {target_info.get('name', 'API')}

Provide testing approach as JSON:
{{
  "methodology": "black_box|white_box|grey_box",
  "phases": [
    {{
      "name": "phase_name",
      "duration_minutes": 30,
      "techniques": ["technique1", "technique2"],
      "tools": ["tool1", "tool2"],
      "success_criteria": ["criteria1", "criteria2"]
    }}
  ],
  "automation_level": "manual|semi_automated|fully_automated",
  "skill_requirements": "beginner|intermediate|advanced",
  "false_positive_likelihood": 0.2
}}
"""
            
            request = AIRequest(
                task_type="testing_approach",
                prompt=prompt,
                temperature=0.3,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_response(response.content)
                
        except Exception as e:
            log.error(f"Failed to generate testing approach: {e}")
        
        return {"approach": "manual", "phases": []}

    async def generate_intelligent_payloads(self, endpoint_info: Dict[str, Any], 
                                          vulnerability_types: List[str] = None) -> List[PayloadSuggestion]:
        """Generate intelligent, context-aware payloads"""
        try:
            log.info(f"🎯 Generating payloads for {endpoint_info.get('method')} {endpoint_info.get('url')}")
            
            suggestions = []
            
            # Analyze endpoint context
            endpoint_context = self._analyze_endpoint_context(endpoint_info)
            
            # Generate payloads for each vulnerability type
            vuln_types = vulnerability_types or ["sql_injection", "xss", "command_injection", "idor"]
            
            for vuln_type in vuln_types:
                payloads = await self._generate_payloads_for_type(vuln_type, endpoint_info, endpoint_context)
                suggestions.extend(payloads)
            
            # Sort by success probability
            suggestions.sort(key=lambda x: x.success_probability, reverse=True)
            
            log.info(f"🧪 Generated {len(suggestions)} payload suggestions")
            return suggestions[:15]  # Limit to top 15
            
        except Exception as e:
            log.error(f"Payload generation failed: {e}")
            return []

    def _analyze_endpoint_context(self, endpoint_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze endpoint context for payload customization"""
        url = endpoint_info.get('url', '').lower()
        method = endpoint_info.get('method', 'GET')
        
        context = {
            "is_authentication": any(term in url for term in ['login', 'auth', 'signin', 'token']),
            "is_search": any(term in url for term in ['search', 'find', 'query', 'filter']),
            "is_admin": any(term in url for term in ['admin', 'manage', 'config']),
            "is_file_operation": any(term in url for term in ['upload', 'download', 'file']),
            "is_user_data": any(term in url for term in ['user', 'profile', 'account']),
            "accepts_data": method in ['POST', 'PUT', 'PATCH'],
            "has_parameters": '?' in endpoint_info.get('url', ''),
            "business_function": endpoint_info.get('business_function', '')
        }
        
        return context

    async def _generate_payloads_for_type(self, vuln_type: str, endpoint_info: Dict[str, Any], 
                                        context: Dict[str, Any]) -> List[PayloadSuggestion]:
        """Generate payloads for specific vulnerability type"""
        suggestions = []
        
        if vuln_type == "sql_injection":
            suggestions.extend(self._generate_sql_injection_payloads(endpoint_info, context))
        elif vuln_type == "xss":
            suggestions.extend(self._generate_xss_payloads(endpoint_info, context))
        elif vuln_type == "command_injection":
            suggestions.extend(self._generate_command_injection_payloads(endpoint_info, context))
        elif vuln_type == "idor":
            suggestions.extend(self._generate_idor_payloads(endpoint_info, context))
        
        return suggestions

    def _generate_sql_injection_payloads(self, endpoint_info: Dict[str, Any], context: Dict[str, Any]) -> List[PayloadSuggestion]:
        """Generate SQL injection payloads"""
        suggestions = []
        
        base_payloads = {
            "error_based": ["'", '"', "\\", "1' OR '1'='1'--"],
            "time_based": ["'; WAITFOR DELAY '00:00:05'--", "' AND SLEEP(5)--"],
            "union_based": ["' UNION SELECT NULL--", "' UNION SELECT version()--"]
        }
        
        # Adjust payloads based on context
        if context.get("is_authentication"):
            auth_payloads = ["admin'--", "' OR '1'='1'#", "admin' OR 1=1--"]
            base_payloads["auth_bypass"] = auth_payloads
        
        for technique, payloads in base_payloads.items():
            for payload in payloads:
                suggestion = PayloadSuggestion(
                    payload_type="sql_injection",
                    payload_value=payload,
                    target_parameter=self._identify_target_parameter(endpoint_info, "sql"),
                    attack_technique=technique,
                    success_probability=self._calculate_sql_success_probability(technique, context),
                    detection_evasion=self._get_sql_evasion_techniques(payload),
                    context={"vulnerability_type": "sql_injection", "technique": technique}
                )
                suggestions.append(suggestion)
        
        return suggestions

    def _generate_xss_payloads(self, endpoint_info: Dict[str, Any], context: Dict[str, Any]) -> List[PayloadSuggestion]:
        """Generate XSS payloads"""
        suggestions = []
        
        payloads = {
            "basic": ["<script>alert(1)</script>", "javascript:alert(1)"],
            "evasion": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            "dom": ["#<script>alert(1)</script>", "location.hash"]
        }
        
        for technique, payload_list in payloads.items():
            for payload in payload_list:
                suggestion = PayloadSuggestion(
                    payload_type="xss",
                    payload_value=payload,
                    target_parameter=self._identify_target_parameter(endpoint_info, "xss"),
                    attack_technique=technique,
                    success_probability=self._calculate_xss_success_probability(technique, context),
                    detection_evasion=self._get_xss_evasion_techniques(payload),
                    context={"vulnerability_type": "xss", "technique": technique}
                )
                suggestions.append(suggestion)
        
        return suggestions

    def _generate_command_injection_payloads(self, endpoint_info: Dict[str, Any], context: Dict[str, Any]) -> List[PayloadSuggestion]:
        """Generate command injection payloads"""
        suggestions = []
        
        payloads = ["; ls", "| whoami", "&& id", "`uname -a`", "$(whoami)"]
        
        for payload in payloads:
            suggestion = PayloadSuggestion(
                payload_type="command_injection",
                payload_value=payload,
                target_parameter=self._identify_target_parameter(endpoint_info, "command"),
                attack_technique="command_chaining",
                success_probability=0.3 if context.get("is_file_operation") else 0.1,
                detection_evasion={"encoding": "none", "obfuscation": "none"},
                context={"vulnerability_type": "command_injection"}
            )
            suggestions.append(suggestion)
        
        return suggestions

    def _generate_idor_payloads(self, endpoint_info: Dict[str, Any], context: Dict[str, Any]) -> List[PayloadSuggestion]:
        """Generate IDOR payloads"""
        suggestions = []
        
        # Extract potential ID parameters
        url = endpoint_info.get('url', '')
        import re
        
        # Look for numeric IDs in URL
        id_matches = re.findall(r'/(\d+)(?:/|$|\?)', url)
        
        for id_value in id_matches:
            try:
                current_id = int(id_value)
                test_ids = [current_id + 1, current_id - 1, 1, 999, 0]
                
                for test_id in test_ids:
                    suggestion = PayloadSuggestion(
                        payload_type="idor",
                        payload_value=test_id,
                        target_parameter="path_parameter",
                        attack_technique="id_enumeration",
                        success_probability=0.6 if context.get("is_user_data") else 0.3,
                        detection_evasion={"encoding": "none", "randomization": True},
                        context={"original_id": current_id, "test_id": test_id}
                    )
                    suggestions.append(suggestion)
                    
            except ValueError:
                continue
        
        return suggestions

    def _identify_target_parameter(self, endpoint_info: Dict[str, Any], vuln_type: str) -> str:
        """Identify the most likely target parameter for payload"""
        
        # Parameter suggestions based on vulnerability type
        param_suggestions = {
            "sql": ["username", "email", "search", "query", "filter", "id"],
            "xss": ["comment", "message", "content", "description", "search"],
            "command": ["filename", "command", "input", "file", "path"]
        }
        
        # Check if endpoint has body parameters
        body = endpoint_info.get('body', {})
        if body.get('mode') == 'raw' and body.get('content'):
            try:
                body_json = json.loads(body['content'])
                if isinstance(body_json, dict):
                    for suggested_param in param_suggestions.get(vuln_type, []):
                        if suggested_param in body_json:
                            return suggested_param
                    # Return first available parameter
                    return list(body_json.keys())[0] if body_json else "input"
            except json.JSONDecodeError:
                pass
        
        # Default parameter names
        defaults = {
            "sql": "username", 
            "xss": "comment",
            "command": "filename"
        }
        
        return defaults.get(vuln_type, "input")

    def _calculate_sql_success_probability(self, technique: str, context: Dict[str, Any]) -> float:
        """Calculate success probability for SQL injection"""
        base_probabilities = {
            "error_based": 0.7,
            "time_based": 0.6,
            "union_based": 0.5,
            "auth_bypass": 0.8
        }
        
        base = base_probabilities.get(technique, 0.5)
        
        # Adjust based on context
        if context.get("is_authentication") and technique == "auth_bypass":
            base += 0.2
        if context.get("accepts_data"):
            base += 0.1
        
        return min(base, 1.0)

    def _calculate_xss_success_probability(self, technique: str, context: Dict[str, Any]) -> float:
        """Calculate success probability for XSS"""
        base_probabilities = {
            "basic": 0.6,
            "evasion": 0.7,
            "dom": 0.4
        }
        
        base = base_probabilities.get(technique, 0.5)
        
        if context.get("accepts_data"):
            base += 0.2
        if context.get("is_search"):
            base += 0.1
        
        return min(base, 1.0)

    def _get_sql_evasion_techniques(self, payload: str) -> Dict[str, Any]:
        """Get SQL evasion techniques for payload"""
        return {
            "encoding": "url_encoding" if "'" in payload else "none",
            "case_variation": "mixed" if payload.isupper() or payload.islower() else "none",
            "comment_insertion": "double_dash" if "--" in payload else "none",
            "whitespace_manipulation": "spaces" if " " in payload else "none"
        }

    def _get_xss_evasion_techniques(self, payload: str) -> Dict[str, Any]:
        """Get XSS evasion techniques for payload"""
        return {
            "encoding": "html_entity" if "<" in payload or ">" in payload else "none",
            "case_variation": "mixed" if "script" in payload.lower() else "none",
            "attribute_manipulation": "event_handler" if "on" in payload else "none",
            "tag_variation": "alternative_tags" if "img" in payload or "svg" in payload else "none"
        }

    async def explain_vulnerability_triage(self, vulnerability_data: Dict[str, Any]) -> str:
        """Provide comprehensive vulnerability explanation and triage"""
        if not self.ai_coordinator:
            return "AI coordinator not available for detailed triage explanation."
        
        try:
            cache_key = f"triage:{hashlib.md5(json.dumps(vulnerability_data, sort_keys=True).encode()).hexdigest()}"
            
            # Check cache
            if self.cache:
                cached_explanation = self.cache.get(cache_key)
                if cached_explanation:
                    return cached_explanation
            
            prompt = f"""Provide comprehensive triage analysis for this security vulnerability:

Vulnerability Data:
{json.dumps(vulnerability_data, indent=2)}

Provide detailed explanation covering:

1. **Vulnerability Analysis**
   - Technical description of the vulnerability
   - Root cause analysis
   - Attack vector explanation

2. **Impact Assessment**
   - Business impact potential
   - Data confidentiality/integrity/availability risks
   - Compliance implications

3. **Exploitability Assessment**
   - Difficulty of exploitation
   - Required attacker capabilities
   - Prerequisites and constraints

4. **Risk Prioritization**
   - Severity justification
   - Urgency factors
   - Business context considerations

5. **Remediation Guidance**
   - Immediate mitigation steps
   - Long-term fixes
   - Prevention strategies

6. **Verification Methods**
   - How to validate the fix
   - Testing recommendations
   - Monitoring suggestions

Format as detailed markdown with clear sections and actionable insights.
"""
            
            request = AIRequest(
                task_type="vulnerability_triage",
                prompt=prompt,
                temperature=0.1,
                model_override=self.model_preferences.get("vulnerability_triage"),
                require_json=False
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                explanation = response.content.strip()
                
                # Cache the explanation
                if self.cache:
                    self.cache.set(cache_key, explanation, ttl=24*3600)  # 24 hours
                
                return explanation
            
        except Exception as e:
            log.error(f"Vulnerability triage explanation failed: {e}")
        
        return f"Unable to provide detailed triage analysis: {str(e)}"

    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """Parse AI JSON response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse AI response: {e}")
        
        return {}

    async def _recommend_payloads(self, target_info: Dict[str, Any], attack_vectors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate payload recommendations based on attack vectors"""
        recommendations = []
        
        for vector in attack_vectors[:10]:  # Top 10 vectors
            category = vector.get("category")
            vuln_type = vector.get("vulnerability_type")
            
            # Get template payloads
            if category in self.payload_templates.get("context_aware", {}):
                templates = self.payload_templates["context_aware"][category]
                if vuln_type in templates:
                    for payload in templates[vuln_type][:3]:  # Top 3 per type
                        recommendations.append({
                            "payload": payload,
                            "category": category,
                            "type": vuln_type,
                            "confidence": vector.get("probability", 0.5),
                            "evasion_techniques": self.payload_templates.get("evasion_techniques", {})
                        })
        
        return recommendations

    async def _assess_target_risks(self, target_info: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess comprehensive target risks"""
        risk_factors = []
        overall_risk = 0
        
        # Business criticality
        criticality = analysis.get("target_classification", {}).get("business_criticality", "medium")
        criticality_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        criticality_score = criticality_scores.get(criticality, 2)
        overall_risk += criticality_score
        
        # Vulnerability likelihood
        vuln_likelihood = analysis.get("vulnerability_likelihood", {})
        for category, details in vuln_likelihood.items():
            probability = details.get("probability", 0.5)
            if probability > 0.7:
                overall_risk += 2
                risk_factors.append(f"High probability of {category}")
            elif probability > 0.5:
                overall_risk += 1
        
        # Convert to risk level
        if overall_risk >= 8:
            risk_level = "Critical"
        elif overall_risk >= 6:
            risk_level = "High"
        elif overall_risk >= 4:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            "risk_level": risk_level,
            "risk_score": overall_risk,
            "risk_factors": risk_factors,
            "business_criticality": criticality,
            "vulnerability_exposure": len([v for v in vuln_likelihood.values() if v.get("probability", 0) > 0.5])
        }

    def _create_testing_timeline(self, attack_vectors: List[Dict[str, Any]], risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Create testing timeline based on vectors and risk"""
        timeline = {
            "total_estimated_hours": 0,
            "phases": [],
            "milestones": []
        }
        
        # Phase 1: Reconnaissance and initial testing
        phase1_vectors = [v for v in attack_vectors if v.get("priority") == 1]
        phase1_hours = len(phase1_vectors) * 0.5  # 30 minutes per high priority vector
        
        timeline["phases"].append({
            "name": "Initial Assessment",
            "duration_hours": phase1_hours,
            "vectors": len(phase1_vectors),
            "focus": "High-priority vulnerabilities"
        })
        
        # Phase 2: Comprehensive testing
        phase2_vectors = [v for v in attack_vectors if v.get("priority") == 2]
        phase2_hours = len(phase2_vectors) * 0.3  # 18 minutes per medium priority vector
        
        timeline["phases"].append({
            "name": "Comprehensive Testing",
            "duration_hours": phase2_hours,
            "vectors": len(phase2_vectors),
            "focus": "Medium-priority vulnerabilities"
        })
        
        # Phase 3: Edge cases and cleanup
        phase3_vectors = [v for v in attack_vectors if v.get("priority") >= 3]
        phase3_hours = len(phase3_vectors) * 0.2  # 12 minutes per low priority vector
        
        timeline["phases"].append({
            "name": "Edge Cases",
            "duration_hours": phase3_hours,
            "vectors": len(phase3_vectors),
            "focus": "Low-priority and edge case testing"
        })
        
        timeline["total_estimated_hours"] = phase1_hours + phase2_hours + phase3_hours
        
        return timeline

    def _define_success_metrics(self, target_info: Dict[str, Any], risk_assessment: Dict[str, Any]) -> List[str]:
        """Define success metrics for testing"""
        metrics = [
            "Vulnerability detection rate > 80%",
            "False positive rate < 15%",
            "Complete coverage of high-priority attack vectors"
        ]
        
        risk_level = risk_assessment.get("risk_level", "Medium")
        
        if risk_level in ["Critical", "High"]:
            metrics.extend([
                "Zero critical vulnerabilities remaining",
                "All authentication bypasses identified",
                "Complete business logic testing coverage"
            ])
        
        return metrics

    def _calculate_strategy_confidence(self, analysis: Dict[str, Any], vectors: List[Dict[str, Any]]) -> float:
        """Calculate confidence in the generated strategy"""
        confidence_factors = []
        
        # Analysis completeness
        if analysis.get("target_classification"):
            confidence_factors.append(0.3)
        if analysis.get("vulnerability_likelihood"):
            confidence_factors.append(0.3)
        if analysis.get("attack_surface_analysis"):
            confidence_factors.append(0.2)
        
        # Vector quality
        high_prob_vectors = len([v for v in vectors if v.get("probability", 0) > 0.6])
        if high_prob_vectors > 0:
            confidence_factors.append(min(0.2, high_prob_vectors * 0.05))
        
        return sum(confidence_factors)

# Usage example and testing
if __name__ == "__main__":
    async def main():
        strategist = EnhancedAIStrategist()
        
        # Example target
        sample_target = {
            "name": "E-commerce API",
            "endpoints": [
                {"method": "POST", "url": "https://api.example.com/auth/login"},
                {"method": "GET", "url": "https://api.example.com/users/123"},
                {"method": "POST", "url": "https://api.example.com/orders"},
                {"method": "PUT", "url": "https://api.example.com/users/123/profile"}
            ],
            "authentication": "JWT tokens",
            "business_criticality": "high"
        }
        
        # Develop strategy
        strategy = await strategist.develop_comprehensive_strategy(sample_target)
        
        print(f"🎯 Strategy for {strategy.target_analysis.get('target_classification', {}).get('application_type', 'API')}")
        print(f"📊 Risk Level: {strategy.risk_assessment.get('risk_level')}")
        print(f"🔍 Attack Vectors: {len(strategy.attack_vectors)}")
        print(f"🧪 Payload Recommendations: {len(strategy.payload_recommendations)}")
        print(f"🤖 AI Confidence: {strategy.ai_confidence:.2f}")
        print(f"⏱️ Estimated Duration: {strategy.testing_timeline.get('total_estimated_hours', 0):.1f} hours")
        
        # Generate payloads for first endpoint
        if sample_target["endpoints"]:
            first_endpoint = sample_target["endpoints"][0]
            payloads = await strategist.generate_intelligent_payloads(first_endpoint)
            
            print(f"\n🧪 Generated {len(payloads)} payloads for {first_endpoint['method']} {first_endpoint['url']}")
            for i, payload in enumerate(payloads[:3]):
                print(f"{i+1}. {payload.payload_type}: {payload.payload_value}")
                print(f"   Success Probability: {payload.success_probability:.2f}")
                print(f"   Target Parameter: {payload.target_parameter}")

    asyncio.run(main())


# Simple wrapper for app.py compatibility
class AIStrategist:
    """Simple wrapper around EnhancedAIStrategist"""
    
    def __init__(self):
        try:
            self.enhanced_strategist = EnhancedAIStrategist()
            self.available = True
            log.info("✅ Enhanced AI Strategist initialized")
        except Exception as e:
            log.error(f"Enhanced AI Strategist failed, using basic mode: {e}")
            self.available = False
    
    async def develop_strategy(self, collection_name: str, endpoints: List[Dict] = None) -> Dict[str, Any]:
        """Develop security testing strategy"""
        # Fallback simple strategy (avoiding complex object serialization)
        endpoints = endpoints or []
        return {
            "collection_name": collection_name,
            "generated_at": datetime.now().isoformat(),
            "endpoint_count": len(endpoints),
            "attack_vectors": len(endpoints) * 2,
            "recommended_tests": min(len(endpoints) * 3, 50),
            "priority_areas": ["Authentication", "Input Validation"],
            "confidence_score": 0.7
        }

# Fix SecurityStrategy object serialization
def _strategy_to_dict(self, strategy):
    """Convert SecurityStrategy to dictionary"""
