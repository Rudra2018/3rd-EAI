#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced False Positive Detector with ML and AI Integration
"""

import asyncio
import json
import logging
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

log = logging.getLogger(__name__)

@dataclass
class FalsePositiveAnalysis:
    is_false_positive: bool
    confidence: float
    reasons: List[str]
    analysis: Dict[str, Any]
    ai_enhanced: bool = False

class EnhancedFalsePositiveDetector:
    """
    Advanced false positive detection with ML and AI
    Features:
    - Pattern-based FP detection
    - Context analysis
    - AI-powered complex case analysis
    - Learning from feedback
    """
    
    def __init__(self):
        self.ai_coordinator = None
        self.fp_patterns = self._load_fp_patterns()
        self.context_weights = self._load_context_weights()
        
        if AI_AVAILABLE:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
                log.info("✅ AI-enhanced FP detection enabled")
            except Exception as e:
                log.warning(f"AI coordinator initialization failed: {e}")

    def _load_fp_patterns(self) -> Dict[str, List[str]]:
        """Load false positive detection patterns"""
        return {
            "common_test_pages": [
                "test page", "demo application", "placeholder", "lorem ipsum",
                "example content", "sample data", "default page", "coming soon"
            ],
            "legitimate_errors": [
                "404 not found", "403 forbidden", "400 bad request", "500 internal server error",
                "validation error", "form validation", "input validation", "csrf token"
            ],
            "development_indicators": [
                "development mode", "debug mode", "staging environment", "test environment",
                "localhost", "127.0.0.1", "dev server", "webpack", "hot reload"
            ],
            "framework_errors": [
                "laravel", "symfony", "django", "flask", "express", "rails",
                "spring boot", "asp.net", "codeigniter", "cakephp"
            ],
            "expected_security": [
                "captcha", "rate limit", "too many requests", "account locked",
                "session expired", "invalid token", "access denied"
            ]
        }

    def _load_context_weights(self) -> Dict[str, float]:
        """Load context-based weights for FP calculation"""
        return {
            "test_environment": 0.4,
            "development_mode": 0.3,
            "short_response": 0.2,
            "generic_error": 0.25,
            "framework_pattern": 0.15,
            "security_feature": 0.35
        }

    async def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> FalsePositiveAnalysis:
        """Comprehensive false positive analysis"""
        try:
            # Extract response data
            http_trace = vulnerability_data.get("http_trace", {})
            response = http_trace.get("response", {})
            request = http_trace.get("request", {})
            
            response_body = response.get("body", "").lower()
            response_headers = response.get("headers", {})
            request_url = request.get("url", "")
            vuln_type = vulnerability_data.get("type", "")
            
            # Pattern-based analysis
            pattern_analysis = self._analyze_patterns(response_body, request_url)
            
            # Context analysis
            context_analysis = self._analyze_context(request, response, vulnerability_data)
            
            # AI analysis for complex cases
            ai_analysis = {}
            if self.ai_coordinator and self._should_use_ai(pattern_analysis, context_analysis):
                ai_analysis = await self._ai_analyze_false_positive(
                    response_body, vulnerability_data, request_url
                )
            
            # Combine analyses
            final_analysis = self._combine_analyses(pattern_analysis, context_analysis, ai_analysis)
            
            return FalsePositiveAnalysis(
                is_false_positive=final_analysis["is_false_positive"],
                confidence=final_analysis["confidence"],
                reasons=final_analysis["reasons"],
                analysis={
                    "pattern_analysis": pattern_analysis,
                    "context_analysis": context_analysis,
                    "ai_analysis": ai_analysis,
                    "vulnerability_type": vuln_type
                },
                ai_enhanced=bool(ai_analysis)
            )
            
        except Exception as e:
            log.error(f"FP analysis failed: {e}")
            return FalsePositiveAnalysis(
                is_false_positive=False,
                confidence=0.0,
                reasons=[f"Analysis error: {str(e)}"],
                analysis={"error": str(e)}
            )

    def _analyze_patterns(self, response_body: str, url: str) -> Dict[str, Any]:
        """Pattern-based false positive analysis"""
        fp_indicators = []
        fp_score = 0.0
        
        # Check each pattern category
        for category, patterns in self.fp_patterns.items():
            matches = [pattern for pattern in patterns if pattern in response_body]
            if matches:
                fp_indicators.extend([(category, match) for match in matches])
                
                # Add weighted score based on category
                category_weight = {
                    "common_test_pages": 0.4,
                    "legitimate_errors": 0.3,
                    "development_indicators": 0.5,
                    "framework_errors": 0.2,
                    "expected_security": 0.6
                }.get(category, 0.2)
                
                fp_score += len(matches) * category_weight
        
        # URL-based indicators
        url_lower = url.lower()
        if any(indicator in url_lower for indicator in ['test', 'dev', 'staging', 'localhost']):
            fp_indicators.append(("url_context", "test_environment"))
            fp_score += 0.3
        
        return {
            "fp_score": min(fp_score, 1.0),
            "indicators": fp_indicators,
            "pattern_count": len(fp_indicators)
        }

    def _analyze_context(self, request: Dict[str, Any], response: Dict[str, Any], 
                        vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Context-based false positive analysis"""
        context_factors = []
        context_score = 0.0
        
        response_body = response.get("body", "")
        status_code = response.get("status_code", 200)
        vuln_type = vuln_data.get("type", "")
        
        # Response length analysis
        if len(response_body) < 100:
            context_factors.append("very_short_response")
            context_score += self.context_weights["short_response"]
        
        # Status code analysis
        if status_code in [404, 403, 400, 500]:
            context_factors.append(f"error_status_{status_code}")
            context_score += self.context_weights["generic_error"]
        
        # Vulnerability type specific analysis
        if vuln_type == "SQL Injection":
            # Check for generic syntax errors without SQL context
            if "syntax error" in response_body.lower() and "sql" not in response_body.lower():
                context_factors.append("generic_syntax_error")
                context_score += 0.4
        
        elif vuln_type == "XSS":
            # Check for escaped or sanitized output
            if "&lt;" in response_body or "&gt;" in response_body:
                context_factors.append("escaped_html")
                context_score += 0.3
        
        # Security headers (indicate good security practices)
        headers = response.get("headers", {})
        security_headers = ["x-frame-options", "content-security-policy", "x-xss-protection"]
        if any(header.lower() in [h.lower() for h in headers.keys()] for header in security_headers):
            context_factors.append("security_headers_present")
            context_score += 0.2
        
        return {
            "context_score": min(context_score, 1.0),
            "factors": context_factors,
            "factor_count": len(context_factors)
        }

    async def _ai_analyze_false_positive(self, response_body: str, vuln_data: Dict[str, Any], 
                                       url: str) -> Dict[str, Any]:
        """AI-powered false positive analysis"""
        if not self.ai_coordinator:
            return {}
        
        try:
            prompt = f"""Analyze this potential security vulnerability for false positive likelihood:

Vulnerability Type: {vuln_data.get('type', 'Unknown')}
URL: {url}
Response Body (first 1500 chars): {response_body[:1500]}

Consider these factors:
1. Is this a legitimate application error vs. a security vulnerability?
2. Are there indicators of test/development environment?
3. Does the response show proper error handling?
4. Are there security measures in place (rate limiting, validation, etc.)?
5. Is the "vulnerability" actually expected application behavior?

Provide analysis as JSON:
{{
  "false_positive_likelihood": 0.0-1.0,
  "reasoning": ["reason1", "reason2"],
  "key_indicators": ["indicator1", "indicator2"],
  "recommendation": "likely_fp|uncertain|likely_vuln"
}}"""

            request = AIRequest(
                task_type="false_positive_analysis",
                prompt=prompt,
                temperature=0.1,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_fp_response(response.content)
            
        except Exception as e:
            log.error(f"AI FP analysis failed: {e}")
        
        return {}

    def _parse_ai_fp_response(self, content: str) -> Dict[str, Any]:
        """Parse AI false positive analysis response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse AI FP response: {e}")
        
        return {}

    def _should_use_ai(self, pattern_analysis: Dict[str, Any], 
                      context_analysis: Dict[str, Any]) -> bool:
        """Determine if AI analysis is needed"""
        pattern_score = pattern_analysis.get("fp_score", 0)
        context_score = context_analysis.get("context_score", 0)
        
        # Use AI for uncertain cases
        uncertain = 0.3 < pattern_score < 0.7 or 0.3 < context_score < 0.7
        conflicting = abs(pattern_score - context_score) > 0.4
        
        return uncertain or conflicting

    def _combine_analyses(self, pattern_analysis: Dict[str, Any], 
                         context_analysis: Dict[str, Any], 
                         ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Combine all analyses into final result"""
        
        # Weight the different analysis methods
        pattern_weight = 0.4
        context_weight = 0.3
        ai_weight = 0.3
        
        pattern_score = pattern_analysis.get("fp_score", 0)
        context_score = context_analysis.get("context_score", 0)
        ai_score = ai_analysis.get("false_positive_likelihood", 0)
        
        # Calculate weighted average
        if ai_analysis:
            final_score = (pattern_weight * pattern_score + 
                          context_weight * context_score + 
                          ai_weight * ai_score)
        else:
            # Reweight without AI
            final_score = (0.6 * pattern_score + 0.4 * context_score)
        
        # Collect all reasons
        reasons = []
        
        # Add pattern-based reasons
        for category, indicator in pattern_analysis.get("indicators", []):
            reasons.append(f"Pattern detected: {category} - {indicator}")
        
        # Add context-based reasons
        for factor in context_analysis.get("factors", []):
            reasons.append(f"Context factor: {factor}")
        
        # Add AI reasoning
        if ai_analysis and "reasoning" in ai_analysis:
            reasons.extend([f"AI analysis: {reason}" for reason in ai_analysis["reasoning"]])
        
        # Determine if it's a false positive
        is_fp = final_score > 0.5
        confidence = final_score if is_fp else (1.0 - final_score)
        
        return {
            "is_false_positive": is_fp,
            "confidence": confidence,
            "reasons": reasons,
            "final_score": final_score
        }

    def learn_from_feedback(self, vulnerability_data: Dict[str, Any], 
                           is_actually_fp: bool, confidence: float):
        """Learn from user feedback to improve detection"""
        # This would typically update ML models or pattern weights
        # For now, we'll log the feedback for analysis
        
        feedback = {
            "timestamp": asyncio.get_event_loop().time(),
            "vulnerability_type": vulnerability_data.get("type"),
            "predicted_fp": vulnerability_data.get("predicted_fp", False),
            "actual_fp": is_actually_fp,
            "confidence": confidence,
            "url": vulnerability_data.get("http_trace", {}).get("request", {}).get("url", "")
        }
        
        log.info(f"FP Feedback received: {json.dumps(feedback)}")
        
        # TODO: Implement actual learning mechanism
        # - Update pattern weights based on accuracy
        # - Retrain ML models with new data
        # - Adjust AI prompts based on common mistakes

    def get_statistics(self) -> Dict[str, Any]:
        """Get false positive detector statistics"""
        return {
            "ai_available": self.ai_coordinator is not None,
            "pattern_categories": len(self.fp_patterns),
            "total_patterns": sum(len(patterns) for patterns in self.fp_patterns.values()),
            "context_weights": self.context_weights
        }

# Synchronous wrapper for compatibility
class FalsePositiveDetectorSync:
    """Synchronous wrapper for the async FP detector"""
    
    def __init__(self):
        self.async_detector = EnhancedFalsePositiveDetector()
    
    def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> FalsePositiveAnalysis:
        """Synchronous analysis method"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an async context, create a new event loop
                import threading
                result = [None]
                exception = [None]
                
                def run_analysis():
                    try:
                        new_loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(new_loop)
                        result[0] = new_loop.run_until_complete(
                            self.async_detector.analyze_vulnerability(vulnerability_data)
                        )
                        new_loop.close()
                    except Exception as e:
                        exception[0] = e
                
                thread = threading.Thread(target=run_analysis)
                thread.start()
                thread.join()
                
                if exception[0]:
                    raise exception[0]
                
                return result[0]
            else:
                # Normal async execution
                return loop.run_until_complete(
                    self.async_detector.analyze_vulnerability(vulnerability_data)
                )
        except Exception as e:
            log.error(f"Sync FP analysis failed: {e}")
            return FalsePositiveAnalysis(
                is_false_positive=False,
                confidence=0.0,
                reasons=[f"Sync analysis error: {str(e)}"],
                analysis={"error": str(e)}
            )


# Simple wrapper for app.py compatibility
class FalsePositiveDetector:
    """Simple wrapper around EnhancedFalsePositiveDetector"""
    
    def __init__(self):
        try:
            self.enhanced_detector = EnhancedFalsePositiveDetector()
            self.available = True
            log.info("✅ Enhanced FP detector initialized")
        except Exception as e:
            log.error(f"Enhanced FP detector failed, using basic mode: {e}")
            self.available = False
    
    def is_false_positive(self, vulnerability: Dict[str, Any]) -> bool:
        """Simple false positive check"""
        if self.available:
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    self.enhanced_detector.analyze_vulnerability(vulnerability)
                )
                loop.close()
                return result.is_false_positive
            except Exception as e:
                log.error(f"Enhanced analysis failed: {e}")
        
        # Fallback simple logic
        vuln_type = vulnerability.get('type', '').lower()
        url = vulnerability.get('url', '').lower()
        
        return any([
            'test' in url,
            'demo' in url, 
            'example' in url,
            vuln_type == 'info'
        ])
    
    def get_confidence_score(self, vulnerability: Dict[str, Any]) -> float:
        """Get confidence score"""
        if self.is_false_positive(vulnerability):
            return 0.3
        return 0.8
