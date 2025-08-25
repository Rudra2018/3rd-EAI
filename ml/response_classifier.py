#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced ML Response Classifier with AI Integration
Real-time response analysis with machine learning and AI insights
"""
import os
import re
import json
import logging
import numpy as np
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

# ML imports
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.naive_bayes import MultinomialNB
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

log = logging.getLogger(__name__)

@dataclass
class ResponseAnalysis:
    vulnerability_scores: Dict[str, float]
    ai_insights: Dict[str, Any]
    confidence: float
    classification: str
    patterns_detected: List[str]
    false_positive_probability: float

class EnhancedResponseClassifier:
    """
    Advanced response classifier with ML and AI integration
    Features:
    - Traditional pattern matching for speed
    - ML-based classification for accuracy
    - AI-powered analysis for complex cases
    - Real-time learning and adaptation
    """
    
    def __init__(self, model_path: str = 'models/response_classifier.pkl'):
        self.model_path = model_path
        self.vectorizer_path = 'models/response_vectorizer.pkl'
        
        # Traditional patterns (fast)
        self.DB_ERRORS = (
            "sql syntax", "mysql", "postgresql", "sqlite", "odbc", "oracle", 
            "mariadb", "database error", "syntax error", "table doesn't exist",
            "column not found", "duplicate entry", "foreign key constraint"
        )
        
        self.XSS_MARKERS = (
            "<script", "</script>", "javascript:", "onerror=", "onload=",
            "alert(", "confirm(", "prompt(", "eval(", "<img src=x onerror="
        )
        
        self.SENSITIVE_INFO = (
            "password", "secret", "token", "api_key", "private_key",
            "database", "config", "env", "debug", "stack trace",
            "internal server error", "exception", "traceback"
        )
        
        self.INJECTION_PATTERNS = {
            "sql_injection": re.compile(
                r"(union\s+select|or\s+1=1|drop\s+table|insert\s+into|delete\s+from)", 
                re.IGNORECASE
            ),
            "command_injection": re.compile(
                r"(;|\||&|`|\$\(|wget|curl|nc\s+)", 
                re.IGNORECASE
            ),
            "xpath_injection": re.compile(
                r"(\'\s+or\s+\'\w+\'\s*=\s*\'\w+|\[\s*\])", 
                re.IGNORECASE
            ),
            "ldap_injection": re.compile(
                r"(\*\)\(|\)\(\*|\|\()", 
                re.IGNORECASE
            )
        }
        
        # ML components
        self.ml_model = None
        self.vectorizer = None
        self.is_trained = False
        
        # AI coordinator
        self.ai_coordinator = None
        if AI_AVAILABLE:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
            except Exception as e:
                log.warning(f"AI coordinator initialization failed: {e}")
        
        self.load_models()

    def classify_response(self, response_text: str, request_context: Optional[Dict[str, Any]] = None) -> ResponseAnalysis:
        """Enhanced response classification with multiple analysis methods"""
        
        # Traditional pattern-based analysis (fast)
        traditional_scores = self._traditional_classify(response_text)
        
        # ML-based classification (if available)
        ml_scores = {}
        ml_confidence = 0.0
        if ML_AVAILABLE and self.is_trained:
            ml_scores, ml_confidence = self._ml_classify(response_text)
        
        # AI-powered analysis (for complex cases)
        ai_insights = {}
        if self.ai_coordinator and self._should_use_ai(traditional_scores, ml_confidence):
            ai_insights = self._ai_classify(response_text, request_context)
        
        # Combine results
        final_scores = self._combine_classifications(traditional_scores, ml_scores, ai_insights)
        
        # Determine overall classification
        classification = max(final_scores.items(), key=lambda x: x[1])
        patterns_detected = self._extract_patterns(response_text)
        
        # Calculate false positive probability
        fp_probability = self._calculate_false_positive_probability(
            response_text, final_scores, request_context
        )
        
        return ResponseAnalysis(
            vulnerability_scores=final_scores,
            ai_insights=ai_insights,
            confidence=max(ml_confidence, 0.7),  # Use ML confidence if available
            classification=classification[0],
            patterns_detected=patterns_detected,
            false_positive_probability=fp_probability
        )

    def _traditional_classify(self, text: str) -> Dict[str, float]:
        """Traditional pattern-based classification"""
        if not text:
            return {"clean": 0.9}
            
        text_lower = text.lower()
        scores = {}
        
        # SQL Injection detection
        sql_score = 0.0
        if any(error in text_lower for error in self.DB_ERRORS):
            sql_score = 0.9
        elif self.INJECTION_PATTERNS["sql_injection"].search(text):
            sql_score = 0.7
        scores["sql_injection"] = sql_score
        
        # XSS detection
        xss_score = 0.0
        if any(marker in text_lower for marker in self.XSS_MARKERS):
            xss_score = 0.85
        elif re.search(r'<[^>]*script[^>]*>', text_lower):
            xss_score = 0.7
        scores["xss"] = xss_score
        
        # Command injection
        cmd_score = 0.0
        if self.INJECTION_PATTERNS["command_injection"].search(text):
            cmd_score = 0.8
        scores["command_injection"] = cmd_score
        
        # Information disclosure
        info_score = 0.0
        if any(info in text_lower for info in self.SENSITIVE_INFO):
            info_score = 0.6
        scores["information_disclosure"] = info_score
        
        # Configuration issues
        config_score = 0.0
        if any(term in text_lower for term in ["index of /", "directory listing", "apache/"]):
            config_score = 0.5
        scores["misconfiguration"] = config_score
        
        return scores

    def _ml_classify(self, text: str) -> tuple:
        """ML-based classification"""
        if not self.ml_model or not self.vectorizer:
            return {}, 0.0
            
        try:
            # Vectorize text
            text_vector = self.vectorizer.transform([text])
            
            # Predict probabilities
            probabilities = self.ml_model.predict_proba(text_vector)[0]
            classes = self.ml_model.classes_
            
            # Create scores dictionary
            scores = dict(zip(classes, probabilities))
            confidence = max(probabilities)
            
            return scores, confidence
            
        except Exception as e:
            log.error(f"ML classification failed: {e}")
            return {}, 0.0

    async def _ai_classify(self, text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """AI-powered classification for complex cases"""
        if not self.ai_coordinator:
            return {}
            
        try:
            prompt = self._build_ai_prompt(text, context)
            
            request = AIRequest(
                task_type="response_analysis",
                prompt=prompt,
                context=context,
                temperature=0.1,  # Low temperature for consistent analysis
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_response(response.content)
            else:
                log.warning("AI classification failed")
                return {}
                
        except Exception as e:
            log.error(f"AI classification error: {e}")
            return {}

    def _build_ai_prompt(self, text: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Build AI prompt for response analysis"""
        prompt = f"""Analyze this HTTP response for security vulnerabilities:

Response Content:
{text[:2000]}  # Limit to first 2000 chars

Please analyze for:
1. SQL Injection indicators
2. Cross-Site Scripting (XSS) patterns
3. Command injection evidence
4. Information disclosure
5. Authentication/authorization bypasses
6. Any other security vulnerabilities

"""
        
        if context:
            prompt += f"\nRequest Context: {json.dumps(context, indent=2)}\n"
            
        prompt += """
Return analysis as JSON:
{
  "vulnerabilities": [
    {
      "type": "vulnerability_type",
      "confidence": 0.0-1.0,
      "evidence": "specific_evidence",
      "severity": "low|medium|high|critical"
    }
  ],
  "false_positive_indicators": [],
  "overall_risk": "low|medium|high|critical",
  "recommendations": []
}
"""
        return prompt

    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """Parse AI response"""
        try:
            # Extract JSON from response
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
                
        except Exception as e:
            log.error(f"Failed to parse AI response: {e}")
            
        return {}

    def _should_use_ai(self, traditional_scores: Dict[str, float], ml_confidence: float) -> bool:
        """Determine if AI analysis is needed"""
        # Use AI for uncertain cases
        max_traditional = max(traditional_scores.values()) if traditional_scores else 0
        
        # Use AI if:
        # 1. Traditional and ML disagree significantly
        # 2. Confidence is low
        # 3. Multiple potential vulnerabilities detected
        
        uncertain = max_traditional < 0.8 and ml_confidence < 0.8
        conflicting = abs(max_traditional - ml_confidence) > 0.3
        multiple_vulns = sum(1 for score in traditional_scores.values() if score > 0.5) > 1
        
        return uncertain or conflicting or multiple_vulns

    def _combine_classifications(self, traditional: Dict[str, float], ml: Dict[str, float], ai: Dict[str, Any]) -> Dict[str, float]:
        """Combine multiple classification results"""
        
        # Start with traditional scores
        final_scores = traditional.copy()
        
        # Incorporate ML scores with weight
        for vuln_type, score in ml.items():
            if vuln_type in final_scores:
                final_scores[vuln_type] = 0.6 * final_scores[vuln_type] + 0.4 * score
            else:
                final_scores[vuln_type] = 0.4 * score
        
        # Incorporate AI insights
        if ai and 'vulnerabilities' in ai:
            for vuln in ai['vulnerabilities']:
                vuln_type = vuln.get('type', 'unknown')
                confidence = vuln.get('confidence', 0.5)
                
                if vuln_type in final_scores:
                    # Weighted average with AI having high weight for complex analysis
                    final_scores[vuln_type] = 0.5 * final_scores[vuln_type] + 0.5 * confidence
                else:
                    final_scores[vuln_type] = 0.5 * confidence
        
        # Normalize scores
        max_score = max(final_scores.values()) if final_scores else 1.0
        if max_score > 1.0:
            final_scores = {k: v/max_score for k, v in final_scores.items()}
        
        return final_scores

    def _extract_patterns(self, text: str) -> List[str]:
        """Extract specific vulnerability patterns"""
        patterns = []
        
        for pattern_name, pattern_regex in self.INJECTION_PATTERNS.items():
            if pattern_regex.search(text):
                patterns.append(pattern_name)
        
        # Check for specific error patterns
        if any(error in text.lower() for error in self.DB_ERRORS):
            patterns.append("database_error")
            
        if any(marker in text.lower() for marker in self.XSS_MARKERS):
            patterns.append("xss_marker")
            
        return patterns

    def _calculate_false_positive_probability(self, text: str, scores: Dict[str, float], context: Optional[Dict[str, Any]] = None) -> float:
        """Calculate probability that this is a false positive"""
        
        # Factors that increase false positive probability
        fp_factors = []
        
        # Generic error pages
        if "404" in text or "not found" in text.lower():
            fp_factors.append(0.3)
            
        # Development/test environments
        if context and context.get('url'):
            url = context['url'].lower()
            if any(env in url for env in ['test', 'dev', 'staging', 'localhost']):
                fp_factors.append(0.2)
        
        # Very short responses
        if len(text) < 100:
            fp_factors.append(0.15)
            
        # Common application frameworks (may have expected error formats)
        if any(framework in text.lower() for framework in ['laravel', 'django', 'rails', 'express']):
            fp_factors.append(0.1)
        
        # Calculate combined false positive probability
        if not fp_factors:
            return 0.1  # Base false positive rate
            
        # Combine factors (not simply additive)
        combined_fp = 1.0 - np.prod([1.0 - factor for factor in fp_factors])
        return min(combined_fp, 0.8)  # Cap at 80%

    def train_model(self, training_data: List[Dict[str, Any]]):
        """Train the ML model with new data"""
        if not ML_AVAILABLE:
            log.warning("ML libraries not available for training")
            return
            
        try:
            # Prepare training data
            texts = []
            labels = []
            
            for item in training_data:
                texts.append(item.get('response_text', ''))
                labels.append(item.get('vulnerability_type', 'clean'))
            
            # Vectorize texts
            if not self.vectorizer:
                self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
                
            X = self.vectorizer.fit_transform(texts)
            
            # Train model
            self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.ml_model.fit(X, labels)
            
            self.is_trained = True
            self.save_models()
            
            log.info(f"Model trained on {len(training_data)} samples")
            
        except Exception as e:
            log.error(f"Model training failed: {e}")

    def save_models(self):
        """Save trained models"""
        if not ML_AVAILABLE or not self.is_trained:
            return
            
        try:
            import os
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            joblib.dump(self.ml_model, self.model_path)
            joblib.dump(self.vectorizer, self.vectorizer_path)
            
            log.info("Models saved successfully")
            
        except Exception as e:
            log.error(f"Failed to save models: {e}")

    def load_models(self):
        """Load pre-trained models"""
        if not ML_AVAILABLE:
            return
            
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
                self.ml_model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                self.is_trained = True
                
                log.info("Pre-trained models loaded successfully")
                
        except Exception as e:
            log.error(f"Failed to load models: {e}")

    def get_model_stats(self) -> Dict[str, Any]:
        """Get model statistics"""
        return {
            "ml_available": ML_AVAILABLE,
            "ai_available": AI_AVAILABLE,
            "is_trained": self.is_trained,
            "model_type": type(self.ml_model).__name__ if self.ml_model else None,
            "feature_count": self.vectorizer.max_features if self.vectorizer else 0,
            "ai_coordinator_active": self.ai_coordinator is not None
        }

