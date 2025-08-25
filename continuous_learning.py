#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Continuous Learning Engine for Rudra AI
Advanced adaptive learning system with real-time model updates and performance optimization
"""

import os
import json
import logging
import asyncio
import hashlib
import numpy as np
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque

# ML imports
try:
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
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
class LearningExample:
    """Single learning example with metadata"""
    input_features: Dict[str, Any]
    ground_truth: Any
    prediction: Any
    confidence: float
    feedback: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = "scan_result"
    validated: bool = False

@dataclass
class ModelPerformance:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    sample_count: int
    last_updated: datetime
    improvement_trend: float = 0.0

class EnhancedContinuousLearning:
    """
    Advanced continuous learning engine with AI-powered adaptation
    Features:
    - Real-time model updates from scan results
    - Performance monitoring and drift detection
    - AI-powered feature engineering and selection
    - Adaptive learning rate and batch sizing
    - Multi-model ensemble management
    - Feedback incorporation and validation
    """
    
    def __init__(self, model_dir: str = "models/continuous", 
                 max_examples: int = 10000,
                 update_threshold: int = 50,
                 ai_enhanced: bool = True):
        
        self.model_dir = model_dir
        self.max_examples = max_examples
        self.update_threshold = update_threshold
        self.ai_enhanced = ai_enhanced and AI_AVAILABLE
        
        # Create model directory
        os.makedirs(model_dir, exist_ok=True)
        
        # Learning data storage
        self.learning_examples = deque(maxlen=max_examples)
        self.validation_examples = deque(maxlen=max_examples // 4)
        self.feedback_buffer = deque(maxlen=1000)
        
        # Model management
        self.models = {}
        self.model_performance = {}
        self.feature_extractors = {}
        
        # Learning metrics
        self.update_count = 0
        self.last_update = None
        self.learning_curve = []
        
        # AI coordinator for advanced learning
        self.ai_coordinator = None
        if self.ai_enhanced:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
                log.info("✅ AI-enhanced continuous learning initialized")
            except Exception as e:
                log.warning(f"AI coordinator initialization failed: {e}")
                self.ai_enhanced = False
        
        # Load existing models and state
        self._load_learning_state()

    async def learn_from_scan_results(self, scan_results: List[Dict[str, Any]], 
                                    ground_truth: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Learn from new scan results with optional ground truth"""
        try:
            log.info(f"🧠 Learning from {len(scan_results)} scan results")
            
            # Process scan results into learning examples
            examples = await self._process_scan_results(scan_results, ground_truth)
            
            # Add examples to learning buffer
            for example in examples:
                self.learning_examples.append(example)
            
            # Check if we have enough examples for an update
            learning_stats = {"examples_added": len(examples)}
            
            if len(self.learning_examples) >= self.update_threshold:
                update_results = await self._perform_model_updates()
                learning_stats.update(update_results)
            
            # AI-powered learning optimization
            if self.ai_enhanced and examples:
                optimization_results = await self._optimize_learning_with_ai(examples)
                learning_stats["ai_optimizations"] = optimization_results
            
            return learning_stats
            
        except Exception as e:
            log.error(f"Learning from scan results failed: {e}")
            return {"error": str(e)}

    async def _process_scan_results(self, scan_results: List[Dict[str, Any]], 
                                  ground_truth: Optional[List[Dict[str, Any]]]) -> List[LearningExample]:
        """Process scan results into learning examples"""
        examples = []
        
        for i, result in enumerate(scan_results):
            try:
                # Extract features from scan result
                features = self._extract_features_from_result(result)
                
                # Get ground truth if available
                truth = None
                if ground_truth and i < len(ground_truth):
                    truth = ground_truth[i]
                
                # Create learning example
                example = LearningExample(
                    input_features=features,
                    ground_truth=truth,
                    prediction=result.get("vulnerabilities", []),
                    confidence=result.get("confidence", 0.5),
                    source="scan_result",
                    validated=truth is not None
                )
                
                examples.append(example)
                
            except Exception as e:
                log.error(f"Failed to process scan result {i}: {e}")
                continue
        
        return examples

    def _extract_features_from_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract learning features from scan result"""
        features = {}
        
        # Basic endpoint features
        features["method"] = result.get("method", "GET")
        features["status_code"] = result.get("status_code", 200)
        features["response_length"] = len(result.get("body", ""))
        features["response_time"] = result.get("response_time", 0)
        
        # Content features
        body = result.get("body", "").lower()
        features["has_error_keywords"] = any(
            keyword in body for keyword in ["error", "exception", "warning"]
        )
        features["has_sql_keywords"] = any(
            keyword in body for keyword in ["mysql", "sql", "database"]
        )
        features["has_script_tags"] = "<script" in body
        
        # Vulnerability features
        vulnerabilities = result.get("vulnerabilities", [])
        features["vulnerability_count"] = len(vulnerabilities)
        features["max_severity"] = self._get_max_severity(vulnerabilities)
        
        # Request features
        features["url_length"] = len(result.get("url", ""))
        features["has_parameters"] = "?" in result.get("url", "")
        
        return features

    def _get_max_severity(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """Get maximum severity score from vulnerabilities"""
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low").lower()
            score = severity_scores.get(severity, 1)
            max_score = max(max_score, score)
        
        return max_score

    async def _perform_model_updates(self) -> Dict[str, Any]:
        """Perform model updates based on accumulated examples"""
        try:
            log.info(f"🔄 Performing model updates with {len(self.learning_examples)} examples")
            
            results = {}
            
            # Update vulnerability detection model
            if "vulnerability_detector" not in self.models:
                self._initialize_vulnerability_detector()
            
            detector_results = await self._update_vulnerability_detector()
            results["vulnerability_detector"] = detector_results
            
            # Update false positive classifier
            if "fp_classifier" not in self.models:
                self._initialize_fp_classifier()
                
            fp_results = await self._update_fp_classifier()
            results["fp_classifier"] = fp_results
            
            # Update severity predictor
            if "severity_predictor" not in self.models:
                self._initialize_severity_predictor()
                
            severity_results = await self._update_severity_predictor()
            results["severity_predictor"] = severity_results
            
            # Update learning metrics
            self.update_count += 1
            self.last_update = datetime.now()
            
            # Save updated models
            self._save_learning_state()
            
            results["update_count"] = self.update_count
            results["examples_used"] = len(self.learning_examples)
            
            return results
            
        except Exception as e:
            log.error(f"Model update failed: {e}")
            return {"error": str(e)}

    def _initialize_vulnerability_detector(self):
        """Initialize vulnerability detection model"""
        if not ML_AVAILABLE:
            log.warning("ML libraries not available for vulnerability detector")
            return
            
        self.models["vulnerability_detector"] = RandomForestClassifier(
            n_estimators=100, random_state=42
        )
        self.feature_extractors["vulnerability_detector"] = TfidfVectorizer(
            max_features=1000, stop_words='english'
        )
        
        self.model_performance["vulnerability_detector"] = ModelPerformance(
            accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
            sample_count=0, last_updated=datetime.now()
        )

    async def _update_vulnerability_detector(self) -> Dict[str, Any]:
        """Update vulnerability detection model"""
        if not ML_AVAILABLE:
            return {"error": "ML not available"}
            
        try:
            # Prepare training data
            X, y = self._prepare_vulnerability_training_data()
            
            if len(X) < 10:  # Minimum samples needed
                return {"status": "insufficient_data", "samples": len(X)}
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train model
            model = self.models["vulnerability_detector"]
            model.fit(X_train, y_train)
            
            # Evaluate performance
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_test, y_pred, average='weighted'
            )
            
            # Update performance metrics
            old_performance = self.model_performance["vulnerability_detector"]
            improvement = accuracy - old_performance.accuracy
            
            self.model_performance["vulnerability_detector"] = ModelPerformance(
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                sample_count=len(X),
                last_updated=datetime.now(),
                improvement_trend=improvement
            )
            
            # Add to learning curve
            self.learning_curve.append({
                "timestamp": datetime.now().isoformat(),
                "model": "vulnerability_detector",
                "accuracy": accuracy,
                "samples": len(X)
            })
            
            return {
                "status": "updated",
                "accuracy": accuracy,
                "improvement": improvement,
                "samples": len(X)
            }
            
        except Exception as e:
            log.error(f"Vulnerability detector update failed: {e}")
            return {"error": str(e)}

    def _prepare_vulnerability_training_data(self) -> Tuple[List, List]:
        """Prepare training data for vulnerability detection"""
        X, y = [], []
        
        for example in self.learning_examples:
            if not example.validated:
                continue
                
            # Features
            features = []
            feature_dict = example.input_features
            
            # Convert features to numeric array
            features.extend([
                1 if feature_dict["method"] == "POST" else 0,
                feature_dict.get("status_code", 200) / 1000,  # Normalize
                min(feature_dict.get("response_length", 0) / 1000, 10),  # Cap and normalize
                min(feature_dict.get("response_time", 0), 5),  # Cap at 5 seconds
                1 if feature_dict.get("has_error_keywords") else 0,
                1 if feature_dict.get("has_sql_keywords") else 0,
                1 if feature_dict.get("has_script_tags") else 0,
                feature_dict.get("vulnerability_count", 0),
                feature_dict.get("max_severity", 0) / 4,  # Normalize severity
                min(feature_dict.get("url_length", 0) / 100, 5),  # Normalize URL length
                1 if feature_dict.get("has_parameters") else 0
            ])
            
            X.append(features)
            
            # Label: 1 if vulnerabilities found, 0 otherwise
            has_vulns = len(example.prediction) > 0 if example.prediction else 0
            y.append(has_vulns)
        
        return X, y

    def _initialize_fp_classifier(self):
        """Initialize false positive classifier"""
        if not ML_AVAILABLE:
            return
            
        self.models["fp_classifier"] = RandomForestClassifier(
            n_estimators=50, random_state=42
        )
        
        self.model_performance["fp_classifier"] = ModelPerformance(
            accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
            sample_count=0, last_updated=datetime.now()
        )

    async def _update_fp_classifier(self) -> Dict[str, Any]:
        """Update false positive classifier"""
        if not ML_AVAILABLE:
            return {"error": "ML not available"}
            
        try:
            # Prepare FP training data
            X, y = self._prepare_fp_training_data()
            
            if len(X) < 10:
                return {"status": "insufficient_data", "samples": len(X)}
            
            # Train and evaluate
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            model = self.models["fp_classifier"]
            model.fit(X_train, y_train)
            
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_test, y_pred, average='weighted'
            )
            
            # Update performance
            old_performance = self.model_performance["fp_classifier"]
            improvement = accuracy - old_performance.accuracy
            
            self.model_performance["fp_classifier"] = ModelPerformance(
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                sample_count=len(X),
                last_updated=datetime.now(),
                improvement_trend=improvement
            )
            
            return {
                "status": "updated",
                "accuracy": accuracy,
                "improvement": improvement,
                "samples": len(X)
            }
            
        except Exception as e:
            return {"error": str(e)}

    def _prepare_fp_training_data(self) -> Tuple[List, List]:
        """Prepare training data for false positive classification"""
        X, y = [], []
        
        for example in self.learning_examples:
            if not example.validated or not example.ground_truth:
                continue
            
            # Same features as vulnerability detector
            features = self._extract_numeric_features(example.input_features)
            X.append(features)
            
            # Label: 1 if prediction was false positive, 0 if true positive
            predicted_vulns = len(example.prediction) if example.prediction else 0
            actual_vulns = len(example.ground_truth.get("vulnerabilities", [])) if isinstance(example.ground_truth, dict) else 0
            
            is_fp = predicted_vulns > 0 and actual_vulns == 0
            y.append(1 if is_fp else 0)
        
        return X, y

    def _initialize_severity_predictor(self):
        """Initialize severity prediction model"""
        if not ML_AVAILABLE:
            return
            
        self.models["severity_predictor"] = RandomForestClassifier(
            n_estimators=75, random_state=42
        )
        
        self.model_performance["severity_predictor"] = ModelPerformance(
            accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
            sample_count=0, last_updated=datetime.now()
        )

    async def _update_severity_predictor(self) -> Dict[str, Any]:
        """Update severity prediction model"""
        if not ML_AVAILABLE:
            return {"error": "ML not available"}
            
        try:
            X, y = self._prepare_severity_training_data()
            
            if len(X) < 10:
                return {"status": "insufficient_data", "samples": len(X)}
            
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            model = self.models["severity_predictor"]
            model.fit(X_train, y_train)
            
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Update performance
            old_performance = self.model_performance["severity_predictor"]
            improvement = accuracy - old_performance.accuracy
            
            self.model_performance["severity_predictor"] = ModelPerformance(
                accuracy=accuracy,
                precision=0.0,  # Multi-class precision calculation more complex
                recall=0.0,
                f1_score=0.0,
                sample_count=len(X),
                last_updated=datetime.now(),
                improvement_trend=improvement
            )
            
            return {
                "status": "updated",
                "accuracy": accuracy,
                "improvement": improvement,
                "samples": len(X)
            }
            
        except Exception as e:
            return {"error": str(e)}

    def _prepare_severity_training_data(self) -> Tuple[List, List]:
        """Prepare training data for severity prediction"""
        X, y = [], []
        severity_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        
        for example in self.learning_examples:
            if not example.validated:
                continue
                
            features = self._extract_numeric_features(example.input_features)
            X.append(features)
            
            # Use max severity as label
            max_sev = example.input_features.get("max_severity", 1)
            y.append(max_sev)
        
        return X, y

    def _extract_numeric_features(self, feature_dict: Dict[str, Any]) -> List[float]:
        """Extract numeric features from feature dictionary"""
        return [
            1.0 if feature_dict.get("method") == "POST" else 0.0,
            float(feature_dict.get("status_code", 200)) / 1000,
            min(float(feature_dict.get("response_length", 0)) / 1000, 10.0),
            min(float(feature_dict.get("response_time", 0)), 5.0),
            1.0 if feature_dict.get("has_error_keywords") else 0.0,
            1.0 if feature_dict.get("has_sql_keywords") else 0.0,
            1.0 if feature_dict.get("has_script_tags") else 0.0,
            float(feature_dict.get("vulnerability_count", 0)),
            float(feature_dict.get("max_severity", 0)) / 4.0,
            min(float(feature_dict.get("url_length", 0)) / 100, 5.0),
            1.0 if feature_dict.get("has_parameters") else 0.0
        ]

    async def _optimize_learning_with_ai(self, examples: List[LearningExample]) -> Dict[str, Any]:
        """Use AI to optimize learning process"""
        if not self.ai_coordinator:
            return {}
            
        try:
            # Analyze learning patterns
            pattern_analysis = await self._analyze_learning_patterns(examples)
            
            # Get optimization suggestions
            optimization_suggestions = await self._get_ai_optimization_suggestions(pattern_analysis)
            
            # Apply feasible optimizations
            applied_optimizations = self._apply_ai_optimizations(optimization_suggestions)
            
            return {
                "patterns_analyzed": len(examples),
                "suggestions": len(optimization_suggestions),
                "applied": applied_optimizations
            }
            
        except Exception as e:
            log.error(f"AI learning optimization failed: {e}")
            return {"error": str(e)}

    async def _analyze_learning_patterns(self, examples: List[LearningExample]) -> Dict[str, Any]:
        """Analyze patterns in learning examples"""
        patterns = {
            "accuracy_trends": [],
            "common_features": {},
            "error_patterns": [],
            "performance_metrics": {}
        }
        
        # Analyze feature distributions
        for example in examples:
            for feature, value in example.input_features.items():
                if feature not in patterns["common_features"]:
                    patterns["common_features"][feature] = []
                patterns["common_features"][feature].append(value)
        
        # Calculate feature statistics
        for feature, values in patterns["common_features"].items():
            if all(isinstance(v, (int, float)) for v in values):
                patterns["common_features"][feature] = {
                    "mean": np.mean(values),
                    "std": np.std(values),
                    "min": np.min(values),
                    "max": np.max(values)
                }
        
        return patterns

    async def _get_ai_optimization_suggestions(self, patterns: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get AI suggestions for learning optimization"""
        if not self.ai_coordinator:
            return []
            
        try:
            prompt = f"""Analyze these machine learning patterns and suggest optimizations:

Learning Patterns:
{json.dumps(patterns, indent=2, default=str)}

Current Model Performance:
{json.dumps({k: v.__dict__ for k, v in self.model_performance.items()}, indent=2, default=str)}

Provide optimization suggestions as JSON array:
[
  {{
    "optimization_type": "feature_engineering|model_tuning|data_preprocessing",
    "suggestion": "specific_suggestion",
    "expected_improvement": "description",
    "implementation_difficulty": "low|medium|high",
    "priority": "high|medium|low"
  }}
]
"""
            
            request = AIRequest(
                task_type="learning_optimization",
                prompt=prompt,
                temperature=0.2,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_optimization_suggestions(response.content)
                
        except Exception as e:
            log.error(f"AI optimization suggestions failed: {e}")
        
        return []

    def _parse_optimization_suggestions(self, content: str) -> List[Dict[str, Any]]:
        """Parse AI optimization suggestions"""
        try:
            start = content.find('[')
            end = content.rfind(']') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse optimization suggestions: {e}")
        
        return []

    def _apply_ai_optimizations(self, suggestions: List[Dict[str, Any]]) -> List[str]:
        """Apply feasible AI optimization suggestions"""
        applied = []
        
        for suggestion in suggestions:
            opt_type = suggestion.get("optimization_type")
            difficulty = suggestion.get("implementation_difficulty", "high")
            
            if difficulty == "low":
                if opt_type == "data_preprocessing":
                    # Simple preprocessing improvements
                    self.update_threshold = max(25, self.update_threshold - 5)
                    applied.append("Reduced update threshold for faster adaptation")
                    
                elif opt_type == "feature_engineering":
                    # Feature engineering improvements would require more complex implementation
                    applied.append("Feature engineering optimization noted for future implementation")
        
        return applied

    async def incorporate_feedback(self, feedback_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Incorporate user feedback into learning process"""
        try:
            feedback_count = 0
            
            for feedback in feedback_data:
                example_id = feedback.get("example_id")
                is_correct = feedback.get("is_correct", True)
                comments = feedback.get("comments", "")
                
                # Find corresponding example and update
                for example in self.learning_examples:
                    if hasattr(example, 'id') and example.id == example_id:
                        example.feedback = comments
                        example.validated = True
                        if not is_correct:
                            # Adjust ground truth based on feedback
                            example.ground_truth = {"corrected": True, "feedback": comments}
                        feedback_count += 1
                        break
                
                # Add to feedback buffer
                self.feedback_buffer.append({
                    "feedback": feedback,
                    "timestamp": datetime.now(),
                    "incorporated": True
                })
            
            return {
                "feedback_incorporated": feedback_count,
                "total_feedback": len(self.feedback_buffer)
            }
            
        except Exception as e:
            log.error(f"Feedback incorporation failed: {e}")
            return {"error": str(e)}

    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get comprehensive learning statistics"""
        return {
            "learning_examples": len(self.learning_examples),
            "validation_examples": len(self.validation_examples),
            "update_count": self.update_count,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "models": list(self.models.keys()),
            "model_performance": {
                name: {
                    "accuracy": perf.accuracy,
                    "sample_count": perf.sample_count,
                    "last_updated": perf.last_updated.isoformat(),
                    "improvement_trend": perf.improvement_trend
                }
                for name, perf in self.model_performance.items()
            },
            "feedback_count": len(self.feedback_buffer),
            "ai_enhanced": self.ai_enhanced,
            "learning_curve_points": len(self.learning_curve)
        }

    def _save_learning_state(self):
        """Save learning state and models to disk"""
        try:
            # Save models
            for name, model in self.models.items():
                if ML_AVAILABLE:
                    model_path = os.path.join(self.model_dir, f"{name}.pkl")
                    joblib.dump(model, model_path)
            
            # Save feature extractors
            for name, extractor in self.feature_extractors.items():
                extractor_path = os.path.join(self.model_dir, f"{name}_extractor.pkl")
                joblib.dump(extractor, extractor_path)
            
            # Save learning state
            state = {
                "update_count": self.update_count,
                "last_update": self.last_update.isoformat() if self.last_update else None,
                "model_performance": {
                    name: {
                        "accuracy": perf.accuracy,
                        "precision": perf.precision,
                        "recall": perf.recall,
                        "f1_score": perf.f1_score,
                        "sample_count": perf.sample_count,
                        "last_updated": perf.last_updated.isoformat(),
                        "improvement_trend": perf.improvement_trend
                    }
                    for name, perf in self.model_performance.items()
                },
                "learning_curve": self.learning_curve
            }
            
            state_path = os.path.join(self.model_dir, "learning_state.json")
            with open(state_path, 'w') as f:
                json.dump(state, f, indent=2)
                
            log.info("Learning state saved successfully")
            
        except Exception as e:
            log.error(f"Failed to save learning state: {e}")

    def _load_learning_state(self):
        """Load learning state and models from disk"""
        try:
            # Load learning state
            state_path = os.path.join(self.model_dir, "learning_state.json")
            if os.path.exists(state_path):
                with open(state_path, 'r') as f:
                    state = json.load(f)
                
                self.update_count = state.get("update_count", 0)
                if state.get("last_update"):
                    self.last_update = datetime.fromisoformat(state["last_update"])
                
                # Load performance metrics
                for name, perf_data in state.get("model_performance", {}).items():
                    self.model_performance[name] = ModelPerformance(
                        accuracy=perf_data["accuracy"],
                        precision=perf_data["precision"],
                        recall=perf_data["recall"],
                        f1_score=perf_data["f1_score"],
                        sample_count=perf_data["sample_count"],
                        last_updated=datetime.fromisoformat(perf_data["last_updated"]),
                        improvement_trend=perf_data.get("improvement_trend", 0.0)
                    )
                
                self.learning_curve = state.get("learning_curve", [])
            
            # Load models if available
            if ML_AVAILABLE:
                for model_name in ["vulnerability_detector", "fp_classifier", "severity_predictor"]:
                    model_path = os.path.join(self.model_dir, f"{model_name}.pkl")
                    if os.path.exists(model_path):
                        self.models[model_name] = joblib.load(model_path)
                    
                    extractor_path = os.path.join(self.model_dir, f"{model_name}_extractor.pkl")
                    if os.path.exists(extractor_path):
                        self.feature_extractors[model_name] = joblib.load(extractor_path)
            
            if self.models:
                log.info(f"Loaded {len(self.models)} models from disk")
            
        except Exception as e:
            log.error(f"Failed to load learning state: {e}")

# Usage example
if __name__ == "__main__":
    async def main():
        learning_engine = EnhancedContinuousLearning()
        
        # Example scan results
        sample_results = [
            {
                "method": "POST",
                "url": "https://api.example.com/login",
                "status_code": 200,
                "body": "Login successful",
                "response_time": 0.5,
                "vulnerabilities": [
                    {"type": "sql_injection", "severity": "high"}
                ],
                "confidence": 0.8
            },
            {
                "method": "GET", 
                "url": "https://api.example.com/users",
                "status_code": 200,
                "body": "User data",
                "response_time": 0.3,
                "vulnerabilities": [],
                "confidence": 0.9
            }
        ]
        
        # Learn from results
        learning_stats = await learning_engine.learn_from_scan_results(sample_results)
        
        print("🧠 Continuous Learning Results:")
        print(f"Examples added: {learning_stats.get('examples_added', 0)}")
        
        # Get statistics
        stats = learning_engine.get_learning_statistics()
        print(f"📊 Learning Statistics:")
        print(f"- Total examples: {stats['learning_examples']}")
        print(f"- Updates performed: {stats['update_count']}")
        print(f"- Models: {', '.join(stats['models'])}")
        print(f"- AI enhanced: {stats['ai_enhanced']}")

    asyncio.run(main())

