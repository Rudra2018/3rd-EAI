#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced AI Coordinator for Rudra's Third Eye
Multi-model AI orchestration with intelligent routing and fallback mechanisms
"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import hashlib
from dataclasses import dataclass
from enum import Enum

# AI Model Clients
try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    import anthropic
    CLAUDE_AVAILABLE = True  
except ImportError:
    CLAUDE_AVAILABLE = False

log = logging.getLogger(__name__)

class AIModel(Enum):
    GPT4_TURBO = "gpt-4-turbo"
    GPT4O = "gpt-4o"
    GPT4O_MINI = "gpt-4o-mini"
    GEMINI_PRO = "gemini-1.5-pro"
    GEMINI_FLASH = "gemini-1.5-flash"
    CLAUDE_SONNET = "claude-3-5-sonnet-20241022"
    CLAUDE_HAIKU = "claude-3-5-haiku-20241022"

@dataclass
class AIRequest:
    task_type: str
    prompt: str
    context: Dict[str, Any] = None
    temperature: float = 0.3
    max_tokens: int = 4000
    priority: str = "medium"  # low, medium, high, critical
    require_json: bool = False

@dataclass
class AIResponse:
    content: str
    model_used: AIModel
    success: bool
    tokens_used: int = 0
    response_time: float = 0.0
    confidence_score: float = 0.0
    metadata: Dict[str, Any] = None

class AdvancedAICoordinator:
    """
    Coordinates multiple AI models for optimal performance and reliability
    Features:
    - Intelligent model selection based on task type
    - Automatic fallback mechanisms
    - Response caching for efficiency
    - Token usage optimization
    - Quality assessment and routing
    """
    
    def __init__(self):
        self.models = {}
        self.cache = {}
        self.model_performance = {}
        self.initialize_models()
        
        # Model capabilities mapping
        self.model_capabilities = {
            AIModel.GPT4O: {
                "security_analysis": 0.95,
                "vulnerability_detection": 0.90,
                "code_analysis": 0.95,
                "exploit_generation": 0.85,
                "report_writing": 0.90,
                "reasoning": 0.95
            },
            AIModel.GEMINI_PRO: {
                "security_analysis": 0.90,
                "vulnerability_detection": 0.85,
                "code_analysis": 0.90,
                "exploit_generation": 0.80,
                "report_writing": 0.95,
                "reasoning": 0.90
            },
            AIModel.CLAUDE_SONNET: {
                "security_analysis": 0.90,
                "vulnerability_detection": 0.85,
                "code_analysis": 0.95,
                "exploit_generation": 0.75,
                "report_writing": 0.95,
                "reasoning": 0.95
            }
        }

    def initialize_models(self):
        """Initialize available AI models"""
        
        # Initialize OpenAI models
        if OPENAI_AVAILABLE and os.getenv("OPENAI_API_KEY"):
            try:
                self.models['openai'] = AsyncOpenAI(
                    api_key=os.getenv("OPENAI_API_KEY")
                )
                log.info("✅ OpenAI models initialized")
            except Exception as e:
                log.warning(f"⚠️ OpenAI initialization failed: {e}")

        # Initialize Gemini models
        if GEMINI_AVAILABLE and os.getenv("GEMINI_API_KEY"):
            try:
                genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
                self.models['gemini'] = genai
                log.info("✅ Gemini models initialized")
            except Exception as e:
                log.warning(f"⚠️ Gemini initialization failed: {e}")

        # Initialize Claude models  
        if CLAUDE_AVAILABLE and os.getenv("ANTHROPIC_API_KEY"):
            try:
                self.models['claude'] = anthropic.AsyncAnthropic(
                    api_key=os.getenv("ANTHROPIC_API_KEY")
                )
                log.info("✅ Claude models initialized")
            except Exception as e:
                log.warning(f"⚠️ Claude initialization failed: {e}")

    def select_optimal_model(self, request: AIRequest) -> AIModel:
        """Select the best model for a given request"""
        
        # Priority-based selection for critical tasks
        if request.priority == "critical":
            return AIModel.GPT4O
        
        # Task-specific model selection
        task_model_preferences = {
            "vulnerability_analysis": [AIModel.GPT4O, AIModel.GEMINI_PRO, AIModel.CLAUDE_SONNET],
            "exploit_generation": [AIModel.GPT4O, AIModel.GEMINI_PRO, AIModel.CLAUDE_SONNET],
            "code_analysis": [AIModel.CLAUDE_SONNET, AIModel.GPT4O, AIModel.GEMINI_PRO],
            "report_generation": [AIModel.CLAUDE_SONNET, AIModel.GEMINI_PRO, AIModel.GPT4O],
            "threat_intelligence": [AIModel.GPT4O, AIModel.GEMINI_PRO, AIModel.CLAUDE_SONNET],
            "payload_generation": [AIModel.GPT4O, AIModel.GEMINI_FLASH, AIModel.CLAUDE_HAIKU],
            "zero_day_analysis": [AIModel.GPT4O, AIModel.CLAUDE_SONNET, AIModel.GEMINI_PRO]
        }
        
        preferred_models = task_model_preferences.get(
            request.task_type, 
            [AIModel.GPT4O, AIModel.GEMINI_PRO, AIModel.CLAUDE_SONNET]
        )
        
        # Select first available model from preferences
        for model in preferred_models:
            if self._is_model_available(model):
                return model
                
        # Fallback to any available model
        return self._get_any_available_model()

    def _is_model_available(self, model: AIModel) -> bool:
        """Check if a model is available"""
        if model in [AIModel.GPT4O, AIModel.GPT4_TURBO, AIModel.GPT4O_MINI]:
            return 'openai' in self.models
        elif model in [AIModel.GEMINI_PRO, AIModel.GEMINI_FLASH]:
            return 'gemini' in self.models  
        elif model in [AIModel.CLAUDE_SONNET, AIModel.CLAUDE_HAIKU]:
            return 'claude' in self.models
        return False

    def _get_any_available_model(self) -> Optional[AIModel]:
        """Get any available model as fallback"""
        if 'openai' in self.models:
            return AIModel.GPT4O_MINI
        elif 'gemini' in self.models:
            return AIModel.GEMINI_FLASH
        elif 'claude' in self.models:
            return AIModel.CLAUDE_HAIKU
        return None

    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process an AI request with intelligent routing and fallback"""
        
        start_time = datetime.now()
        
        # Check cache first
        cache_key = self._generate_cache_key(request)
        if cache_key in self.cache:
            log.debug(f"📦 Cache hit for request: {request.task_type}")
            cached_response = self.cache[cache_key]
            cached_response.response_time = 0.0  # Instant from cache
            return cached_response

        # Select optimal model
        selected_model = self.select_optimal_model(request)
        if not selected_model:
            return AIResponse(
                content="No AI models available",
                model_used=None,
                success=False,
                response_time=(datetime.now() - start_time).total_seconds()
            )

        # Attempt request with selected model
        response = await self._execute_request(request, selected_model)
        
        # If failed, try fallback models
        if not response.success:
            fallback_models = self._get_fallback_models(selected_model)
            for fallback_model in fallback_models:
                log.warning(f"🔄 Trying fallback model: {fallback_model}")
                response = await self._execute_request(request, fallback_model)
                if response.success:
                    break

        # Update performance metrics
        self._update_performance_metrics(selected_model, response)
        
        # Cache successful responses
        if response.success and request.priority != "critical":
            self.cache[cache_key] = response

        response.response_time = (datetime.now() - start_time).total_seconds()
        return response

    async def _execute_request(self, request: AIRequest, model: AIModel) -> AIResponse:
        """Execute request on specific model"""
        
        try:
            if model in [AIModel.GPT4O, AIModel.GPT4_TURBO, AIModel.GPT4O_MINI]:
                return await self._call_openai(request, model)
            elif model in [AIModel.GEMINI_PRO, AIModel.GEMINI_FLASH]:
                return await self._call_gemini(request, model)
            elif model in [AIModel.CLAUDE_SONNET, AIModel.CLAUDE_HAIKU]:
                return await self._call_claude(request, model)
            else:
                raise ValueError(f"Unsupported model: {model}")
                
        except Exception as e:
            log.error(f"❌ Model {model} request failed: {e}")
            return AIResponse(
                content=f"Model request failed: {str(e)}",
                model_used=model,
                success=False
            )

    async def _call_openai(self, request: AIRequest, model: AIModel) -> AIResponse:
        """Call OpenAI API"""
        
        messages = [
            {"role": "system", "content": self._get_system_prompt(request.task_type)},
            {"role": "user", "content": request.prompt}
        ]
        
        if request.context:
            messages.insert(1, {
                "role": "system", 
                "content": f"Context: {json.dumps(request.context, indent=2)}"
            })

        response = await self.models['openai'].chat.completions.create(
            model=model.value,
            messages=messages,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            response_format={"type": "json_object"} if request.require_json else None
        )

        return AIResponse(
            content=response.choices[0].message.content,
            model_used=model,
            success=True,
            tokens_used=response.usage.total_tokens,
            confidence_score=self._calculate_confidence_score(
                response.choices[0].message.content, request.task_type
            )
        )

    async def _call_gemini(self, request: AIRequest, model: AIModel) -> AIResponse:
        """Call Gemini API"""
        
        model_instance = genai.GenerativeModel(model.value)
        
        prompt = f"{self._get_system_prompt(request.task_type)}\n\n{request.prompt}"
        if request.context:
            prompt += f"\n\nContext: {json.dumps(request.context, indent=2)}"

        response = await model_instance.generate_content_async(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=request.temperature,
                max_output_tokens=request.max_tokens
            )
        )

        return AIResponse(
            content=response.text,
            model_used=model,
            success=True,
            tokens_used=response.usage_metadata.total_token_count if hasattr(response, 'usage_metadata') else 0,
            confidence_score=self._calculate_confidence_score(response.text, request.task_type)
        )

    async def _call_claude(self, request: AIRequest, model: AIModel) -> AIResponse:
        """Call Claude API"""
        
        system_prompt = self._get_system_prompt(request.task_type)
        user_prompt = request.prompt
        
        if request.context:
            user_prompt += f"\n\nContext: {json.dumps(request.context, indent=2)}"

        message = await self.models['claude'].messages.create(
            model=model.value,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        )

        return AIResponse(
            content=message.content[0].text,
            model_used=model,
            success=True,
            tokens_used=message.usage.input_tokens + message.usage.output_tokens,
            confidence_score=self._calculate_confidence_score(
                message.content[0].text, request.task_type
            )
        )

    def _get_system_prompt(self, task_type: str) -> str:
        """Get task-specific system prompts"""
        
        prompts = {
            "vulnerability_analysis": """You are an expert cybersecurity analyst specializing in API vulnerability assessment. 
            Analyze the provided information for security vulnerabilities, classify them according to OWASP API Security Top 10, 
            and provide detailed technical analysis with exploitation scenarios and remediation steps.""",
            
            "exploit_generation": """You are an ethical security researcher creating proof-of-concept exploits for educational purposes. 
            Generate safe, educational exploit code that demonstrates vulnerabilities without causing harm. 
            Always include warnings and educational context.""",
            
            "code_analysis": """You are a senior security engineer performing code security review. 
            Analyze the provided code for security vulnerabilities, insecure patterns, and potential attack vectors. 
            Provide specific recommendations for remediation.""",
            
            "report_generation": """You are a senior security consultant creating professional security assessment reports. 
            Generate comprehensive, executive-level reports with clear risk ratings, business impact analysis, 
            and actionable remediation guidance.""",
            
            "threat_intelligence": """You are a threat intelligence analyst providing contextual information about cybersecurity threats. 
            Analyze threat patterns, attack vectors, and provide strategic recommendations for defense.""",
            
            "payload_generation": """You are a security testing specialist creating test payloads for vulnerability assessment. 
            Generate diverse, effective test cases for identifying security weaknesses in APIs and web applications.""",
            
            "zero_day_analysis": """You are a cutting-edge security researcher specializing in novel vulnerability discovery. 
            Analyze patterns and behaviors that might indicate unknown vulnerabilities or zero-day exploits."""
        }
        
        return prompts.get(task_type, 
            "You are an expert cybersecurity professional. Provide detailed, accurate analysis.")

    def _calculate_confidence_score(self, content: str, task_type: str) -> float:
        """Calculate confidence score for AI response"""
        
        # Basic scoring based on content characteristics
        score = 0.5  # Base score
        
        # Length-based scoring
        if len(content) > 500:
            score += 0.1
        if len(content) > 1000:
            score += 0.1
            
        # Task-specific indicators
        confidence_indicators = {
            "vulnerability_analysis": ["CVE-", "OWASP", "vulnerability", "exploit", "risk"],
            "exploit_generation": ["payload", "exploit", "proof-of-concept", "demonstration"],
            "code_analysis": ["function", "variable", "security", "vulnerability", "recommendation"],
            "report_generation": ["executive summary", "findings", "recommendations", "risk rating"]
        }
        
        indicators = confidence_indicators.get(task_type, [])
        found_indicators = sum(1 for indicator in indicators if indicator.lower() in content.lower())
        score += (found_indicators / len(indicators)) * 0.3
        
        return min(1.0, score)

    def _generate_cache_key(self, request: AIRequest) -> str:
        """Generate cache key for request"""
        content = f"{request.task_type}:{request.prompt}:{request.temperature}"
        return hashlib.md5(content.encode()).hexdigest()

    def _get_fallback_models(self, failed_model: AIModel) -> List[AIModel]:
        """Get fallback models when primary fails"""
        all_models = [AIModel.GPT4O, AIModel.GEMINI_PRO, AIModel.CLAUDE_SONNET, 
                     AIModel.GPT4O_MINI, AIModel.GEMINI_FLASH, AIModel.CLAUDE_HAIKU]
        return [m for m in all_models if m != failed_model and self._is_model_available(m)]

    def _update_performance_metrics(self, model: AIModel, response: AIResponse):
        """Update performance metrics for model"""
        if model not in self.model_performance:
            self.model_performance[model] = {
                "requests": 0,
                "successes": 0,
                "failures": 0,
                "avg_response_time": 0.0,
                "avg_confidence": 0.0
            }
        
        metrics = self.model_performance[model]
        metrics["requests"] += 1
        
        if response.success:
            metrics["successes"] += 1
            # Update averages
            metrics["avg_response_time"] = (
                (metrics["avg_response_time"] * (metrics["successes"] - 1) + response.response_time) 
                / metrics["successes"]
            )
            metrics["avg_confidence"] = (
                (metrics["avg_confidence"] * (metrics["successes"] - 1) + response.confidence_score) 
                / metrics["successes"]
            )
        else:
            metrics["failures"] += 1

    # Convenience methods for common tasks
    
    async def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> AIResponse:
        """Analyze vulnerability data"""
        request = AIRequest(
            task_type="vulnerability_analysis",
            prompt=f"Analyze this vulnerability data and provide detailed assessment:\n{json.dumps(vulnerability_data, indent=2)}",
            context=vulnerability_data,
            priority="high",
            require_json=True
        )
        return await self.process_request(request)

    async def generate_exploit_poc(self, vulnerability: Dict[str, Any]) -> AIResponse:
        """Generate proof-of-concept exploit"""
        request = AIRequest(
            task_type="exploit_generation", 
            prompt=f"Generate a safe proof-of-concept exploit for educational purposes:\n{json.dumps(vulnerability, indent=2)}",
            context=vulnerability,
            priority="medium"
        )
        return await self.process_request(request)

    async def generate_security_report(self, scan_results: Dict[str, Any]) -> AIResponse:
        """Generate comprehensive security report"""
        request = AIRequest(
            task_type="report_generation",
            prompt="Generate a comprehensive security assessment report based on the scan results.",
            context=scan_results,
            priority="high",
            max_tokens=8000
        )
        return await self.process_request(request)

    async def analyze_for_zero_days(self, findings: List[Dict[str, Any]]) -> AIResponse:
        """Analyze findings for potential zero-day vulnerabilities"""
        request = AIRequest(
            task_type="zero_day_analysis",
            prompt="Analyze these security findings for patterns that might indicate unknown vulnerabilities or zero-day exploits.",
            context={"findings": findings},
            priority="critical",
            require_json=True
        )
        return await self.process_request(request)

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for all models"""
        return {
            "models": dict(self.model_performance),
            "cache_size": len(self.cache),
            "available_models": [model.value for model in AIModel if self._is_model_available(model)]
        }
