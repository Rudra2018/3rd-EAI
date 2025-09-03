#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced AI Coordinator - Multi-Model AI Integration
"""

import os
import json
import asyncio
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

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

log = logging.getLogger(__name__)

@dataclass
class AIRequest:
    task_type: str
    prompt: str
    temperature: float = 0.3
    model_override: Optional[str] = None
    require_json: bool = False
    max_tokens: int = 4000

@dataclass
class AIResponse:
    success: bool
    content: str
    model_used: str
    processing_time: float
    token_usage: Optional[Dict[str, int]] = None
    error: Optional[str] = None

class AdvancedAICoordinator:
    """Advanced AI coordination with multiple model support"""
    
    def __init__(self):
        self.openai_client = None
        self.gemini_model = None
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize available AI models"""
        # Initialize OpenAI
        if OPENAI_AVAILABLE and os.getenv("OPENAI_API_KEY"):
            try:
                self.openai_client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                log.info("✅ OpenAI initialized")
            except Exception as e:
                log.error(f"OpenAI initialization failed: {e}")
        
        # Initialize Gemini
        if GEMINI_AVAILABLE and os.getenv("GOOGLE_API_KEY"):
            try:
                genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
                self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                log.info("✅ Gemini initialized")
            except Exception as e:
                log.error(f"Gemini initialization failed: {e}")
    
    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process AI request with best available model"""
        start_time = datetime.now()
        
        try:
            # Determine best model
            model_to_use = self._select_best_model(request)
            
            if model_to_use == "openai" and self.openai_client:
                response = await self._process_openai_request(request)
            elif model_to_use == "gemini" and self.gemini_model:
                response = await self._process_gemini_request(request)
            else:
                return AIResponse(
                    success=False,
                    content="",
                    model_used="none",
                    processing_time=0,
                    error="No AI models available"
                )
            
            processing_time = (datetime.now() - start_time).total_seconds()
            response.processing_time = processing_time
            
            return response
            
        except Exception as e:
            log.error(f"AI request processing failed: {e}")
            return AIResponse(
                success=False,
                content="",
                model_used="error",
                processing_time=0,
                error=str(e)
            )
    
    def _select_best_model(self, request: AIRequest) -> str:
        """Select best model for request"""
        if request.model_override:
            if "gpt" in request.model_override.lower() and self.openai_client:
                return "openai"
            elif "gemini" in request.model_override.lower() and self.gemini_model:
                return "gemini"
        
        # Default selection logic
        if self.openai_client:
            return "openai"
        elif self.gemini_model:
            return "gemini"
        
        return "none"
    
    async def _process_openai_request(self, request: AIRequest) -> AIResponse:
        """Process request with OpenAI"""
        try:
            messages = [{"role": "user", "content": request.prompt}]
            
            if request.require_json:
                messages[0]["content"] += "\n\nRespond with valid JSON only."
            
            response = await self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                temperature=request.temperature,
                max_tokens=request.max_tokens
            )
            
            content = response.choices[0].message.content
            
            return AIResponse(
                success=True,
                content=content,
                model_used="gpt-4o-mini",
                processing_time=0,
                token_usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                }
            )
            
        except Exception as e:
            return AIResponse(
                success=False,
                content="",
                model_used="openai_error",
                processing_time=0,
                error=str(e)
            )
    
    async def _process_gemini_request(self, request: AIRequest) -> AIResponse:
        """Process request with Gemini"""
        try:
            prompt = request.prompt
            if request.require_json:
                prompt += "\n\nRespond with valid JSON only."
            
            response = await asyncio.to_thread(
                self.gemini_model.generate_content,
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=request.temperature,
                    max_output_tokens=request.max_tokens
                )
            )
            
            return AIResponse(
                success=True,
                content=response.text,
                model_used="gemini-1.5-flash",
                processing_time=0
            )
            
        except Exception as e:
            return AIResponse(
                success=False,
                content="",
                model_used="gemini_error",
                processing_time=0,
                error=str(e)
            )

