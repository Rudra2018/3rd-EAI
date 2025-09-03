#!/usr/bin/env python3
"""
Fixed Advanced AI Coordinator - Resolves OpenAI API Format Issues
"""

import asyncio
import logging
import os
import json
import time
from typing import Dict, List, Any, Optional, Union
from enum import Enum
from dataclasses import dataclass

# AI Models
try:
    import openai
    import google.generativeai as genai
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

log = logging.getLogger("advanced_ai_coordinator")

class AIModel(Enum):
    GPT4O = "gpt-4o"
    GPT4O_MINI = "gpt-4o-mini"
    GEMINI_PRO = "gemini-2.5-pro"
    GEMINI_FLASH = "gemini-2.5-flash"

@dataclass
class AIRequest:
    prompt: str
    model: AIModel = AIModel.GPT4O
    max_tokens: int = 1000
    temperature: float = 0.7
    response_format: str = "text"  # "text" or "json"

@dataclass 
class AIResponse:
    success: bool
    content: str
    model_used: AIModel
    error: Optional[str] = None

class AdvancedAICoordinator:
    """Fixed AI Coordinator with proper API format handling"""
    
    def __init__(self):
        self.openai_client = None
        self.gemini_model = None
        self.initialize_models()
    
    def initialize_models(self):
        """Initialize AI models with proper error handling"""
        if not AI_AVAILABLE:
            log.warning("AI libraries not available")
            return
        
        # Initialize OpenAI
        try:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                openai.api_key = api_key
                self.openai_client = openai
                log.info("✅ OpenAI models initialized")
        except Exception as e:
            log.error(f"OpenAI initialization failed: {e}")
        
        # Initialize Gemini
        try:
            gemini_key = os.getenv("GEMINI_API_KEY")
            if gemini_key:
                genai.configure(api_key=gemini_key)
                self.gemini_model = genai.GenerativeModel('gemini-pro')
                log.info("✅ Gemini models initialized")
        except Exception as e:
            log.error(f"Gemini initialization failed: {e}")
    
    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process AI request with proper format handling"""
        
        # Try OpenAI first
        if self.openai_client and request.model in [AIModel.GPT4O, AIModel.GPT4O_MINI]:
            try:
                return await self._call_openai(request)
            except Exception as e:
                log.error(f"OpenAI request failed: {e}")
        
        # Fallback to Gemini
        if self.gemini_model and request.model in [AIModel.GEMINI_PRO, AIModel.GEMINI_FLASH]:
            try:
                return await self._call_gemini(request)
            except Exception as e:
                log.error(f"Gemini request failed: {e}")
        
        # Return fallback response
        return AIResponse(
            success=False,
            content="AI processing unavailable",
            model_used=request.model,
            error="All AI models failed"
        )
    
    async def _call_openai(self, request: AIRequest) -> AIResponse:
        """FIXED: Call OpenAI with proper JSON format handling"""
        
        # FIXED: Ensure prompt contains 'json' when using json response format
        if request.response_format == "json":
            if "json" not in request.prompt.lower():
                request.prompt += "\n\nPlease respond in JSON format."
        
        # Prepare messages
        messages = [
            {"role": "system", "content": "You are a helpful security analysis assistant."},
            {"role": "user", "content": request.prompt}
        ]
        
        # Prepare request parameters
        params = {
            "model": request.model.value,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature
        }
        
        # FIXED: Only add response_format if using json AND prompt contains 'json'
        if request.response_format == "json" and "json" in request.prompt.lower():
            params["response_format"] = {"type": "json_object"}
        
        try:
            response = await asyncio.to_thread(
                self.openai_client.ChatCompletion.create,
                **params
            )
            
            content = response.choices[0].message.content
            
            return AIResponse(
                success=True,
                content=content,
                model_used=request.model
            )
            
        except Exception as e:
            log.error(f"OpenAI API call failed: {e}")
            raise
    
    async def _call_gemini(self, request: AIRequest) -> AIResponse:
        """FIXED: Call Gemini with proper error handling"""
        
        try:
            # FIXED: Prevent division by zero and other errors
            if not request.prompt or len(request.prompt.strip()) == 0:
                raise ValueError("Empty prompt provided")
            
            response = await asyncio.to_thread(
                self.gemini_model.generate_content,
                request.prompt
            )
            
            # FIXED: Safe content extraction
            content = ""
            if hasattr(response, 'text') and response.text:
                content = response.text
            elif hasattr(response, 'candidates') and response.candidates:
                if response.candidates[0] and hasattr(response.candidates[0], 'content'):
                    content = str(response.candidates[0].content)
            
            if not content:
                content = "Gemini response was empty"
            
            return AIResponse(
                success=True,
                content=content,
                model_used=request.model
            )
            
        except Exception as e:
            log.error(f"Gemini API call failed: {e}")
            raise
    
    # Convenience methods for common use cases
    async def analyze_vulnerability(self, data: Dict[str, Any]) -> AIResponse:
        """Analyze vulnerability with fixed format"""
        prompt = f"""
        Analyze this API security data and provide insights in JSON format:
        
        Data: {json.dumps(data, indent=2)}
        
        Please provide a JSON response with:
        - severity: (low/medium/high/critical)
        - category: (authentication/authorization/injection/etc)
        - description: (detailed analysis)
        - recommendations: (list of fixes)
        """
        
        request = AIRequest(
            prompt=prompt,
            model=AIModel.GPT4O,
            response_format="json"
        )
        
        return await self.process_request(request)
    
    async def generate_exploit_poc(self, vulnerability_data: str) -> AIResponse:
        """Generate proof of concept with safe format"""
        prompt = f"""
        Based on this vulnerability analysis, provide a proof of concept:
        
        {vulnerability_data}
        
        Provide a responsible proof of concept for testing purposes only.
        """
        
        request = AIRequest(
            prompt=prompt,
            model=AIModel.GPT4O_MINI,
            response_format="text"
        )
        
        return await self.process_request(request)
    
    async def analyze_for_zero_days(self, findings: List[str]) -> AIResponse:
        """Analyze for potential zero-day vulnerabilities"""
        prompt = f"""
        Analyze these security findings for potential zero-day vulnerabilities:
        
        {json.dumps(findings, indent=2)}
        
        Focus on novel attack vectors and previously unknown vulnerability patterns.
        """
        
        request = AIRequest(
            prompt=prompt,
            model=AIModel.GEMINI_PRO,
            response_format="text"
        )
        
        return await self.process_request(request)
    
    async def generate_security_report(self, analysis_data: Dict[str, Any]) -> AIResponse:
        """Generate comprehensive security report"""
        prompt = f"""
        Generate a comprehensive security report based on this analysis data:
        
        {json.dumps(analysis_data, indent=2)}
        
        Provide a professional security assessment report with:
        - Executive summary
        - Technical findings
        - Risk assessment
        - Remediation recommendations
        """
        
        request = AIRequest(
            prompt=prompt,
            model=AIModel.GPT4O,
            response_format="text"
        )
        
        return await self.process_request(request)

# For backward compatibility
if __name__ == "__main__":
    # Test the fixed coordinator
    async def test_coordinator():
        coordinator = AdvancedAICoordinator()
        
        test_request = AIRequest(
            prompt="Analyze this API endpoint for security issues: GET /api/users/123",
            model=AIModel.GPT4O,
            response_format="text"
        )
        
        response = await coordinator.process_request(test_request)
        print(f"Success: {response.success}")
        print(f"Content: {response.content[:100]}...")
    
    asyncio.run(test_coordinator())
