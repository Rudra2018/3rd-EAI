#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Configuration for Rudra's Third Eye AI
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class EnhancedConfig:
    """Enhanced configuration class"""
    
    # API Keys
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    
    # Bug Bounty API Keys
    HACKERONE_API_KEY: str = os.getenv("HACKERONE_API_KEY", "")
    HACKERONE_API_USERNAME: str = os.getenv("HACKERONE_API_USERNAME", "")
    BUGCROWD_API_KEY: str = os.getenv("BUGCROWD_API_KEY", "")
    INTIGRITI_API_TOKEN: str = os.getenv("INTIGRITI_API_TOKEN", "")
    
    # Application Settings
    AI_ENHANCED: bool = True
    ML_ENHANCED: bool = True
    CONTINUOUS_LEARNING: bool = True
    MAX_CONCURRENT_SCANS: int = 10
    DEFAULT_TIMEOUT: int = 30
    
    # Model Settings
    DEFAULT_AI_MODEL: str = "gpt-4o"
    FALLBACK_AI_MODEL: str = "gpt-4o-mini"
    AI_TEMPERATURE: float = 0.2
    
    # Paths
    MODELS_DIR: str = "models"
    REPORTS_DIR: str = "reports"
    CACHE_DIR: str = ".ai_cache"
    
    def validate(self) -> List[str]:
        """Validate configuration and return any issues"""
        issues = []
        
        if self.AI_ENHANCED and not self.OPENAI_API_KEY:
            issues.append("OPENAI_API_KEY required for AI features")
        
        if not os.path.exists(self.MODELS_DIR):
            os.makedirs(self.MODELS_DIR, exist_ok=True)
            
        if not os.path.exists(self.REPORTS_DIR):
            os.makedirs(self.REPORTS_DIR, exist_ok=True)
            
        return issues

# Global config instance
config = EnhancedConfig()

