#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Base Classes and Utilities
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

log = logging.getLogger(__name__)

class AdvancedAIBase(ABC):
    """Base class for AI-powered components"""
    
    def __init__(self):
        self.initialized = False
        self.ai_coordinator = None
        
    async def initialize(self):
        """Initialize AI components"""
        try:
            from ai.advanced_ai_coordinator import AdvancedAICoordinator
            self.ai_coordinator = AdvancedAICoordinator()
            self.initialized = True
            log.info(f"✅ {self.__class__.__name__} initialized")
        except Exception as e:
            log.error(f"❌ Failed to initialize {self.__class__.__name__}: {e}")
    
    def is_ready(self) -> bool:
        """Check if component is ready"""
        return self.initialized and self.ai_coordinator is not None

class FalsePositiveAnalysis:
    """Enhanced false positive analysis result"""
    
    def __init__(self, is_false_positive: bool = False, confidence: float = 0.0, 
                 reasons: list = None, analysis: dict = None):
        self.is_false_positive = is_false_positive
        self.confidence = confidence
        self.reasons = reasons or []
        self.analysis = analysis or {}

