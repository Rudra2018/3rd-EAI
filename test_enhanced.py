#!/usr/bin/env python3
"""
Quick test script for Enhanced Rudra setup
"""

import os
import sys
from dotenv import load_dotenv

def test_enhanced_setup():
    print("🧪 Testing Enhanced Rudra Setup...")
    
    # Load environment
    load_dotenv()
    
    # Test API keys
    openai_key = os.getenv('OPENAI_API_KEY')
    gemini_key = os.getenv('GEMINI_API_KEY')
    h1_key = os.getenv('HACKERONE_API_KEY')
    
    print(f"✅ OpenAI API Key: {'✓' if openai_key else '✗'}")
    print(f"✅ Gemini API Key: {'✓' if gemini_key else '✗'}")  
    print(f"✅ HackerOne API Key: {'✓' if h1_key else '✗'}")
    
    # Test imports
    try:
        from advanced_ai_coordinator import AdvancedAICoordinator
        print("✅ AI Coordinator: ✓")
    except ImportError as e:
        print(f"❌ AI Coordinator: ✗ ({e})")
    
    try:
        from agents.beast_mode import EnhancedBeastMode
        print("✅ Beast Mode: ✓")
    except ImportError as e:
        print(f"❌ Beast Mode: ✗ ({e})")
    
    try:
        from core.api_scanner import EnhancedAPIScanner
        print("✅ Enhanced Scanner: ✓")
    except ImportError as e:
        print(f"❌ Enhanced Scanner: ✗ ({e})")
    
    # Test directories
    required_dirs = ['models', 'reports', 'logs', 'data']
    for directory in required_dirs:
        exists = os.path.exists(directory)
        print(f"✅ Directory {directory}: {'✓' if exists else '✗'}")
    
    print("\n🎯 Setup verification complete!")
    
    if openai_key and os.path.exists('models'):
        print("✅ Ready to run Enhanced Rudra!")
        print("Run: python enhanced_app.py")
    else:
        print("⚠️ Some components missing - check setup")

if __name__ == "__main__":
    test_enhanced_setup()

