#!/usr/bin/env python3
# Enhanced Rudra's Third Eye AI - Test Script

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_ai_models():
    '''Test AI model connectivity'''
    print("🤖 Testing AI Models...")
    
    try:
        from ai.advanced_ai_coordinator import AdvancedAICoordinator
        coordinator = AdvancedAICoordinator()
        
        models = coordinator.models
        print(f"✅ Available AI models: {list(models.keys())}")
        
        return True
    except Exception as e:
        print(f"❌ AI models test failed: {e}")
        return False

def test_databases():
    '''Test database connectivity'''
    print("🗄️ Testing Databases...")
    
    try:
        import sqlite3
        conn = sqlite3.connect('data/rudra_enhanced.db')
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()
        print("✅ Database connection successful")
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_ml_libraries():
    '''Test ML library imports'''
    print("🧠 Testing ML Libraries...")
    
    try:
        import sklearn
        import numpy
        import pandas
        print("✅ Core ML libraries available")
        
        try:
            import torch
            print("✅ PyTorch available")
        except ImportError:
            print("⚠️  PyTorch not available (optional)")
            
        return True
    except Exception as e:
        print(f"❌ ML libraries test failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Running Enhanced Rudra Tests...")
    
    tests = [
        test_databases,
        test_ml_libraries, 
        test_ai_models
    ]
    
    results = []
    for test in tests:
        results.append(test())
        print()
    
    if all(results):
        print("✅ All tests passed! Enhanced Rudra is ready.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please check the configuration.")
        sys.exit(1)
