#!/usr/bin/env python3
"""Integration tests for Enhanced API Security Scanner"""

import requests
import time
import json

BASE_URL = "http://localhost:8000"

def test_scanner():
    print("🧪 Testing Enhanced API Security Scanner...")
    print("=" * 50)
    
    # Test 1: Health check with robust error handling
    print("\n1. 🏥 Testing health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=10)
        
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            try:
                health = response.json()
                print(f"   ✅ Response received: {json.dumps(health, indent=2)}")
                
                # Check for expected keys
                if 'status' in health:
                    print(f"   ✅ Health Status: {health['status']}")
                else:
                    print(f"   ⚠️  No 'status' key found. Available keys: {list(health.keys())}")
                
                if 'version' in health:
                    print(f"   ✅ Version: {health['version']}")
                
                if 'components' in health:
                    active_components = sum(health['components'].values()) if isinstance(health['components'], dict) else 0
                    print(f"   ✅ Components Active: {active_components}")
                else:
                    print("   ⚠️  No 'components' key found")
                    
            except json.JSONDecodeError:
                print(f"   ❌ Invalid JSON response: {response.text}")
        else:
            print(f"   ❌ HTTP Error: {response.status_code} - {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("   ❌ Connection failed - Is the server running on port 8000?")
        print("   💡 Make sure to run: python app.py")
        return False
    except requests.exceptions.Timeout:
        print("   ❌ Request timed out")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False
    
    # Test 2: Check if server is responding
    print("\n2. 🌐 Testing server connectivity...")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"   ✅ Server responding on port 8000 (Status: {response.status_code})")
    except Exception as e:
        print(f"   ❌ Server connectivity issue: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 Integration test complete!")
    return True

def quick_health_check():
    """Quick health check for debugging"""
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        print(f"Quick Check - Status: {response.status_code}")
        if response.status_code == 200:
            print(f"Response: {response.json()}")
        else:
            print(f"Error Response: {response.text}")
    except Exception as e:
        print(f"Quick Check Failed: {e}")

if __name__ == "__main__":
    # Run quick check first
    print("🔍 Quick Health Check:")
    quick_health_check()
    print()
    
    # Run full test
    test_scanner()
