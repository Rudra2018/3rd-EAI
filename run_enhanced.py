#!/usr/bin/env python3
"""
Enhanced Rudra Launch Script
"""

import os
import sys
import subprocess
from enhanced_config import config

def main():
    print("🚀 Launching Enhanced Rudra's Third Eye AI")
    
    # Validate config
    issues = config.validate()
    if issues:
        print("⚠️ Configuration issues:")
        for issue in issues:
            print(f"  - {issue}")
        print("\nPlease check your .env file")
        return 1
    
    # Launch enhanced app
    try:
        from enhanced_app import create_enhanced_app
        app = create_enhanced_app()
        app.run(debug=False)
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please install requirements: pip install -r requirements-final.txt")
        return 1
    except KeyboardInterrupt:
        print("\n👋 Shutting down Enhanced Rudra")
        return 0

if __name__ == "__main__":
    sys.exit(main())

