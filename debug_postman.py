# Create debug_postman.py
import json
from integrations.postman import PostmanIntegration

# Create test collection
test_collection = {
    "info": {
        "name": "Debug Test Collection"
    },
    "item": [
        {
            "name": "Simple Test",
            "request": {
                "method": "GET",
                "url": "https://jsonplaceholder.typicode.com/users/1"
            }
        }
    ]
}

with open('debug_collection.json', 'w') as f:
    json.dump(test_collection, f, indent=2)

# Test integration directly
print("🔍 Testing Postman Integration directly...")
try:
    integration = PostmanIntegration()
    vulnerabilities = integration.run_security_scan('debug_collection.json')
    print(f"✅ Direct test successful: {len(vulnerabilities)} vulnerabilities")
    for vuln in vulnerabilities:
        print(f"  - {vuln}")
except Exception as e:
    print(f"❌ Direct test failed: {e}")
    import traceback
    traceback.print_exc()

# Cleanup
import os
if os.path.exists('debug_collection.json'):
    os.remove('debug_collection.json')

