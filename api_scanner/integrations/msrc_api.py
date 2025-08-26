import os
from typing import List, Dict, Any

# MSRC is a vendor VRP (single program with multiple products), not a marketplace with third-party scopes.
# We model it as one “program” + a coarse set of API-ish targets when present.

def msrc_programs() -> List[Dict[str, Any]]:
    policy = "https://www.microsoft.com/en-us/msrc/bounty"
    return [{
        "platform": "msrc",
        "slug": "microsoft-vrp",
        "policy": policy,
        "targets": [
            # You SHOULD NOT scan random Microsoft endpoints; limit to explicit test/safe targets if MSRC provides any.
            # We leave scopes empty for safety; users can seed via env MSRC_SCOPES_JSON if they have explicit in-scope endpoints from MSRC communications.
        ]
    }]

