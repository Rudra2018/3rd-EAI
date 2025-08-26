# Minimal, extensible VRT mapping helpers.
from typing import Dict

VRT_HINTS = [
  # tuples: (signal, vrt_category, default_sev)
  ("idor", "API — BOLA/IDOR", "high"),
  ("object level auth", "API — BOLA/IDOR", "high"),
  ("graphql introspection", "GraphQL — Introspection Enabled", "medium"),
  ("n+1 batching", "GraphQL — Resource Exhaustion / Batching", "medium"),
  ("deep query", "GraphQL — Query Depth Abuse", "medium"),
  ("rate limit", "API — Improper Rate Limiting", "medium"),
  ("jwt none alg", "API — Broken Auth / JWT", "critical"),
  ("hardcoded token", "API — Sensitive Data Exposure", "high"),
  ("ssrf", "API — SSRF", "critical"),
  ("sqli", "API — SQL Injection", "critical"),
  ("rce", "API — Remote Code Execution", "critical"),
]

SEV_ORDER = ["info", "low", "medium", "high", "critical"]

def map_vrt_from_context(ctx: Dict) -> Dict:
    text = (ctx.get("title","") + " " + ctx.get("summary","") + " " + str(ctx)).lower()
    for sig, vrt, sev in VRT_HINTS:
        if sig in text:
            return {"vrt_category": vrt, "severity_hint": sev}
    return {"vrt_category": "API — Other", "severity_hint": "medium"}

def normalize_severity(model_sev: str, hint_sev: str) -> str:
    mi = SEV_ORDER.index(model_sev) if model_sev in SEV_ORDER else 2
    hi = SEV_ORDER.index(hint_sev) if hint_sev in SEV_ORDER else 2
    return SEV_ORDER[max(mi, hi)]  # never undercut the hint

