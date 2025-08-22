# utils/vrt.py
"""
Bugcrowd VRT mapping (lightweight, battle-tested defaults) + helpers.
If you place the official VRT JSON beside this file, we’ll try to load it.
Otherwise we fall back to the internal mapping below.

Priorities: P1,P2,P3,P4,P5. Report generation & Bug Bounty mode use only P1-P3.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any
import json
import os

@dataclass
class VRTDecision:
    priority: str    # P1..P5
    severity: str    # Critical/High/Medium/Low/Info
    rationale: str

# Minimal, opinionated defaults aligned with Bugcrowd VRT categories.
# These are applied with contextual rules inside `classify`.
_BASE_DEFAULTS: Dict[str, Tuple[str, str]] = {
    # type: (default_priority, default_severity)
    "SQL Injection": ("P1", "Critical"),
    "Command Injection": ("P1", "Critical"),
    "RCE": ("P1", "Critical"),
    "Auth Bypass / Broken Authentication": ("P1", "Critical"),
    "IDOR / BOLA": ("P2", "High"),
    "SSRF": ("P2", "High"),
    "Open Redirect": ("P3", "Medium"),
    "XSS": ("P3", "Medium"),
    "Sensitive Data Exposure": ("P2", "High"),
    "GraphQL Introspection Exposed": ("P3", "Medium"),
    "Security Headers Missing": ("P4", "Low"),
    "Rate Limiting Missing": ("P3", "Medium"),
    "CORS Misconfiguration": ("P3", "Medium"),
    "XXE": ("P2", "High"),
    "LDAP Injection": ("P2", "High"),
    "NoSQL Injection": ("P2", "High"),
}

def _try_load_official_vrt(path: str) -> Optional[dict]:
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return None

def _priority_order(p: str) -> int:
    return {"P1":1,"P2":2,"P3":3,"P4":4,"P5":5}.get(p, 5)

class VRT:
    def __init__(self, local_json_path: str = None):
        self.vrt_json = None
        if local_json_path:
            self.vrt_json = _try_load_official_vrt(local_json_path)

    def classify(self, vuln_type: str, ctx: Dict[str, Any]) -> VRTDecision:
        """
        ctx fields we honor (best-effort):
          - method (GET/POST/PUT/DELETE/PATCH/OPTIONS)
          - unauth_status (int)
          - auth_status (int)
          - redirect_location (str or None)
          - cors: {acao, acac, acam, reflected}
          - is_sensitive (bool)
          - requires_auth (bool)
          - has_auth_header (bool)
          - is_write (bool)  # method in POST/PUT/PATCH/DELETE
          - exploitable (bool)  # if we managed PoC success
        """
        base_pri, base_sev = _BASE_DEFAULTS.get(vuln_type, ("P4","Low"))

        # ---- Contextual upgrades/downgrades ----
        # Broken Auth: treat 302 to login as NOT vulnerable (strong FP reduction)
        if "Auth" in vuln_type or "Authentication" in vuln_type or "Bypass" in vuln_type:
            unauth = ctx.get("unauth_status")
            auth = ctx.get("auth_status")
            loc = (ctx.get("redirect_location") or "").lower()
            redirected_to_login = (unauth in (301,302,303,307,308)) and any(
                k in loc for k in ("login", "signin", "auth", "account", "authorize")
            )
            # If unauth → 200/201/204 or same protected JSON as auth, it's a real issue.
            # If unauth → 401/403 or 302→/login, it's protected (no vuln).
            if redirected_to_login or unauth in (401,403):
                return VRTDecision(priority="P5", severity="Info",
                                   rationale="Access control enforced (unauthenticated request not allowed).")
            if unauth and (200 <= unauth < 300):
                # Confirm different from a 'public' endpoint by checking ctx.exploitable
                if ctx.get("exploitable", True):
                    return VRTDecision(priority="P1", severity="Critical",
                                       rationale="Unauthenticated access returned 2xx to protected resource.")
                else:
                    return VRTDecision(priority="P4", severity="Low",
                                       rationale="Unauthenticated access 2xx but not exploitable content.")
            return VRTDecision(priority=base_pri, severity=base_sev,
                               rationale="Default classification for auth weakness.")

        # CORS Misconfiguration:
        if "CORS" in vuln_type:
            c = ctx.get("cors", {}) or {}
            acao = (c.get("acao") or "").strip()
            acac = str(c.get("acac") or "").lower() in ("true","1")
            reflected = bool(c.get("reflected"))
            is_write = bool(ctx.get("is_write"))
            requires_auth = bool(ctx.get("requires_auth"))
            # Bugcrowd-ish rules of thumb:
            # P1: ACAO="*" with ACAC=true is highly critical only if we confirm credentialed cross-origin reads.
            if acao == "*" and acac:
                return VRTDecision("P1","Critical","Wildcard ACAO with credentials = true (credential leakage risk).")
            # P2: Origin reflection with credentials true or wide methods incl. write on sensitive endpoints.
            if reflected and acac:
                return VRTDecision("P2","High","Origin reflection + credentials=true enables authenticated cross-origin reads.")
            # P3: Reflection without credentials, or wildcard on non-sensitive, or write-unsafe preflight policies
            if reflected or acao == "*":
                sev = "Medium" if is_write or requires_auth else "Low"
                pri = "P3" if sev == "Medium" else "P4"
                return VRTDecision(pri, sev, "Permissive CORS; impact limited without credentials.")
            # Otherwise informational
            return VRTDecision("P5","Info","CORS present but not exploitable under browser model.")

        # IDOR/BOLA: upgrade to P1 if directly exposes cross-tenant high-value objects and exploitable
        if "IDOR" in vuln_type or "BOLA" in vuln_type:
            if ctx.get("exploitable"):
                return VRTDecision("P1","Critical","Direct object reference to protected resource confirmed.")
            return VRTDecision("P2","High","Potential IDOR; manual validation advised.")

        # SSRF: upgrade to P1 if we observed internal metadata/EC2/169.254 or callback
        if "SSRF" in vuln_type:
            if ctx.get("exploitable"):
                return VRTDecision("P1","Critical","Internal resource access confirmed via SSRF.")
            return VRTDecision("P2","High","Potential SSRF; partial indicators found.")

        # Security headers missing = never higher than P3 by itself
        if "Security Headers" in vuln_type:
            return VRTDecision("P4","Low","Missing security headers; generally low-severity baseline.")

        # For all others, if we got PoC success, keep base or nudge higher
        if ctx.get("exploitable") and _priority_order(base_pri) > 2:
            # Don’t overshoot P2 for generic classes unless specified above
            return VRTDecision("P2","High",f"Exploitable {vuln_type} confirmed.")
        return VRTDecision(base_pri, base_sev, f"Default classification for {vuln_type}.")

