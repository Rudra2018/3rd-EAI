# utils/vrt.py
"""
Bugcrowd VRT mapping (lightweight, battle-tested defaults) + helpers.

Priorities: P1,P2,P3,P4,P5. Report generation & Bug Bounty mode usually use P1-P3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any
import json
import os

__all__ = ["VRTDecision", "VRT", "VRTMapper", "map_vrt_from_context"]

@dataclass
class VRTDecision:
    priority: str    # P1..P5
    severity: str    # Critical/High/Medium/Low/Info
    rationale: str

# Minimal, opinionated defaults aligned with common Bugcrowd VRT categories.
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
    """
    Core classifier. You can use this directly, or via VRTMapper for compatibility.
    """
    def __init__(self, local_json_path: str | None = None):
        self.vrt_json = None
        # Auto-load if not provided explicitly and a file exists next to us
        if local_json_path is None:
            here = os.path.dirname(os.path.abspath(__file__))
            candidate = os.path.join(here, "bugcrowd_vrt.json")
            if os.path.exists(candidate):
                local_json_path = candidate
        if local_json_path:
            self.vrt_json = _try_load_official_vrt(local_json_path)

    def classify(self, vuln_type: str, ctx: Dict[str, Any]) -> VRTDecision:
        """
        ctx fields honored (best-effort):
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
            loc = (ctx.get("redirect_location") or "").lower()
            redirected_to_login = (unauth in (301,302,303,307,308)) and any(
                k in loc for k in ("login", "signin", "auth", "account", "authorize")
            )
            if redirected_to_login or unauth in (401,403):
                return VRTDecision(priority="P5", severity="Info",
                                   rationale="Access control enforced (unauthenticated request not allowed).")
            if unauth and (200 <= unauth < 300):
                if ctx.get("exploitable", True):
                    return VRTDecision(priority="P1", severity="Critical",
                                       rationale="Unauthenticated access returned 2xx to protected resource.")
                else:
                    return VRTDecision(priority="P4", severity="Low",
                                       rationale="Unauthenticated access 2xx but not clearly exploitable.")
            return VRTDecision(base_pri, base_sev,
                               rationale="Default classification for auth weakness.")

        # CORS Misconfiguration:
        if "CORS" in vuln_type:
            c = ctx.get("cors", {}) or {}
            acao = (c.get("acao") or "").strip()
            acac = str(c.get("acac") or "").lower() in ("true","1")
            reflected = bool(c.get("reflected"))
            is_write = bool(ctx.get("is_write"))
            requires_auth = bool(ctx.get("requires_auth"))
            if acao == "*" and acac:
                return VRTDecision("P1","Critical","Wildcard ACAO with credentials=true (credential leakage risk).")
            if reflected and acac:
                return VRTDecision("P2","High","Origin reflection + credentials=true enables authenticated cross-origin reads.")
            if reflected or acao == "*":
                sev = "Medium" if is_write or requires_auth else "Low"
                pri = "P3" if sev == "Medium" else "P4"
                return VRTDecision(pri, sev, "Permissive CORS; impact limited without credentials.")
            return VRTDecision("P5","Info","CORS present but not exploitable under browser model.")

        # IDOR/BOLA:
        if "IDOR" in vuln_type or "BOLA" in vuln_type:
            if ctx.get("exploitable"):
                return VRTDecision("P1","Critical","Direct object reference to protected resource confirmed.")
            return VRTDecision("P2","High","Potential IDOR; manual validation advised.")

        # SSRF:
        if "SSRF" in vuln_type:
            if ctx.get("exploitable"):
                return VRTDecision("P1","Critical","Internal resource access confirmed via SSRF.")
            return VRTDecision("P2","High","Potential SSRF; partial indicators found.")

        # Security headers missing = never higher than P3 by itself
        if "Security Headers" in vuln_type:
            return VRTDecision("P4","Low","Missing security headers; generally low-severity baseline.")

        # For all others, if we got PoC success, keep base or nudge higher but cap at P2 for generic classes
        if ctx.get("exploitable") and _priority_order(base_pri) > 2:
            return VRTDecision("P2","High",f"Exploitable {vuln_type} confirmed.")

        return VRTDecision(base_pri, base_sev, f"Default classification for {vuln_type}.")

class VRTMapper:
    """
    Backward-compatible wrapper expected by `from utils.vrt import VRTMapper`.

    Methods:
      - classify(vuln_type, ctx) -> VRTDecision
      - map(vuln_type, ctx) -> dict with priority/severity/rationale (useful for JSON)
      - classify_from_finding(finding_dict) -> VRTDecision
        finding_dict keys (best-effort):
            {
              "type": "CORS Misconfiguration",
              "context": {...}  # same shape as ctx
            }
    """
    def __init__(self, local_json_path: str | None = None):
        self._vrt = VRT(local_json_path)

    def classify(self, vuln_type: str, ctx: Dict[str, Any] | None = None) -> VRTDecision:
        ctx = ctx or {}
        return self._vrt.classify(vuln_type, ctx)

    def map(self, vuln_type: str, ctx: Dict[str, Any] | None = None) -> Dict[str, Any]:
        decision = self.classify(vuln_type, ctx or {})
        return {
            "priority": decision.priority,
            "severity": decision.severity,
            "rationale": decision.rationale,
        }

    def classify_from_finding(self, finding: Dict[str, Any]) -> VRTDecision:
        vuln_type = str(finding.get("type") or finding.get("category") or "Uncategorized")
        ctx = finding.get("context") or finding.get("ctx") or {}
        # Optional heuristics if only signatures are present
        signature = (finding.get("signature") or finding.get("rule_name") or "").lower()
        if vuln_type == "Uncategorized" and signature:
            if "sql" in signature and "injection" in signature:
                vuln_type = "SQL Injection"
            elif "command" in signature and "injection" in signature:
                vuln_type = "Command Injection"
            elif "xss" in signature:
                vuln_type = "XSS"
            elif "idor" in signature or "bola" in signature:
                vuln_type = "IDOR / BOLA"
            elif "ssrf" in signature:
                vuln_type = "SSRF"
            elif "cors" in signature:
                vuln_type = "CORS Misconfiguration"
            elif "auth" in signature or "authentication" in signature:
                vuln_type = "Auth Bypass / Broken Authentication"

        return self._vrt.classify(vuln_type, ctx)

def map_vrt_from_context(ctx: Dict) -> Dict:
    vrt_mapper = VRTMapper()
    vrt_decision = vrt_mapper.classify(
        ctx.get("category") or ctx.get("title") or "Unknown",
        ctx
    )
    return {
        "vrt_category": vrt_decision.priority + " - " + vrt_decision.severity,
        "severity_hint": vrt_decision.severity.lower()
    }

def normalize_severity(model_sev: str, hint_sev: str) -> str:
    mi = SEV_ORDER.index(model_sev) if model_sev in SEV_ORDER else 2
    hi = SEV_ORDER.index(hint_sev) if hint_sev in SEV_ORDER else 2
    return SEV_ORDER[max(mi, hi)]
