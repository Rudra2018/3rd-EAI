"""
Vertex AI (Gemini) analyzer returning strict JSON with:
title, severity, vrt_category, confidence, rationale, recommended_fix, references[]
"""

import os
import json
from typing import Dict, Any
from vertexai import init
from vertexai.generative_models import GenerativeModel

PROJECT = os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT")
LOCATION = os.getenv("GCP_REGION", "us-central1")
MODEL_NAME = os.getenv("VERTEX_MODEL", "gemini-2.5-pro")

init(project=PROJECT, location=LOCATION)
_gemini = GenerativeModel(MODEL_NAME)

SYSTEM = (
    "You are an elite API security analyst. "
    "Classify findings with severity and Bugcrowd VRT. "
    "Return strict JSON with keys: "
    "title, severity(one of: critical, high, medium, low, info), "
    "vrt_category, confidence(0-1), rationale, recommended_fix, references"
)

def analyze_finding(context: Dict[str, Any]) -> Dict[str, Any]:
    prompt = f"""SYSTEM:
{SYSTEM}

CONTEXT (JSON):
{json.dumps(context, ensure_ascii=False)}

RULES:
- Base severity on exploitability, impact, and auth context.
- Map to Bugcrowd VRT (e.g., "API — BOLA/IDOR", "GraphQL — Introspection Enabled").
- If uncertain, reduce confidence and explain why.
- Output JSON ONLY.
"""
    try:
        out = _gemini.generate_content([prompt])
        txt = (out.text or "").strip()
        return json.loads(txt)
    except Exception:
        # Guardrail fallback
        return {
            "title": context.get("title", "Potential Issue"),
            "severity": "medium",
            "vrt_category": "API — Other",
            "confidence": 0.5,
            "rationale": "Fallback classification",
            "recommended_fix": "Review evidence and apply least-privilege/authz checks.",
            "references": []
        }

