
from __future__ import annotations
import os, orjson, datetime
from typing import Any, Dict, List

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def write_json(obj: Any, path: str):
    with open(path,"wb") as f:
        f.write(orjson.dumps(obj, option=orjson.OPT_INDENT_2))

def write_md(text: str, path: str):
    with open(path,"w",encoding="utf-8") as f:
        f.write(text)

def render_markdown(findings: List[Dict[str, Any]]) -> str:
    lines = ["# API Scan Findings", "", f"_Generated: {datetime.datetime.utcnow().isoformat()}Z_", ""]
    for f in findings:
        lines.append(f"## {f['title']} ({f['severity']}) — score {f['score']}")
        lines.append(f"**Endpoint:** `{f['endpoint']}`  \n**Category:** `{f['category']}`")
        recs = f.get("recommendations") or []
        if recs:
            lines.append("**Recommendations:**")
            for r in recs:
                lines.append(f"- {r}")
        lines.append("")
    return "\n".join(lines)
