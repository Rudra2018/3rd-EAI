# report_generator.py
import os
import datetime
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Rudra Scan Report</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #111a2b;
      --muted: #a8b3cf;
      --text: #e6edf7;
      --accent: #6ee7f9;
      --accent2: #a78bfa;
      --danger: #fb7185;
      --warn: #fbbf24;
      --ok: #34d399;
    }}
    body {{ margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; background: var(--bg); color: var(--text); }}
    .wrap {{ padding: 40px; }}
    .title {{ font-size: 28px; font-weight: 800; letter-spacing: .3px; }}
    .muted {{ color: var(--muted); }}
    .grid {{ display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; }}
    .card {{ background: linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)); border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 16px 18px; }}
    .kpi {{ font-size: 32px; font-weight: 700; }}
    .tag {{ display:inline-block; padding:3px 8px; border-radius: 999px; font-size: 12px; border: 1px solid rgba(255,255,255,.2); margin-right:6px; }}
    .sev-crit {{ background: rgba(251,113,133,.1); border-color: var(--danger); color: var(--danger); }}
    .sev-high {{ background: rgba(251,113,133,.08); border-color: var(--danger); color: var(--danger); }}
    .sev-mid {{ background: rgba(251,191,36,.08); border-color: var(--warn); color: var(--warn); }}
    .sev-low {{ background: rgba(110,231,249,.08); border-color: var(--accent); color: var(--accent); }}
    .table {{ width:100%; border-collapse: separate; border-spacing: 0 8px; }}
    .tr {{ background: #0f172a; border-radius: 12px; }}
    .td {{ padding: 12px 14px; font-size: 14px; }}
    .pill {{ padding: 2px 8px; border-radius: 999px; border: 1px solid rgba(255,255,255,.2); font-size: 12px; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New"; font-size: 12px; }}
    .hr {{ height: 1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,.25), transparent); margin: 18px 0; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="title">Security Report — {product}</div>
    <div class="muted">{ts}</div>

    <div class="grid" style="margin-top:20px;">
      <div class="card" style="grid-column: span 3;">
        <div class="muted">Total Findings</div>
        <div class="kpi">{total}</div>
      </div>
      <div class="card" style="grid-column: span 3;">
        <div class="muted">Severity</div>
        <div><span class="tag sev-crit">Critical {critical}</span>
             <span class="tag sev-high">High {high}</span></div>
        <div style="margin-top:6px;"><span class="tag sev-mid">Medium {medium}</span>
             <span class="tag sev-low">Low {low}</span></div>
      </div>
      <div class="card" style="grid-column: span 3;">
        <div class="muted">Priorities</div>
        <div><span class="tag">P1 {p1}</span><span class="tag">P2 {p2}</span>
             <span class="tag">P3 {p3}</span><span class="tag">P4 {p4}</span></div>
      </div>
      <div class="card" style="grid-column: span 3;">
        <div class="muted">Analysis</div>
        <div><span class="tag">Endpoints {endpoints}</span><span class="tag">AI Tests {tests}</span></div>
      </div>
    </div>

    <div class="hr"></div>

    <div class="title" style="font-size:20px;">Findings</div>
    <table class="table" style="margin-top:8px;">
      {rows}
    </table>
  </div>
</body>
</html>
"""

def _row(v: Dict[str, Any]) -> str:
    sev = (v.get("severity") or "Low").lower()
    sev_class = "sev-low"
    if sev == "critical": sev_class = "sev-crit"
    elif sev == "high": sev_class = "sev-high"
    elif sev == "medium": sev_class = "sev-mid"
    tags = " ".join(f'<span class="pill">{t}</span>' for t in (v.get("tags") or []))
    desc = (v.get("description") or "")[:240]
    endpoint = v.get("endpoint") or v.get("url") or ""
    method = v.get("method") or ""
    return f"""
      <tr class="tr">
        <td class="td"><span class="tag {sev_class}">{v.get("severity","Low")}</span></td>
        <td class="td"><div><b>{v.get("type","")}</b></div><div class="muted">{desc}</div></td>
        <td class="td"><div class="mono">{method} {endpoint}</div></td>
        <td class="td">{tags}</td>
      </tr>
    """

class ComprehensiveReportGenerator:
    def generate_enhanced_report(self, scan_id: str, collection_analysis: Dict[str, Any], test_cases: List[Dict[str, Any]],
                                 vulnerabilities: List[Dict[str, Any]], ai_enabled: bool) -> str:
        summary = {
            "total": len(vulnerabilities),
            "critical": sum(1 for v in vulnerabilities if (v.get("severity") == "Critical")),
            "high": sum(1 for v in vulnerabilities if (v.get("severity") == "High")),
            "medium": sum(1 for v in vulnerabilities if (v.get("severity") == "Medium")),
            "low": sum(1 for v in vulnerabilities if (v.get("severity") == "Low")),
            "p1": sum(1 for v in vulnerabilities if (v.get("priority") == "P1")),
            "p2": sum(1 for v in vulnerabilities if (v.get("priority") == "P2")),
            "p3": sum(1 for v in vulnerabilities if (v.get("priority") == "P3")),
            "p4": sum(1 for v in vulnerabilities if (v.get("priority") == "P4")),
            "endpoints": len(collection_analysis.get("endpoints") or []),
            "tests": len(test_cases or []),
        }
        rows = "\n".join(_row(v) for v in vulnerabilities)

        html = HTML_TEMPLATE.format(
            product="Rudra's Third Eye (AI)",
            ts=datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
            rows=rows, **summary
        )

        # Prefer WeasyPrint, then pdfkit, else write HTML next to PDF path
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, f"rudra_report_{scan_id}.pdf")
        try:
            from weasyprint import HTML  # pip install weasyprint
            HTML(string=html).write_pdf(pdf_path)
            log.info("Report generated via WeasyPrint")
            return pdf_path
        except Exception:
            try:
                import pdfkit  # requires wkhtmltopdf
                tmp_html = os.path.join(reports_dir, f"tmp_{scan_id}.html")
                with open(tmp_html, "w", encoding="utf-8") as f:
                    f.write(html)
                pdfkit.from_file(tmp_html, pdf_path)
                os.remove(tmp_html)
                log.info("Report generated via pdfkit")
                return pdf_path
            except Exception as e:
                # Fallback: write HTML and let API serve it
                html_path = os.path.join(reports_dir, f"rudra_report_{scan_id}.html")
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html)
                log.warning(f"PDF generation failed: {e}. Wrote HTML instead.")
                return html_path

