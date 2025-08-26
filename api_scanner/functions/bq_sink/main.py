import base64, json, os
import functions_framework
from google.cloud import bigquery

BQ_TABLE = os.getenv("BQ_TABLE")  # e.g. mobile-new-pip.vuln_data.findings
bq = bigquery.Client()

@functions_framework.cloud_event
def handler(cloud_event):
    msg = cloud_event.data["message"]
    finding = json.loads(base64.b64decode(msg["data"]).decode("utf-8"))

    # Flatten a few fields for convenience
    row = {
        "program": finding.get("program"),
        "scope_url": finding.get("scope_url"),
        "analysis_title": finding.get("analysis",{}).get("title"),
        "analysis_severity": finding.get("analysis",{}).get("severity"),
        "vrt_category": finding.get("analysis",{}).get("vrt_category"),
        "confidence": finding.get("analysis",{}).get("confidence"),
        "recommended_fix": finding.get("analysis",{}).get("recommended_fix"),
        "evidence": finding.get("evidence"),
        "raw_event": finding.get("raw_event"),
        "created_at": finding.get("created_at"),
        "raw_json": json.dumps(finding),
    }

    errors = bq.insert_rows_json(BQ_TABLE, [row])
    if errors:
        # surface to logs; Cloud Functions Gen2 will mark as 500
        raise RuntimeError(f"BigQuery insert failed: {errors}")

