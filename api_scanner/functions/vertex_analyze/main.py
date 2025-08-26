# Cloud Function (2nd gen, Python) subscribed to findings.raw
import base64, json, os
from google.cloud import pubsub_v1
from services.vertex_ai_client import analyze_finding
from services.vrt_mapper import map_vrt_from_context, normalize_severity

PROJECT_ID = os.getenv("GCP_PROJECT")
TOPIC_OUT  = os.getenv("TOPIC_FINDINGS_CURATED", "findings.curated")
publisher  = pubsub_v1.PublisherClient()
topic_out  = publisher.topic_path(PROJECT_ID, TOPIC_OUT)

def handler(event, context):
    data = json.loads(base64.b64decode(event["data"]).decode("utf-8"))
    model = analyze_finding(data)
    hint  = map_vrt_from_context(data)
    model["vrt_category"] = model.get("vrt_category") or hint["vrt_category"]
    model["severity"]     = normalize_severity(model.get("severity","medium"), hint["severity_hint"])
    enriched = {**data, "analysis": model}
    publisher.publish(topic_out, json.dumps(enriched).encode("utf-8"))

