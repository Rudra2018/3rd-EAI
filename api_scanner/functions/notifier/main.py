import base64, json, os, requests
import functions_framework

SEVERITIES = {"high","medium","low","info"}  # you filter below

@functions_framework.cloud_event
def handler(cloud_event):
    msg = cloud_event.data["message"]
    finding = json.loads(base64.b64decode(msg["data"]).decode("utf-8"))

    sev = (finding.get("analysis",{}).get("severity") or "medium").lower()
    # ignore low/info (change logic if you really wanted otherwise)
    if sev in ("low", "info"):
        return

    title = finding["analysis"]["title"]
    vrt   = finding["analysis"]["vrt_category"]
    conf  = finding["analysis"].get("confidence", 0.5)
    pgm   = finding.get("program")
    url   = finding.get("scope_url")
    fix   = finding["analysis"].get("recommended_fix","")

    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if webhook:
        requests.post(webhook, json={
            "text": f"*{sev.upper()}* [{pgm}] {title}\nVRT: {vrt} (conf {conf:.2f})\nScope: {url}\nFix: {fix}"
        })

