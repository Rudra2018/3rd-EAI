# api_scanner/functions/notifier/main.py
import base64
import json
import os
import logging
from typing import Dict, Any, Optional

import functions_framework
from cloudevents.http import CloudEvent
import requests

# ---------- Configuration ----------
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
EMAIL_ENABLED = os.getenv("EMAIL_NOTIFICATIONS", "false").lower() == "true"
SEVERITY_THRESHOLD = os.getenv("NOTIFY_SEVERITY_THRESHOLD", "medium").lower()

# Severity levels (lower number = higher severity)
SEVERITY_LEVELS = {
    "critical": 1,
    "high": 2, 
    "medium": 3,
    "low": 4,
    "info": 5
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _should_notify(severity: str) -> bool:
    """Check if finding severity meets notification threshold."""
    finding_level = SEVERITY_LEVELS.get(severity.lower(), 5)
    threshold_level = SEVERITY_LEVELS.get(SEVERITY_THRESHOLD, 3)
    return finding_level <= threshold_level

def _format_slack_message(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Format finding as Slack message with rich formatting."""
    severity = finding.get("analysis_severity", "unknown").upper()
    title = finding.get("analysis_title", "Unnamed Finding")
    program = finding.get("program", "unknown")
    url = finding.get("scope_url", "")
    vrt_category = finding.get("vrt_category", "Unknown")
    confidence = finding.get("confidence", 0)
    fix = finding.get("recommended_fix", "No fix provided")
    
    # Color coding by severity
    color_map = {
        "CRITICAL": "#FF0000",  # Red
        "HIGH": "#FF8C00",      # Dark Orange  
        "MEDIUM": "#FFD700",    # Gold
        "LOW": "#32CD32",       # Lime Green
        "INFO": "#87CEEB"       # Sky Blue
    }
    color = color_map.get(severity, "#808080")
    
    # Severity emoji
    emoji_map = {
        "CRITICAL": "🚨",
        "HIGH": "⚠️", 
        "MEDIUM": "🔍",
        "LOW": "ℹ️",
        "INFO": "📋"
    }
    emoji = emoji_map.get(severity, "🔍")
    
    return {
        "text": f"Security Finding: {severity} - {title}",
        "attachments": [{
            "color": color,
            "fields": [
                {
                    "title": f"{emoji} {severity} Finding",
                    "value": title,
                    "short": False
                },
                {
                    "title": "Program",
                    "value": program,
                    "short": True
                },
                {
                    "title": "VRT Category", 
                    "value": vrt_category,
                    "short": True
                },
                {
                    "title": "Target URL",
                    "value": f"`{url}`",
                    "short": False
                },
                {
                    "title": "Confidence",
                    "value": f"{confidence:.1%}" if confidence else "Unknown",
                    "short": True
                },
                {
                    "title": "Recommended Fix",
                    "value": fix[:200] + "..." if len(fix) > 200 else fix,
                    "short": False
                }
            ],
            "footer": "API Security Scanner",
            "ts": int(finding.get("created_at", "0").replace("T", " ").replace("Z", "").replace("-", "").replace(":", "")[:8])
        }]
    }

def _send_slack_notification(finding: Dict[str, Any]) -> bool:
    """Send finding to Slack webhook."""
    if not SLACK_WEBHOOK_URL:
        logger.info("Slack webhook not configured, skipping Slack notification")
        return False
        
    try:
        message = _format_slack_message(finding)
        
        response = requests.post(
            SLACK_WEBHOOK_URL,
            json=message,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        
        logger.info(f"Slack notification sent successfully for finding: {finding.get('analysis_title')}")
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Slack notification: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending Slack notification: {e}")
        return False

def _send_email_notification(finding: Dict[str, Any]) -> bool:
    """Send finding via email (placeholder - integrate with SendGrid/SES/etc.)."""
    if not EMAIL_ENABLED:
        return False
        
    # TODO: Implement email integration
    logger.info("Email notifications not implemented yet")
    return False

@functions_framework.cloud_event  
def notifier_handler(cloud_event: CloudEvent) -> None:
    """
    Cloud Function to send notifications for high-priority vulnerability findings.
    Triggered by Pub/Sub messages from scan-worker.
    """
    logger.info("Processing vulnerability finding for notification")
    
    try:
        # Extract Pub/Sub message
        if not cloud_event.data or "message" not in cloud_event.data:
            logger.warning("No message data in event")
            return
            
        message = cloud_event.data["message"]
        if "data" not in message:
            logger.warning("No data in message") 
            return
            
        # Decode the finding
        message_data = base64.b64decode(message["data"]).decode("utf-8")
        finding = json.loads(message_data)
        
        # Check if we should notify based on severity
        severity = finding.get("analysis_severity", "info").lower()
        if not _should_notify(severity):
            logger.info(f"Severity '{severity}' below threshold '{SEVERITY_THRESHOLD}', skipping notification")
            return
            
        # Validate required fields
        required_fields = ["analysis_title", "analysis_severity", "program", "scope_url"]
        missing_fields = [field for field in required_fields if not finding.get(field)]
        
        if missing_fields:
            logger.error(f"Missing required fields for notification: {missing_fields}")
            return
            
        logger.info(f"Sending {severity.upper()} notification: {finding.get('analysis_title')}")
        
        # Send notifications
        notification_sent = False
        
        # Slack notification
        if _send_slack_notification(finding):
            notification_sent = True
            
        # Email notification  
        if _send_email_notification(finding):
            notification_sent = True
            
        if not notification_sent:
            logger.warning("No notifications were sent - check configuration")
        else:
            logger.info(f"Notification processing completed for finding: {finding.get('analysis_title')}")
            
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON message: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in notifier_handler: {e}")
        # Don't re-raise - we don't want to cause message redelivery for notification failures

