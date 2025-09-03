import os
import json
import logging
import time
from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from google.cloud import pubsub_v1

# Logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [scan-dispatcher] %(message)s",
)
log = logging.getLogger("scan-dispatcher")

app = FastAPI(title="Scan Dispatcher", version="2.0.0")

# Configuration
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
JOBS_TOPIC = os.getenv("PUBSUB_JOBS_TOPIC", "vuln-jobs")

if not PROJECT_ID:
    raise ValueError("PROJECT_ID environment variable is required")

# Pub/Sub setup
publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, JOBS_TOPIC)

# Request models
class ScanUrlRequest(BaseModel):
    scan_id: str = Field(..., description="Unique identifier for this scan")
    url: str = Field(..., alias="source_url", description="Target URL to scan")
    priority: int = Field(default=1, ge=1, le=10, description="Priority (1=highest, 10=lowest)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional scan context")
    
    class Config:
        populate_by_name = True
        schema_extra = {
            "example": {
                "scan_id": "scan-123",
                "url": "https://api.example.com",
                "priority": 1,
                "metadata": {"program": "example-corp", "campaign": "api-audit"}
            }
        }

# API endpoints
@app.get("/")
def root():
    return {
        "service": "scan-dispatcher", 
        "version": "2.0.0",
        "status": "healthy"
    }

@app.get("/health")
@app.get("/healthz")
def health():
    return {"status": "healthy", "jobs_topic": JOBS_TOPIC}

@app.post("/scan/url")
def dispatch_url_scan(request: ScanUrlRequest):
    """Dispatch a single URL scan to the processing queue."""
    try:
        job_payload = {
            "scan_id": request.scan_id,
            "url": request.url,
            "priority": request.priority,
            "metadata": request.metadata,
            "dispatched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        
        message_data = json.dumps(job_payload, ensure_ascii=False).encode("utf-8")
        future = publisher.publish(topic_path, data=message_data)
        message_id = future.result(timeout=10)
        
        log.info(f"Dispatched scan_id={request.scan_id}, url={request.url}, msg_id={message_id}")
        
        return {
            "success": True,
            "scan_id": request.scan_id,
            "message_id": message_id,
            "status": "queued"
        }
        
    except Exception as e:
        log.error(f"Failed to dispatch scan_id={request.scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Dispatch failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)

