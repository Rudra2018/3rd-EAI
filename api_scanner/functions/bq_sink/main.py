# api_scanner/functions/bq_sink/main.py
import base64
import json
import os
import logging
from typing import Dict

import functions_framework
from cloudevents.http import CloudEvent
from google.cloud import bigquery
from google.api_core.exceptions import NotFound, Forbidden
from datetime import datetime, timezone

# Configuration
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT")
BQ_DATASET = os.getenv("BQ_DATASET", "vuln_data")
BQ_TABLE = os.getenv("BQ_TABLE", "findings")

# Initialize BigQuery client
bq_client = bigquery.Client()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _ensure_dataset():
    """Create dataset if it doesn't exist."""
    dataset_ref = bq_client.dataset(BQ_DATASET)
    try:
        bq_client.get_dataset(dataset_ref)
        logger.info(f"Dataset {BQ_DATASET} exists.")
    except NotFound:
        dataset = bigquery.Dataset(dataset_ref)
        dataset.location = "US"
        bq_client.create_dataset(dataset)
        logger.info(f"Dataset {BQ_DATASET} created.")

def _ensure_table():
    """Create table with proper schema if it doesn't exist."""
    table_ref = bq_client.dataset(BQ_DATASET).table(BQ_TABLE)
    try:
        bq_client.get_table(table_ref)
        logger.info(f"Table {BQ_TABLE} exists.")
    except NotFound:
        schema = [
            bigquery.SchemaField("scan_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("program", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("scope_url", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("analysis_title", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("analysis_severity", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("vrt_category", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("confidence", "FLOAT", mode="NULLABLE"),
            bigquery.SchemaField("recommended_fix", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("evidence", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("raw_event", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("inserted_at", "TIMESTAMP", mode="REQUIRED")
        ]
        table = bigquery.Table(table_ref, schema=schema)
        bq_client.create_table(table)
        logger.info(f"Table {BQ_TABLE} created with proper schema.")

# Initialize dataset and table on startup
try:
    _ensure_dataset()
    _ensure_table()
except Exception as e:
    logger.error(f"Failed to initialize BigQuery resources: {e}")

@functions_framework.cloud_event
def bq_sink_handler(cloud_event: CloudEvent) -> None:
    """
    Cloud Function to store vulnerability findings in BigQuery.
    Triggered by Pub/Sub messages from scan-worker.
    """
    logger.info("Processing vulnerability finding for BigQuery storage.")

    try:
        # Validate CloudEvent structure
        if not cloud_event.data or "message" not in cloud_event.data:
            logger.warning("No message data in CloudEvent.")
            return

        message = cloud_event.data["message"]
        if "data" not in message:
            logger.warning("No data in message.")
            return

        # Decode the finding from base64
        raw_data = base64.b64decode(message["data"]).decode("utf-8")
        finding = json.loads(raw_data)

        # Validate required fields
        required_fields = ["scan_id", "program", "scope_url", "analysis_title", "analysis_severity"]
        missing = [field for field in required_fields if not finding.get(field)]
        if missing:
            logger.error(f"Missing required fields: {missing}")
            return

        # Handle timestamps safely - FIXED: Convert to ISO strings
        now = datetime.now(timezone.utc)
        
        # Parse created_at timestamp if provided
        created_at_str = finding.get("created_at")
        if created_at_str:
            try:
                created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            except Exception as e:
                logger.warning(f"Failed to parse created_at '{created_at_str}': {e}")
                created_at = now
        else:
            created_at = now

        # CRITICAL FIX: Convert datetime objects to ISO format strings for JSON serialization
        row = {
            "scan_id": finding.get("scan_id"),
            "program": finding.get("program"),
            "scope_url": finding.get("scope_url"),
            "analysis_title": finding.get("analysis_title"),
            "analysis_severity": finding.get("analysis_severity"),
            "vrt_category": finding.get("vrt_category"),
            "confidence": finding.get("confidence"),
            "recommended_fix": finding.get("recommended_fix"),
            "evidence": finding.get("evidence"),
            "raw_event": json.dumps(finding),
            "created_at": created_at.isoformat(),  # Convert datetime to ISO string
            "inserted_at": now.isoformat()         # Convert datetime to ISO string
        }

        # Insert into BigQuery
        table_id = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}"
        errors = bq_client.insert_rows_json(table_id, [row])

        if errors:
            logger.error(f"BigQuery insert errors: {errors}")
            raise RuntimeError(f"Failed to insert into BigQuery: {errors}")

        logger.info(f"✅ Successfully inserted finding: scan_id={row['scan_id']}, "
                   f"title={finding.get('analysis_title')}, severity={finding.get('analysis_severity')}")

    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON message: {e}")
    except Forbidden as e:
        logger.error(f"Permission denied for BigQuery operation: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in bq_sink_handler: {e}")
        raise

