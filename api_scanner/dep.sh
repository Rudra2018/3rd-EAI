#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-mobile-new-pip}"
REGION="${REGION:-us-central1}"
REPO="${REPO:-containers}"

# ---- images ----
PF_IMAGE="us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO}/program-fetcher:latest"
SW_IMAGE="us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO}/scan-worker:latest"

# ---- service accounts ----
PUBSUB_SA="pubsub-pusher@${PROJECT_ID}.iam.gserviceaccount.com"
SCANNER_SA="scanner-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# ---- pubsub topics/subscription ----
TOPIC_SCAN="scan-requests"
TOPIC_CURATED="findings.curated"
TOPIC_RAW="findings.raw"
SUB_WORKER="scan-worker-push"

# ---- create repo (idempotent) ----
gcloud artifacts repositories create "${REPO}" \
  --repository-format=docker \
  --location="${REGION}" \
  --description="API scanner containers" \
  --project="${PROJECT_ID}" || true

# ---- build with docker (explicit, avoids buildpacks guessing) ----
# program-fetcher
gcloud builds submit --project "${PROJECT_ID}" --tag "${PF_IMAGE}" \
  --gcs-log-dir="gs://${PROJECT_ID}_cloudbuild/logs" \
  --gcs-source-staging-dir="gs://${PROJECT_ID}_cloudbuild/source" \
  --substitutions=_SERVICE=program-fetcher

# scan-worker
gcloud builds submit --project "${PROJECT_ID}" --tag "${SW_IMAGE}" \
  --gcs-log-dir="gs://${PROJECT_ID}_cloudbuild/logs" \
  --gcs-source-staging-dir="gs://${PROJECT_ID}_cloudbuild/source" \
  --substitutions=_SERVICE=scan-worker

# ---- service accounts (idempotent) ----
gcloud iam service-accounts create pubsub-pusher --project "${PROJECT_ID}" || true
gcloud iam service-accounts create scanner-sa    --project "${PROJECT_ID}" || true

# allow Pub/Sub SA to push OIDC tokens
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${PUBSUB_SA}" \
  --role="roles/run.invoker"

# allow scanner to publish curated findings
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SCANNER_SA}" \
  --role="roles/pubsub.publisher"

# ---- topics (idempotent) ----
gcloud pubsub topics create "${TOPIC_SCAN}"   --project "${PROJECT_ID}" || true
gcloud pubsub topics create "${TOPIC_CURATED}" --project "${PROJECT_ID}" || true
gcloud pubsub topics create "${TOPIC_RAW}"     --project "${PROJECT_ID}" || true

# ---- deploy scan-dispatcher (you already have one; keep if needed) ----
# gcloud run deploy scan-dispatcher \
#   --image "us-central1-docker.pkg.dev/${PROJECT_ID}/${REPO}/api-scanner:latest" \
#   --project "${PROJECT_ID}" --region "${REGION}" \
#   --allow-unauthenticated \
#   --service-account "${SCANNER_SA}" \
#   --max-instances=10

# Discover dispatcher URL (assuming service exists)
DISPATCHER_URL="$(gcloud run services describe scan-dispatcher --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)' 2>/dev/null || true)"
echo "Dispatcher URL: ${DISPATCHER_URL}"

# ---- deploy scan-worker ----
gcloud run deploy scan-worker \
  --image "${SW_IMAGE}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --service-account "${SCANNER_SA}" \
  --allow-unauthenticated \
  --max-instances=20 \
  --timeout=600 \
  --set-env-vars "TOPIC_FINDINGS_CURATED=${TOPIC_CURATED}" \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID}" \
  --set-env-vars "GCP_PROJECT=${PROJECT_ID}" \
  --set-env-vars "PYTHONUNBUFFERED=1" \
  --update-secrets "SLACK_WEBHOOK_URL=slack-webhook:latest" || {
    echo "scan-worker deploy failed; check logs:"
    exit 1
  }

WORKER_URL="$(gcloud run services describe scan-worker --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')"
echo "Worker URL: ${WORKER_URL}"

# ---- create push subscription to worker /pubsub/push (idempotent) ----
gcloud pubsub subscriptions create "${SUB_WORKER}" \
  --topic "${TOPIC_SCAN}" \
  --push-endpoint="${WORKER_URL}/pubsub/push" \
  --push-auth-service-account="${PUBSUB_SA}" \
  --push-auth-token-audience="${WORKER_URL}/pubsub/push" \
  --project "${PROJECT_ID}" || true

# ---- deploy program-fetcher (points at dispatcher) ----
gcloud run deploy program-fetcher \
  --image "${PF_IMAGE}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --allow-unauthenticated \
  --max-instances=5 \
  --timeout=600 \
  --set-env-vars "DISPATCHER_URL=${DISPATCHER_URL}" \
  --set-env-vars "ENABLED_SOURCES=chaos" \
  --update-secrets "CHAOS_API_TOKEN=chaos-api-token:latest"

echo "All set."
echo "program-fetcher: $(gcloud run services describe program-fetcher --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')"
echo "scan-worker:     ${WORKER_URL}"
echo "dispatcher:      ${DISPATCHER_URL}"

