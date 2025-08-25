
# Minimal Vertex AI Pipelines (KFP v2) wrapper to run the containerized scanner.
# Build image first, then use this pipeline to run "bugbounty-run" daily.
from kfp import dsl

@dsl.container_component
def run_scanner(image: str, args: list[str] = []):
    return dsl.ContainerSpec(
        image=image,
        command=["api-scan"],
        args=args,
    )

@dsl.pipeline(name="api-scanner-bugbounty-pipeline")
def pipeline(image: str = "us-central1-docker.pkg.dev/YOUR-PROJECT/scan/api-scanner:latest",
             targets_gcs_path: str = "gs://YOUR_BUCKET/targets.txt"):
    # Download targets to /workspace/targets.txt and run
    step = run_scanner(image=image, args=["bugbounty-run", "/workspace/targets.txt"])
