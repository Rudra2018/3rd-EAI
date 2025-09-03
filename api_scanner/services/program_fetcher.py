import json
import logging
import os
import time
import uuid
import asyncio
from typing import Any, Dict, List

import requests
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# Import enhanced program sources
try:
    from api_scanner.services.program_sources import ProgramAggregator
    SOURCES_AVAILABLE = True
except ImportError:
    SOURCES_AVAILABLE = False
    logging.warning("Program sources not available")

# Logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [program-fetcher] %(message)s",
)
log = logging.getLogger("program-fetcher")

app = FastAPI(title="Enhanced Program Fetcher", version="2.0.0")

# Configuration
DISPATCHER_URL = os.getenv("DISPATCHER_URL", "").rstrip("/")
MAX_URLS_PER_SYNC = int(os.getenv("MAX_URLS_PER_SYNC", "50"))
MAX_PROGRAMS_TO_PROCESS = int(os.getenv("MAX_PROGRAMS_TO_PROCESS", "100"))

# Request/Response models
class SyncRequest(BaseModel):
    mode: str = Field(default="aggregate", description="Sync mode: 'aggregate', 'manual', or 'chaos'")
    manual_urls: List[str] = Field(default_factory=list, description="Manual URLs for manual mode")
    max_urls: int = Field(default=25, ge=1, le=100, description="Maximum URLs to process")
    priority: int = Field(default=5, ge=1, le=10, description="Priority (1=highest, 10=lowest)")
    metadata: Dict[str, Any] = Field(default_factory=lambda: {"campaign": "enhanced_automated"}, description="Additional metadata")
    sources: List[str] = Field(default_factory=list, description="Specific sources to use (optional)")

class SyncResult(BaseModel):
    timestamp: str
    mode: str
    sources_used: List[str]
    programs_discovered: int
    urls_discovered: int
    urls_queued: int
    private_programs: int
    chaos_discoveries: int
    errors: List[str]
    sample_urls: List[str]
    source_breakdown: Dict[str, int]

# Helper functions
def normalize_url(url: str) -> str:
    """Normalize URL format."""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url

def dispatch_to_scanner(targets: List[Dict[str, Any]], priority: int, base_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Send targets to scan-dispatcher with enhanced metadata."""
    if not DISPATCHER_URL:
        return {"dispatched": 0, "errors": ["DISPATCHER_URL not configured"]}
    
    dispatched = 0
    errors = []
    
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    
    for target in targets:
        try:
            url = target.get("url", "")
            if not url:
                continue
                
            # Enhanced metadata with target information
            enhanced_metadata = {
                **base_metadata,
                "program": target.get("program", "unknown"),
                "source": target.get("source", "unknown"),
                "original_scope": target.get("original_scope", ""),
                "discovery_method": "program_sources_v2",
                "dispatched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            
            payload = {
                "scan_id": f"prog-{int(time.time())}-{uuid.uuid4().hex[:8]}",
                "url": url,
                "priority": priority,
                "metadata": enhanced_metadata
            }
            
            response = session.post(
                f"{DISPATCHER_URL}/scan/url",
                json=payload,
                timeout=15
            )
            response.raise_for_status()
            dispatched += 1
            log.debug(f"Dispatched {url} from {target.get('program', 'unknown')}")
            
        except Exception as e:
            error_msg = f"Failed to dispatch {url}: {str(e)}"
            errors.append(error_msg)
            log.warning(error_msg)
    
    session.close()
    return {"dispatched": dispatched, "errors": errors}

async def fetch_from_enhanced_sources(sources_filter: List[str] = None) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Fetch from enhanced program sources with detailed statistics."""
    if not SOURCES_AVAILABLE:
        log.warning("Enhanced program sources not available, using fallback")
        fallback_targets = [
            {"url": "https://api.github.com", "program": "GitHub", "source": "fallback"},
            {"url": "https://jsonplaceholder.typicode.com/posts/1", "program": "JSONPlaceholder", "source": "fallback"},
            {"url": "https://httpbin.org/get", "program": "HTTPBin", "source": "fallback"}
        ]
        return {"programs": 0, "sources_used": ["fallback"], "breakdown": {"fallback": 3}}, fallback_targets
    
    try:
        aggregator = ProgramAggregator()
        
        # Fetch all programs
        log.info("Fetching programs from enhanced sources...")
        programs = await aggregator.get_all_programs()
        
        # Filter by sources if specified
        if sources_filter:
            original_count = len(programs)
            programs = [p for p in programs if p.get("source") in sources_filter]
            log.info(f"Filtered programs from {original_count} to {len(programs)} based on sources: {sources_filter}")
        
        # Extract API targets with metadata
        targets = aggregator.extract_api_endpoints(programs, max_per_program=5)
        
        # Calculate statistics
        source_breakdown = {}
        sources_used = set()
        private_programs = 0
        chaos_discoveries = 0
        
        for program in programs:
            source = program.get("source", "unknown")
            sources_used.add(source)
            source_breakdown[source] = source_breakdown.get(source, 0) + 1
            
            if "private" in source:
                private_programs += 1
            elif source == "chaos":
                chaos_discoveries += 1
        
        stats = {
            "programs": len(programs),
            "sources_used": list(sources_used),
            "breakdown": source_breakdown,
            "private_programs": private_programs,
            "chaos_discoveries": chaos_discoveries
        }
        
        log.info(f"Enhanced discovery: {len(programs)} programs, {len(targets)} API targets")
        log.info(f"Sources used: {', '.join(sources_used)}")
        
        return stats, targets
        
    except Exception as e:
        log.error(f"Enhanced program fetching failed: {e}")
        fallback_targets = [
            {"url": "https://api.github.com", "program": "GitHub", "source": "fallback"}
        ]
        return {"programs": 0, "sources_used": ["fallback"], "breakdown": {"fallback": 1}}, fallback_targets

# API endpoints
@app.get("/")
def root():
    return {
        "service": "enhanced-program-fetcher",
        "version": "2.0.0", 
        "status": "healthy",
        "features": {
            "sources_available": SOURCES_AVAILABLE,
            "private_hackerone": bool(os.getenv("HACKERONE_USERNAME") and os.getenv("HACKERONE_API_TOKEN")),
            "chaos_integration": bool(os.getenv("CHAOS_API_TOKEN")),
            "dispatcher_configured": bool(DISPATCHER_URL)
        }
    }

@app.get("/health")
@app.get("/healthz")  
def health():
    return {
        "status": "healthy",
        "dispatcher_url": DISPATCHER_URL or "not_configured",
        "max_urls": MAX_URLS_PER_SYNC,
        "sources": "enhanced" if SOURCES_AVAILABLE else "fallback_only",
        "integrations": {
            "hackerone_private": bool(os.getenv("HACKERONE_USERNAME")),
            "chaos_api": bool(os.getenv("CHAOS_API_TOKEN")),
        }
    }

@app.get("/sources")
def list_sources():
    """List available program sources and their status."""
    sources_status = {
        "hackerone_public": "available",
        "bugcrowd": "available", 
        "intigriti": "available",
        "yeswehack": "available",
        "testing_endpoints": "available",
        "hackerone_private": "available" if os.getenv("HACKERONE_USERNAME") else "missing_credentials",
        "chaos": "available" if os.getenv("CHAOS_API_TOKEN") else "missing_token"
    }
    
    return {
        "sources": sources_status,
        "credentials_required": {
            "hackerone_private": ["HACKERONE_USERNAME", "HACKERONE_API_TOKEN"],
            "chaos": ["CHAOS_API_TOKEN"]
        }
    }

@app.post("/sync", response_model=SyncResult, status_code=status.HTTP_202_ACCEPTED)
async def sync_programs(request: SyncRequest):
    """Enhanced sync with multiple program sources and private API integration."""
    start_time = time.time()
    
    try:
        targets = []
        stats = {"programs": 0, "sources_used": [], "breakdown": {}, "private_programs": 0, "chaos_discoveries": 0}
        
        if request.mode == "manual" and request.manual_urls:
            # Manual mode - use provided URLs
            for url in request.manual_urls:
                normalized = normalize_url(url)
                if normalized:
                    targets.append({
                        "url": normalized,
                        "program": "Manual Entry",
                        "source": "manual"
                    })
            stats = {"programs": 0, "sources_used": ["manual"], "breakdown": {"manual": len(targets)}, "private_programs": 0, "chaos_discoveries": 0}
            log.info(f"Manual mode: processing {len(targets)} provided URLs")
            
        elif request.mode in ["aggregate", "chaos"]:
            # Enhanced mode - fetch from all available sources
            stats, targets = await fetch_from_enhanced_sources(request.sources)
            log.info(f"Enhanced mode: discovered {stats['programs']} programs, {len(targets)} API targets")
            
        else:
            # Fallback 
            targets = [{"url": "https://api.github.com", "program": "GitHub", "source": "fallback"}]
            stats = {"programs": 1, "sources_used": ["fallback"], "breakdown": {"fallback": 1}, "private_programs": 0, "chaos_discoveries": 0}
        
        # Limit targets to max_urls
        original_count = len(targets)
        targets = targets[:request.max_urls]
        if len(targets) < original_count:
            log.info(f"Limited targets from {original_count} to {len(targets)}")
        
        # Dispatch to scanner
        dispatched_count = 0
        errors = []
        
        if targets and DISPATCHER_URL:
            log.info(f"Dispatching {len(targets)} targets to scanner")
            dispatch_result = dispatch_to_scanner(targets, request.priority, request.metadata)
            dispatched_count = dispatch_result["dispatched"]
            errors = dispatch_result["errors"]
        else:
            errors = ["No targets to dispatch or DISPATCHER_URL not configured"]
        
        elapsed = time.time() - start_time
        log.info("Enhanced sync completed in %.2fs: %d programs, %d targets, %d dispatched",
                elapsed, stats["programs"], len(targets), dispatched_count)
        
        return SyncResult(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            mode=request.mode,
            sources_used=stats["sources_used"],
            programs_discovered=stats["programs"],
            urls_discovered=len(targets),
            urls_queued=dispatched_count,
            private_programs=stats["private_programs"],
            chaos_discoveries=stats["chaos_discoveries"],
            errors=errors[:10],  # Limit errors shown
            sample_urls=[t["url"] for t in targets[:5]],  # Show sample URLs
            source_breakdown=stats["breakdown"]
        )
        
    except Exception as e:
        log.exception(f"Enhanced sync operation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enhanced sync failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)

