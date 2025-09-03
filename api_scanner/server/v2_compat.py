# api_scanner/server/v2_compat.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
import httpx
import os

router = APIRouter(tags=["compat-v2"])

INTERNAL_BASE = os.environ.get("INTERNAL_BASE", "http://127.0.0.1:9000")

class UrlImportBody(BaseModel):
    url: HttpUrl
    max_pages: int | None = 3
    same_host_only: bool | None = True
    use_heavy_ml: bool | None = True

@router.post("/import/url")
async def import_url(body: UrlImportBody):
    """
    Legacy UI posts to /v2/import/url. We immediately call your real /scan/url.
    If your UI expects a two-step flow, you can return a scan_id and store state.
    """
    data = {
        "url": str(body.url),
        "max_pages": body.max_pages if body.max_pages is not None else 3,
        "same_host_only": True if body.same_host_only is None else body.same_host_only,
        "use_heavy_ml": True if body.use_heavy_ml is None else body.use_heavy_ml,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post(f"{INTERNAL_BASE}/scan/url", json=data)
        if r.status_code >= 400:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

# Optional stubs if your UI hits them; wire as needed later:
@router.post("/scans/start")
async def start_scan_stub():
    return {"status": "ok", "note": "mapped to /scan/url already via import/url"}

@router.post("/import/postman")
async def import_postman_stub():
    return {"status": "todo", "note": "map to /scan/postman if needed"}

@router.post("/import/openapi")
async def import_openapi_stub():
    return {"status": "todo", "note": "map to /scan/report or dedicated OAS route"}

