// src/api.ts
export const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";

export async function aiFix(collection: object | string, provider: "openai" | "gemini" | "none" = "none", redact = true) {
  const r = await fetch(`${API_BASE}/ai/fix_postman`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ collection, provider, redact_secrets: redact }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function scan(collection: object | string, handlesCsv = "") {
  const handles = handlesCsv.split(",").map(s => s.trim()).filter(Boolean);
  const r = await fetch(`${API_BASE}/scan/postman`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ collection, handles }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function scanReport(collection: object | string, handlesCsv = ""): Promise<string> {
  const handles = handlesCsv.split(",").map(s => s.trim()).filter(Boolean);
  const r = await fetch(`${API_BASE}/scan/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ collection, handles, format: "markdown" }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.text();
}

export async function loadInScope(handlesCsv = "") {
  const r = await fetch(`${API_BASE}/hackerone/inscope?handles=${encodeURIComponent(handlesCsv)}`);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// URL scan
export async function scanUrl(url: string, max_pages = 3, same_host_only = true, use_heavy_ml = true) {
  const r = await fetch(`${API_BASE}/scan/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, max_pages, same_host_only, use_heavy_ml }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export async function scanUrlReport(url: string, max_pages = 3, same_host_only = true, use_heavy_ml = true): Promise<string> {
  const r = await fetch(`${API_BASE}/scan/url_report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, max_pages, same_host_only, use_heavy_ml }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.text();
}

