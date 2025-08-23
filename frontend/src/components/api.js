const BASE = ""; // same origin; Vite dev proxy will forward to Flask

function withTimeout(promise, ms=15000, controller){
  const t = setTimeout(() => controller.abort(), ms);
  return promise.finally(() => clearTimeout(t));
}

export async function apiGet(path, params={}){
  const url = new URL(path, window.location.origin);
  Object.entries(params).forEach(([k,v]) => v!=null && url.searchParams.set(k, v));
  const controller = new AbortController();
  const res = await withTimeout(fetch(url, { signal: controller.signal }), 15000, controller);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export async function apiPost(path, body){
  const controller = new AbortController();
  const res = await withTimeout(fetch(path, {
    method: "POST",
    headers: { "Content-Type":"application/json" },
    body: JSON.stringify(body || {}),
    signal: controller.signal
  }), 20000, controller);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

// Specific helpers (server-side pagination)
export const getStatus   = () => apiGet("/api/scan/status");
export const getFindings = ({page=1, page_size=50, q="", severity=""}={}) =>
  apiGet("/api/findings", { page, page_size, q, severity });
export const getPrograms = ({page=1, page_size=50, q=""}={}) =>
  apiGet("/api/bug-bounty/programs", { page, page_size, q });
export const startScan   = (payload) => apiPost("/api/scan/start", payload);
export const authStatus  = () => apiGet("/api/auth/status");
export const authConfig  = (cfg) => apiPost("/api/auth/config", cfg);

