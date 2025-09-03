const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:9000';

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, options);
  if (!res.ok) {
    throw new Error(`API call to ${path} failed: ${res.statusText}`);
  }
  return res.json();
}

export const scanUrl = (body: {
  url: string;
  max_pages?: number;
  same_host_only?: boolean;
  use_heavy_ml?: boolean;
}) => apiFetch(`/scan/url`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body)
});

export const scanPostman = (collection: any, handles?: string[]) =>
  apiFetch(`/scan/postman`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ collection, handles })
  });

export const scanReport = (collection: any, handles?: string[], format: "markdown" | "json" = "markdown") =>
  apiFetch(`/scan/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ collection, handles, format })
  });

export const aiFixPostman = (collection: any, provider: "none" | "openai" | "gemini" = "none", redact_secrets = true) =>
  apiFetch(`/ai/fix_postman`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ collection, provider, redact_secrets })
  });
