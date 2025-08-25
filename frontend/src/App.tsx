// src/App.tsx
import { useMemo, useRef, useState } from "react";
import { aiFix, scan, scanReport, loadInScope, scanUrl, scanUrlReport, API_BASE as DEFAULT_API_BASE } from "./api";
import "./index.css";

const SAMPLE_COLLECTION_PLACEHOLDER = `{
  "collection": {
    "info": {
      "name": "My Collection",
      "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    },
    "item": [
      {
        "name": "Example",
        "request": {
          "method": "GET",
          "header": [
            { "key": "X-APP-TOKEN", "value": "***REDACTED***" }
          ],
          "url": { "raw": "http://example.com/v1/health" }
        }
      }
    ]
  }
}`;

type Summary = { High: number; Medium: number; Low: number; Info: number };

export default function App() {
  const [apiBase, setApiBase] = useState<string>(DEFAULT_API_BASE);
  const [handles, setHandles] = useState<string>("");
  const [provider, setProvider] = useState<"openai" | "gemini" | "none">("none");
  const [redact, setRedact] = useState<boolean>(true);

  const [rawText, setRawText] = useState<string>("");
  const [parsed, setParsed] = useState<any | null>(null);
  const [fixed, setFixed] = useState<any | null>(null);
  const [report, setReport] = useState<string>("");

  const [summary, setSummary] = useState<Summary | null>(null);
  const [inScope, setInScope] = useState<string[]>([]);
  const [loading, setLoading] = useState<string>("");

  // URL scanner state
  const [urlToScan, setUrlToScan] = useState<string>("");
  const [urlDepth, setUrlDepth] = useState<number>(3);
  const [urlSameHost, setUrlSameHost] = useState<boolean>(true);
  const [urlUseML, setUrlUseML] = useState<boolean>(true);
  const [urlReport, setUrlReport] = useState<string>("");
  const [urlSummary, setUrlSummary] = useState<Summary | null>(null);

  const fileRef = useRef<HTMLInputElement>(null);

  const canScan = useMemo(() => Boolean(parsed || rawText.trim()), [parsed, rawText]);

  function download(filename: string, content: string) {
    const blob = new Blob([content], { type: "application/json;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function parseLocal() {
    try {
      const obj = JSON.parse(rawText);
      setParsed(obj);
      setFixed(null);
      setReport("");
      setSummary(null);
      setInScope([]);
    } catch (e: any) {
      alert(`Invalid JSON: ${e?.message ?? e}`);
    }
  }

  async function onFix() {
    try {
      setLoading("Fixing with AI…");
      const body = parsed ? parsed : JSON.parse(rawText);
      const res = await aiFix(body, provider, redact);
      setFixed(res);
    } catch (e: any) {
      alert(e?.message ?? String(e));
    } finally {
      setLoading("");
    }
  }

  async function onScan() {
    try {
      setLoading("Scanning collection…");
      const body = (fixed ?? parsed) ? (fixed ?? parsed) : JSON.parse(rawText);
      const res = await scan(body, handles);
      setSummary(res.summary);
      setInScope(res.in_scope_assets ?? []);
    } catch (e: any) {
      alert(e?.message ?? String(e));
    } finally {
      setLoading("");
    }
  }

  async function onReport() {
    try {
      setLoading("Generating report…");
      const body = (fixed ?? parsed) ? (fixed ?? parsed) : JSON.parse(rawText);
      const md = await scanReport(body, handles);
      setReport(md);
    } catch (e: any) {
      alert(e?.message ?? String(e));
    } finally {
      setLoading("");
    }
  }

  async function onLoadInScope() {
    try {
      setLoading("Loading in-scope…");
      const res = await loadInScope(handles);
      alert(`Loaded handles: ${res.handles?.join(", ") || "(none)"}`);
    } catch (e: any) {
      alert(e?.message ?? String(e));
    } finally {
      setLoading("");
    }
  }

  // URL scan handlers
  async function onScanUrl() {
    try {
      setLoading("Scanning URL…");
      const res = await scanUrl(urlToScan, urlDepth, urlSameHost, urlUseML);
      setUrlSummary(res.summary);
      // Also dump a quick markdown in the report panel for convenience
      const md = await scanUrlReport(urlToScan, urlDepth, urlSameHost, urlUseML);
      setUrlReport(md);
    } catch (e: any) {
      alert(e?.message ?? String(e));
    } finally {
      setLoading("");
    }
  }

  async function onUrlReportOnly() {
    try {
      setLoading("Generating URL report…");
      const md = await scanUrlReport(urlToScan, urlDepth, urlSameHost, urlUseML);
      setUrlReport(md);
    } catch (e: any) {
      alert(e?.message ?? String(e));
    } finally {
      setLoading("");
    }
  }

  function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      setRawText(String(reader.result ?? ""));
      setParsed(null);
      setFixed(null);
      setReport("");
      setSummary(null);
      setInScope([]);
    };
    reader.readAsText(f);
    e.currentTarget.value = "";
  }

  // Clear helpers
  function clearOriginal() {
    setRawText("");
    setParsed(null);
  }
  function clearFixed() {
    setFixed(null);
  }
  function clearReport() {
    setReport("");
  }
  function clearSummary() {
    setSummary(null);
  }
  function clearInScope() {
    setInScope([]);
  }
  function clearUrlPanel() {
    setUrlReport("");
    setUrlSummary(null);
    setUrlToScan("");
  }

  return (
    <div className="app">
      <header className="app__header">
        <div className="brand">
          <span className="badge">Rudra’s Third Eye</span>
          <h1>API Scanner</h1>
        </div>

        <div className="toolbar">
          <div className="field">
            <label>Scanner Base URL</label>
            <input
              value={apiBase}
              onChange={(e) => setApiBase(e.target.value)}
              placeholder="http://127.0.0.1:8000"
            />
            <small>Current: {apiBase}</small>
          </div>

          <div className="field">
            <label>Bug bounty handles (comma-separated)</label>
            <input
              value={handles}
              onChange={(e) => setHandles(e.target.value)}
              placeholder="hackerone_handle,intigriti_handle"
            />
            <small>Sanitized: {handles.replace(/[^a-z0-9_,]/gi, "_") || "—"}</small>
          </div>

          <div className="field">
            <label>AI Provider</label>
            <select value={provider} onChange={(e) => setProvider(e.target.value as any)}>
              <option value="none">None</option>
              <option value="openai">OpenAI</option>
              <option value="gemini">Gemini</option>
            </select>
            <label className="checkbox">
              <input type="checkbox" checked={redact} onChange={(e) => setRedact(e.target.checked)} />
              Redact secrets before sending
            </label>
          </div>
        </div>
      </header>

      <main className="grid">
        {/* URL Scanner Panel */}
        <section className="card col-span-2">
          <div className="card__header">
            <h2>URL Scanner (AI/ML-assisted)</h2>
            <div className="actions">
              <button className="btn btn--outline btn--mini" onClick={clearUrlPanel}>Clear</button>
            </div>
          </div>

          <div className="urlgrid">
            <div className="field">
              <label>URL to scan</label>
              <input
                value={urlToScan}
                onChange={(e) => setUrlToScan(e.target.value)}
                placeholder="https://example.com"
              />
              <small>Includes light crawl and model-based checks.</small>
            </div>

            <div className="field">
              <label>Max pages</label>
              <input
                type="number"
                min={1}
                max={20}
                value={urlDepth}
                onChange={(e) => setUrlDepth(parseInt(e.target.value || "1", 10))}
              />
              <label className="checkbox">
                <input type="checkbox" checked={urlSameHost} onChange={(e) => setUrlSameHost(e.target.checked)} />
                Same host only
              </label>
              <label className="checkbox">
                <input type="checkbox" checked={urlUseML} onChange={(e) => setUrlUseML(e.target.checked)} />
                Use heavy ML (if available)
              </label>
            </div>

            <div className="field">
              <label>Actions</label>
              <div className="row">
                <button className="btn btn--primary" onClick={onScanUrl} disabled={!urlToScan}>Scan URL</button>
                <button className="btn btn--outline" onClick={onUrlReportOnly} disabled={!urlToScan}>Report</button>
                {loading && <span className="loading">{loading}</span>}
              </div>
            </div>
          </div>

          <div className="row">
            <div className="chipbox">
              <span className="chip chip--high">High {urlSummary?.High ?? 0}</span>
              <span className="chip chip--med">Medium {urlSummary?.Medium ?? 0}</span>
              <span className="chip chip--low">Low {urlSummary?.Low ?? 0}</span>
              <span className="chip chip--info">Info {urlSummary?.Info ?? 0}</span>
            </div>
          </div>

          <textarea className="markdown" readOnly value={urlReport || "—"} />
        </section>

        {/* Postman Collection Panel */}
        <section className="card col-span-2">
          <div className="card__header">
            <h2>Paste Postman collection JSON</h2>
            <div className="actions">
              <button className="btn btn--outline btn--mini" onClick={clearOriginal}>Clear</button>
              <button className="btn" onClick={parseLocal}>Parse (local)</button>
              <button className="btn" onClick={() => fileRef.current?.click()}>Upload JSON</button>
              <input ref={fileRef} type="file" accept="application/json" style={{ display: "none" }} onChange={onFileChange} />
            </div>
          </div>

          <textarea
            className="editor"
            rows={16}
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder={SAMPLE_COLLECTION_PLACEHOLDER}
          />

          <div className="spacer" />

          <div className="row">
            <button className="btn btn--accent" disabled={!canScan} onClick={onFix}>Fix with AI</button>
            <button className="btn" onClick={onLoadInScope}>Load In-Scope</button>
            <button className="btn btn--primary" disabled={!canScan} onClick={onScan}>Scan</button>
            <button className="btn btn--outline" disabled={!canScan} onClick={onReport}>Report</button>
            {loading && <span className="loading">{loading}</span>}
          </div>
        </section>

        <section className="card">
          <div className="card__header">
            <h2>Original (parsed)</h2>
            <div className="actions">
              <button className="btn btn--outline btn--mini" onClick={clearOriginal}>Clear</button>
            </div>
          </div>
          <textarea className="viewer" readOnly value={parsed ? JSON.stringify(parsed, null, 2) : "—"} />
        </section>

        <section className="card">
          <div className="card__header">
            <h2>Fixed (AI)</h2>
            <div className="actions">
              {!!fixed && (
                <button
                  className="btn btn--mini"
                  onClick={() => download("fixed_postman_collection.json", JSON.stringify(fixed, null, 2))}
                >
                  Download
                </button>
              )}
              <button className="btn btn--outline btn--mini" onClick={clearFixed}>Clear</button>
            </div>
          </div>
          <textarea className="viewer" readOnly value={fixed ? JSON.stringify(fixed, null, 2) : "—"} />
        </section>

        <section className="card col-span-2">
          <div className="card__header">
            <h2>Report</h2>
            <div className="actions">
              <button className="btn btn--outline btn--mini" onClick={clearReport}>Clear</button>
            </div>
          </div>
          <textarea className="markdown" readOnly value={report || "—"} />
        </section>

        <section className="card">
          <div className="card__header">
            <h2>Summary</h2>
            <div className="actions">
              <button className="btn btn--outline btn--mini" onClick={clearSummary}>Clear</button>
            </div>
          </div>
          <div className="summary">
            {summary ? (
              <>
                <span className="chip chip--high">High {summary.High ?? 0}</span>
                <span className="chip chip--med">Medium {summary.Medium ?? 0}</span>
                <span className="chip chip--low">Low {summary.Low ?? 0}</span>
                <span className="chip chip--info">Info {summary.Info ?? 0}</span>
              </>
            ) : (
              <span>—</span>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card__header">
            <h2>In-Scope Assets</h2>
            <div className="actions">
              <button className="btn btn--outline btn--mini" onClick={clearInScope}>Clear</button>
            </div>
          </div>
          <ul className="list">
            {inScope.length ? inScope.map(h => <li key={h}><code>{h}</code></li>) : <li>—</li>}
          </ul>
        </section>
      </main>

      <footer className="footer">
        <small>Base URL: <code>{apiBase}</code></small>
      </footer>
    </div>
  );
}

