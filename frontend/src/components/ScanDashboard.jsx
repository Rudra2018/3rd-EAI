import React, { useCallback, useEffect, useRef, useState } from "react";
import io from "socket.io-client";
import ScanProgress from "./ScanProgress";

// Prefer proxy when on Vite dev server
const API_BASE = window.location.port === "5173" ? "" : "http://localhost:4000";

export default function ScanDashboard() {
  const [phase, setPhase] = useState("initializing");
  const [progress, setProgress] = useState(0);
  const [scanId, setScanId] = useState(null);
  const [activity, setActivity] = useState(["Socket connected"]);
  const [reportLink, setReportLink] = useState(null);
  const [busy, setBusy] = useState(false);

  const [aiEnabled, setAiEnabled] = useState(true);
  const [mlEnabled, setMlEnabled] = useState(true);
  const [bugBounty, setBugBounty] = useState(true);
  const [beastMode, setBeastMode] = useState(true);
  const [targetUrl, setTargetUrl] = useState("");

  const collectionRef = useRef(null);
  const variablesRef = useRef(null);
  const pdfRef = useRef(null);

  const socketRef = useRef(null);
  const pollTimer = useRef(null);

  const log = useCallback((msg) => {
    if (!msg) return;
    setActivity((a) => [msg, ...a].slice(0, 300));
  }, []);

  // Fallback polling
  const pollScan = useCallback(async () => {
    if (!scanId) return;
    try {
      const r = await fetch(`${API_BASE}/api/scan/${scanId}`);
      if (!r.ok) return;
      const js = await r.json();
      if (typeof js.progress === "number") setProgress(js.progress);
      if (js.phase) setPhase(js.phase);
      if (js.status === "completed") {
        setBusy(false);
        setReportLink(`${API_BASE}/api/scan/${scanId}/report`);
        clearInterval(pollTimer.current);
      }
    } catch { /* silent */ }
  }, [scanId]);

  // Socket wiring
  useEffect(() => {
    const socket = io(API_BASE || undefined, { transports: ["websocket"], reconnectionAttempts: 10 });
    socketRef.current = socket;

    socket.on("connect", () => log("Socket connected"));
    socket.on("disconnect", () => log("Socket disconnected"));

    socket.on("scan_update", (payload) => {
      if (!payload) return;
      if (payload.scan_id && payload.scan_id !== scanId) setScanId(payload.scan_id);
      if (typeof payload.progress === "number") setProgress(payload.progress);
      if (payload.phase) setPhase(payload.phase);
      if (payload.message) log(payload.message);
    });

    socket.on("scan_complete", () => {
      setPhase("completed");
      setProgress(100);
      log("Scan completed.");
      setBusy(false);
      if (scanId) setReportLink(`${API_BASE}/api/scan/${scanId}/report`);
    });

    socket.on("scan_error", (payload) => {
      setPhase("completed");
      setProgress(100);
      setBusy(false);
      log(`Error: ${payload?.error || "Unknown error"}`);
    });

    return () => socket.disconnect();
  }, [log, scanId]);

  // Join room & poll fallback
  useEffect(() => {
    if (socketRef.current && scanId) {
      socketRef.current.emit("join_scan", { scan_id: scanId });
      clearInterval(pollTimer.current);
      pollTimer.current = setInterval(pollScan, 2000);
    }
    return () => clearInterval(pollTimer.current);
  }, [scanId, pollScan]);

  const startScan = useCallback(async (e) => {
    e.preventDefault();
    setBusy(true);
    setActivity([]);
    setReportLink(null);
    setPhase("initializing");
    setProgress(0);

    const form = new FormData();
    if (collectionRef.current?.files?.[0]) form.append("collection", collectionRef.current.files[0]);
    if (variablesRef.current?.files?.[0]) form.append("variables", variablesRef.current.files[0]);
    if (pdfRef.current?.files?.[0]) form.append("api_doc_pdf", pdfRef.current.files[0]);
    if (targetUrl) form.append("target_url", targetUrl);

    form.append("ai_enabled", String(aiEnabled));
    form.append("ml_enabled", String(mlEnabled));
    form.append("bug_bounty", String(bugBounty));
    form.append("beast_mode", String(beastMode));

    try {
      const res = await fetch(`${API_BASE}/api/scan/postman-ai`, { method: "POST", body: form });
      const js = await res.json();
      if (!res.ok) throw new Error(js?.error || "Failed to start scan");
      setScanId(js.scan_id);
      log(`Scan started: ${js.scan_id}`);
    } catch (err) {
      setBusy(false);
      log(`Start failed: ${err.message}`);
    }
  }, [aiEnabled, mlEnabled, bugBounty, beastMode, targetUrl, log]);

  return (
    <div className="grid">
      {/* Progress */}
      <div className="card">
        <ScanProgress phase={phase} progress={progress} />
      </div>

      {/* Controls */}
      <div className="card">
        <form onSubmit={startScan} className="grid grid-2">
          <div>
            <div className="label">Postman Collection (.json)</div>
            <input ref={collectionRef} type="file" accept=".json" className="file" />
          </div>
          <div>
            <div className="label">Postman Variables/Env (optional)</div>
            <input ref={variablesRef} type="file" accept=".json" className="file" />
          </div>
          <div>
            <div className="label">API Doc PDF (optional)</div>
            <input ref={pdfRef} type="file" accept=".pdf" className="file" />
          </div>
          <div>
            <div className="label">Target URL (optional, recon)</div>
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://api.example.com"
              className="input"
            />
          </div>

          <div className="row" style={{ gridColumn: "1 / -1" }}>
            <label className="toggle"><input type="checkbox" checked={aiEnabled} onChange={e=>setAiEnabled(e.target.checked)} />AI Enabled</label>
            <label className="toggle"><input type="checkbox" checked={mlEnabled} onChange={e=>setMlEnabled(e.target.checked)} />ML Enabled</label>
            <label className="toggle"><input type="checkbox" checked={bugBounty} onChange={e=>setBugBounty(e.target.checked)} />Bug Bounty Mode</label>
            <label className="toggle">
              <input type="checkbox" checked={beastMode} onChange={e=>setBeastMode(e.target.checked)} disabled={!bugBounty} />
              Beast Mode
            </label>
          </div>

          <div className="row" style={{ gridColumn: "1 / -1" }}>
            <button type="submit" className="btn" disabled={busy}>{busy ? "Running…" : "Start Scan"}</button>
            {reportLink && <a className="link" href={reportLink}>Download Report</a>}
          </div>
        </form>
      </div>

      {/* Activity */}
      <div className="card">
        <div className="label" style={{ marginBottom: 8 }}>Activity</div>
        <ul className="activity">
          {activity.map((line, i) => <li key={i}>• {line}</li>)}
        </ul>
      </div>
    </div>
  );
}

