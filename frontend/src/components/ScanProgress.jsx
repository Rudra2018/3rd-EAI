import React from "react";

const STEPS = [
  { key: "initializing", label: "Initializing" },
  { key: "Analysis", label: "Analysis" },
  { key: "AI TestGen", label: "AI TestGen" },
  { key: "Parsing", label: "Parsing" },
  { key: "Standard", label: "Standard Tests" },
  { key: "Agentic", label: "Beast Mode" },
  { key: "AI Exec", label: "AI Exec" },
  { key: "Verify", label: "Verification" },
  { key: "Report", label: "Report" },
  { key: "completed", label: "Completed" },
];

const indexFor = (phase) =>
  Math.max(0, STEPS.findIndex((s) => s.key.toLowerCase() === String(phase || "").toLowerCase()));

export default function ScanProgress({ phase, progress }) {
  const activeIdx = indexFor(phase);
  const pct = Math.max(0, Math.min(100, Number(progress || 0)));

  return (
    <div>
      <div className="progress-head">
        <div>
          Phase: <span className="phase">{STEPS[activeIdx]?.label || "…"}</span>
        </div>
        <div>{pct}%</div>
      </div>

      <div className="progress-wrap">
        <div className="progress-bar" style={{ width: `${pct}%` }} />
      </div>

      <div className="stepper">
        {STEPS.map((s, i) => (
          <div key={s.key} className={`step ${i <= activeIdx ? "active" : ""}`} title={s.label} />
        ))}
      </div>
    </div>
  );
}

