import React from "react";
import ScanDashboard from "./components/ScanDashboard";

export default function App() {
  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <div className="brand-dot">R</div>
          <div>
            <div className="header-title">Rudra’s Third Eye (AI)</div>
            <div className="header-sub">Halodoc-style Security Dashboard</div>
          </div>
        </header>
        <ScanDashboard />
      </div>
    </div>
  );
}

