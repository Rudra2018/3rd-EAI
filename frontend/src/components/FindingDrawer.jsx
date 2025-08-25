import React, { useEffect, useMemo, useState } from "react";
import {
  Box, Button, Card, CardContent, Chip, Grid, Paper,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Typography, Stack, TextField, Divider, LinearProgress
} from "@mui/material";
import PlayArrowRounded from "@mui/icons-material/PlayArrowRounded";
import RefreshRounded from "@mui/icons-material/RefreshRounded";
import BugReportRounded from "@mui/icons-material/BugReportRounded";
import FindingDrawer from "./FindingDrawer";

const stepsDefault = ["Queued", "Recon", "Scanning", "Analyzing", "Reporting"];

const sevColor = (sev) =>
  sev === "Critical" ? "error" :
  sev === "High" ? "error" :
  sev === "Medium" ? "warning" :
  sev === "Low" ? "info" : "default";

function StepDots({ steps = stepsDefault, active = 0 }) {
  return (
    <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
      {steps.map((s, i) => (
        <Chip
          key={s}
          size="small"
          variant={i === active ? "filled" : "outlined"}
          color={i <= active ? "primary" : "default"}
          label={s}
        />
      ))}
    </Stack>
  );
}

export default function ScanDashboard() {
  const [targets, setTargets] = useState(["https://example.com/api/health"]);
  const [status, setStatus] = useState({ status: "idle", progress: 0, active_step: 0, steps: stepsDefault });
  const [findings, setFindings] = useState([]);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selected, setSelected] = useState(null);

  const polling = useMemo(() => {
    let timer;
    return {
      start() {
        if (timer) return;
        timer = setInterval(async () => {
          const r = await fetch("/api/scan/status").catch(() => null);
          if (r && r.ok) {
            const d = await r.json();
            setStatus(d);
            if (d.status === "done" || d.status === "error") {
              this.stop();
              const fr = await fetch("/api/findings").catch(() => null);
              if (fr && fr.ok) {
                const fd = await fr.json();
                setFindings(Array.isArray(fd.findings) ? fd.findings : []);
              }
            }
          }
        }, 600);
      },
      stop() {
        if (timer) {
          clearInterval(timer);
          timer = null;
        }
      }
    };
  }, []);

  useEffect(() => {
    // initial load
    fetch("/api/scan/status").then(r => r.json()).then(setStatus).catch(() => {});
    fetch("/api/findings").then(r => r.json()).then(d => setFindings(d.findings || [])).catch(() => {});
  }, []);

  const startScan = async () => {
    const r = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targets }),
    });
    if (r.ok || r.status === 202) {
      polling.start();
    }
  };

  const refreshFindings = async () => {
    const fr = await fetch("/api/findings").catch(() => null);
    if (fr && fr.ok) {
      const fd = await fr.json();
      setFindings(Array.isArray(fd.findings) ? fd.findings : []);
    }
  };

  const openDrawer = (f) => { setSelected(f); setDrawerOpen(true); };
  const closeDrawer = () => { setDrawerOpen(false); setSelected(null); };

  return (
    <>
      <Box>
        <Typography variant="h6" sx={{ mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
          <BugReportRounded /> Rudra – API Security Dashboard
        </Typography>

        <Grid container spacing={2}>
          {/* Left: Controls + Progress */}
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="subtitle2" color="text.secondary">Targets</Typography>
                <Stack spacing={1} sx={{ mt: 1 }}>
                  {targets.map((t, i) => (
                    <TextField
                      key={i}
                      size="small"
                      value={t}
                      placeholder="https://api.example.com/v1/health"
                      onChange={(e) => {
                        const next = [...targets];
                        next[i] = e.target.value;
                        setTargets(next);
                      }}
                    />
                  ))}
                  <Button onClick={() => setTargets((arr) => [...arr, ""])}>+ Add target</Button>
                </Stack>

                <Divider sx={{ my: 2 }} />

                <Stack direction="row" spacing={1}>
                  <Button
                    variant="contained"
                    startIcon={<PlayArrowRounded />}
                    disabled={status.status === "running" || targets.length === 0}
                    onClick={startScan}
                  >
                    Start Scan
                  </Button>
                  <Button variant="outlined" startIcon={<RefreshRounded />} onClick={refreshFindings}>
                    Refresh
                  </Button>
                </Stack>
              </CardContent>
            </Card>

            <Box sx={{ mt: 2 }}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>Scan Progress</Typography>
                <Stack spacing={1}>
                  <StepDots steps={status.steps || stepsDefault} active={status.active_step || 0} />

                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="caption">{(status.status || "idle").toUpperCase()}</Typography>
                    <Typography variant="caption">{Math.round(status.progress || 0)}%</Typography>
                  </Stack>

                  <LinearProgress
                    variant="determinate"
                    value={Math.round(status.progress || 0)}
                    sx={{ height: 10, borderRadius: 6 }}
                  />
                </Stack>
              </Paper>
            </Box>
          </Grid>

          {/* Right: Findings */}
          <Grid item xs={12} md={8}>
            <Paper sx={{ p: 1 }}>
              <Typography variant="subtitle2" sx={{ p: 1 }}>Findings</Typography>
              <TableContainer sx={{ maxHeight: 560 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Type</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Endpoint</TableCell>
                      <TableCell>Method</TableCell>
                      <TableCell>Confidence</TableCell>
                      <TableCell>Tags</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(findings || []).map((f, idx) => (
                      <TableRow key={idx} hover onClick={() => openDrawer(f)} sx={{ cursor: "pointer" }}>
                        <TableCell>
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Typography variant="body2">{f.type}</Typography>
                            { (f.cve || f.cve_id || f.nvd?.cve_id) && (
                              <Chip size="small" variant="outlined" label={f.cve || f.cve_id || f.nvd?.cve_id} />
                            )}
                          </Stack>
                        </TableCell>
                        <TableCell>
                          <Chip size="small" color={sevColor(f.severity)} label={f.severity} />
                        </TableCell>
                        <TableCell sx={{ maxWidth: 320, whiteSpace: "nowrap", textOverflow: "ellipsis", overflow: "hidden" }}>
                          {f.endpoint}
                        </TableCell>
                        <TableCell>{f.method}</TableCell>
                        <TableCell>{Math.round((f.confidence || 0) * 100)}%</TableCell>
                        <TableCell>
                          <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap" }}>
                            {(f.tags || []).map((t) => (
                              <Chip key={t} size="small" label={t} variant="outlined" />
                            ))}
                          </Stack>
                        </TableCell>
                      </TableRow>
                    ))}
                    {(!findings || findings.length === 0) && (
                      <TableRow>
                        <TableCell colSpan={6}>
                          <Typography variant="body2" color="text.secondary">
                            No findings yet. Start a scan.
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>
      </Box>

      <FindingDrawer open={drawerOpen} onClose={closeDrawer} finding={selected} />
    </>
  );
}

