import React, { useEffect, useMemo, useState, Suspense, lazy } from "react";
import { Box, Button, Card, CardContent, Divider, Grid, LinearProgress, Stack, TextField, Typography } from "@mui/material";
import PlayArrowRoundedIcon from "@mui/icons-material/PlayArrowRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import BugReportRoundedIcon from "@mui/icons-material/BugReportRounded";
import { getStatus, startScan } from "./api";

// Lazy-panels (loaded on demand)
const FindingsTable   = lazy(() => import("./FindingsTable.jsx"));
const AuthPanel       = lazy(() => import("./AuthPanel.jsx"));
const ImportPanel     = lazy(() => import("./ImportPanel.jsx"));
const BugBountyPanel  = lazy(() => import("./BugBountyPanel.jsx"));
const ReportButtons   = lazy(() => import("./ReportButtons.jsx"));

export default function ScanDashboard(){
  const [targets, setTargets] = useState("https://example.com/api/health");
  const [status, setStatus] = useState({ status:"idle", progress:0, active_step:0, steps:[] });

  // light polling
  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try{
        const s = await getStatus();
        if (!stop) setStatus(s);
      }catch(e){ console.warn("status err", e); }
    };
    tick();
    const id = setInterval(tick, 1200);
    return () => { stop = true; clearInterval(id); };
  }, []);

  const stepLabel = useMemo(() => {
    const steps = status.steps || [];
    return steps[status.active_step] || "";
  }, [status]);

  const runScan = async () => {
    const t = targets.split(/\s|,|\n/).map(s => s.trim()).filter(Boolean);
    if (!t.length) return;
    await startScan({ targets: t, options: { ai_enhanced: true, beast_mode: true, crawl: true, concurrency: 4 } });
  };

  return (
    <Grid container spacing={2}>
      {/* Header & Actions */}
      <Grid item xs={12}>
        <Typography variant="h5" fontWeight={700}>Rudra – API Security Dashboard</Typography>
        <Typography variant="body2" sx={{ opacity: 0.7 }}>Halodoc-style Security Dashboard</Typography>
      </Grid>

      {/* Controls */}
      <Grid item xs={12} md={8}>
        <Card>
          <CardContent>
            <Stack direction="row" spacing={1} alignItems="center">
              <TextField
                fullWidth
                size="small"
                multiline
                minRows={1}
                label="Targets (space/comma/newline separated)"
                value={targets}
                onChange={e=>setTargets(e.target.value)}
              />
              <Button variant="contained" startIcon={<PlayArrowRoundedIcon />} onClick={runScan}>
                Start
              </Button>
              <Button variant="outlined" startIcon={<RefreshRoundedIcon />} onClick={()=>location.reload()}>
                Refresh
              </Button>
            </Stack>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={4}>
        <Card>
          <CardContent>
            <Stack spacing={1}>
              <Typography variant="subtitle2">Scan Progress</Typography>
              <LinearProgress variant="determinate" value={Math.min(100, Number(status.progress) || 0)} />
              <Typography variant="caption">
                {Math.round(Number(status.progress) || 0)}% • {stepLabel || "Idle"}
              </Typography>
            </Stack>
          </CardContent>
        </Card>
      </Grid>

      {/* Auth & Import (lazy) */}
      <Grid item xs={12} md={4}>
        <Suspense fallback={<Card><CardContent style={{ height: 180 }} /></Card>}>
          <AuthPanel />
        </Suspense>
      </Grid>
      <Grid item xs={12} md={8}>
        <Suspense fallback={<Card><CardContent style={{ height: 180 }} /></Card>}>
          <ImportPanel />
        </Suspense>
      </Grid>

      {/* Findings (server-paginated & virtualized) */}
      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
              <BugReportRoundedIcon fontSize="small" />
              <Typography variant="subtitle1" fontWeight={600}>Findings</Typography>
            </Stack>
            <Suspense fallback={<Box sx={{ height: 520 }} />}>
              <FindingsTable />
            </Suspense>
          </CardContent>
        </Card>
      </Grid>

      {/* Bug Bounty & Reports (lazy) */}
      <Grid item xs={12} md={8}>
        <Suspense fallback={<Card><CardContent style={{ height: 240 }} /></Card>}>
          <BugBountyPanel />
        </Suspense>
      </Grid>
      <Grid item xs={12} md={4}>
        <Suspense fallback={<Card><CardContent style={{ height: 240 }} /></Card>}>
          <ReportButtons />
        </Suspense>
      </Grid>
    </Grid>
  );
}

