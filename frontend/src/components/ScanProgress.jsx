// src/components/ScanProgress.jsx
import React from "react";
import { Box, LinearProgress, Step, StepLabel, Stepper, Typography, Paper } from "@mui/material";

export default function ScanProgress({ progress = 0, activeStep = 0, steps = [] }) {
  const safeSteps = steps && steps.length ? steps : ["Queued", "Recon", "Scanning", "Analyzing", "Reporting"];
  const safeActive = Math.min(Math.max(activeStep, 0), safeSteps.length - 1);

  return (
    <Paper elevation={2} sx={{ p: 2 }}>
      <Typography variant="subtitle1" gutterBottom>
        Scan Progress
      </Typography>

      <Box sx={{ width: "100%", mb: 2 }}>
        <LinearProgress variant="determinate" value={progress} />
        <Box sx={{ display: "flex", justifyContent: "space-between", mt: 0.5 }}>
          <Typography variant="caption">{safeSteps[safeActive]}</Typography>
          <Typography variant="caption">{Math.round(progress)}%</Typography>
        </Box>
      </Box>

      <Stepper activeStep={safeActive} alternativeLabel>
        {safeSteps.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>
    </Paper>
  );
}

