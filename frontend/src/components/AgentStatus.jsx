import React, { useEffect, useState } from "react";
import { Card, CardContent, Typography, Stack, Chip, Divider } from "@mui/material";

const colorFor = (s) =>
  s === "ready" || s === "armed" ? "success" :
  s === "busy" ? "warning" : "default";

export default function AgentStatus() {
  const [data, setData] = useState({
    ai_enhanced: false,
    beast_mode: false,
    continuous_learning: false,
    agents: []
  });

  useEffect(() => {
    fetch("/api/agent/status")
      .then(r => r.json())
      .then(setData)
      .catch(() => {});
  }, []);

  return (
    <Card>
      <CardContent>
        <Typography variant="subtitle1" sx={{ mb: 1, fontWeight: 700 }}>
          Agentic AI
        </Typography>

        <Stack direction="row" spacing={1} sx={{ mb: 1, flexWrap: "wrap" }}>
          <Chip size="small" color={data.ai_enhanced ? "success" : "default"} label={`AI Enhanced: ${data.ai_enhanced ? "On" : "Off"}`} />
          <Chip size="small" color={data.beast_mode ? "warning" : "default"} label={`Beast Mode: ${data.beast_mode ? "On" : "Off"}`} />
          <Chip size="small" color={data.continuous_learning ? "info" : "default"} label={`Learning: ${data.continuous_learning ? "On" : "Off"}`} />
        </Stack>

        <Divider sx={{ my: 1 }} />

        <Stack spacing={0.75}>
          {(data.agents || []).map((a, i) => (
            <Stack key={i} direction="row" spacing={1} alignItems="center">
              <Typography variant="body2" sx={{ minWidth: 120 }}>{a.name}</Typography>
              <Chip size="small" color={colorFor(a.status)} label={a.status} />
            </Stack>
          ))}
          {(!data.agents || data.agents.length === 0) && (
            <Typography variant="body2" color="text.secondary">No agents loaded.</Typography>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

