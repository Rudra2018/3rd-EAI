import React, { useState, useEffect } from "react";
import {
  Box, Button, Card, CardContent, Divider, Grid, MenuItem, Stack, TextField, Typography
} from "@mui/material";

const TYPES = ["api_key","bearer","jwt","basic","oauth2"];

export default function AuthPanel() {
  const [host, setHost] = useState("default");
  const [type, setType] = useState("bearer");
  const [apiKeyName, setApiKeyName] = useState("X-API-Key");
  const [apiKeyIn, setApiKeyIn] = useState("header");
  const [apiKeyValue, setApiKeyValue] = useState("");
  const [bearerToken, setBearerToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [oauthAccessToken, setOauthAccessToken] = useState("");
  const [extraHeaders, setExtraHeaders] = useState("");

  const save = async () => {
    const payload = { host, type };
    if (type === "api_key") {
      payload.name = apiKeyName; payload["in"] = apiKeyIn; payload.key = apiKeyValue;
    } else if (type === "bearer" || type === "jwt") {
      payload.token = bearerToken;
    } else if (type === "basic") {
      payload.username = username; payload.password = password;
    } else if (type === "oauth2") {
      payload.access_token = oauthAccessToken;
    }
    if (extraHeaders.trim()) {
      try { payload.extra_headers = JSON.parse(extraHeaders); } catch {}
    }
    await fetch("/api/auth/config", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  };

  return (
    <Card>
      <CardContent>
        <Typography variant="subtitle2" color="text.secondary">Authentication</Typography>
        <Grid container spacing={1.5} sx={{ mt: 0.5 }}>
          <Grid item xs={12} md={3}>
            <TextField size="small" label="Host (or default)" value={host} onChange={e=>setHost(e.target.value)} fullWidth />
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField size="small" label="Type" select value={type} onChange={e=>setType(e.target.value)} fullWidth>
              {TYPES.map(t=><MenuItem key={t} value={t}>{t}</MenuItem>)}
            </TextField>
          </Grid>

          {type === "api_key" && (
            <>
              <Grid item xs={12} md={3}>
                <TextField size="small" label="Header/Param Name" value={apiKeyName} onChange={e=>setApiKeyName(e.target.value)} fullWidth />
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField size="small" label="In" select value={apiKeyIn} onChange={e=>setApiKeyIn(e.target.value)} fullWidth>
                  <MenuItem value="header">header</MenuItem>
                  <MenuItem value="query">query</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={12}>
                <TextField size="small" label="API Key" value={apiKeyValue} onChange={e=>setApiKeyValue(e.target.value)} fullWidth />
              </Grid>
            </>
          )}

          {(type === "bearer" || type === "jwt") && (
            <Grid item xs={12}>
              <TextField size="small" label="Token" value={bearerToken} onChange={e=>setBearerToken(e.target.value)} fullWidth />
            </Grid>
          )}

          {type === "basic" && (
            <>
              <Grid item xs={12} md={6}>
                <TextField size="small" label="Username" value={username} onChange={e=>setUsername(e.target.value)} fullWidth />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField size="small" label="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)} fullWidth />
              </Grid>
            </>
          )}

          {type === "oauth2" && (
            <Grid item xs={12}>
              <TextField size="small" label="Access Token" value={oauthAccessToken} onChange={e=>setOauthAccessToken(e.target.value)} fullWidth />
            </Grid>
          )}

          <Grid item xs={12}>
            <TextField size="small" label='Extra Headers (JSON: {"Header":"Value"})' value={extraHeaders} onChange={e=>setExtraHeaders(e.target.value)} fullWidth />
          </Grid>
        </Grid>

        <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
          <Button variant="contained" onClick={save}>Save Auth</Button>
          <Button variant="text" onClick={async()=>{
            const r = await fetch("/api/auth/status"); const d = await r.json();
            alert(JSON.stringify(d, null, 2));
          }}>View Status</Button>
        </Stack>
      </CardContent>
    </Card>
  );
}

