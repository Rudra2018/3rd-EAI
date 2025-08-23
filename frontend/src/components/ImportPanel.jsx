import React, { useRef, useState } from "react";
import { Box, Button, Card, CardContent, Divider, MenuItem, Stack, TextField, Typography } from "@mui/material";

export default function ImportPanel({ onImported }) {
  const [type, setType] = useState("openapi");
  const [url, setUrl] = useState("");
  const fileRef = useRef(null);

  const importNow = async () => {
    const fd = new FormData();
    fd.append("type", type);
    if (fileRef.current?.files?.[0]) {
      fd.append("file", fileRef.current.files[0]);
    } else if (url.trim()) {
      fd.append("url", url.trim());
    } else {
      alert("Select a file or enter a URL");
      return;
    }
    const r = await fetch("/api/import", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) { alert(d.error || "Import failed"); return; }
    onImported?.(d.requests || []);
  };

  return (
    <Card>
      <CardContent>
        <Typography variant="subtitle2" color="text.secondary">Import API (Postman / OpenAPI / HAR)</Typography>
        <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
          <TextField size="small" label="Type" select value={type} onChange={e=>setType(e.target.value)} sx={{ minWidth: 180 }}>
            <MenuItem value="openapi">openapi</MenuItem>
            <MenuItem value="postman">postman</MenuItem>
            <MenuItem value="har">har</MenuItem>
          </TextField>
          <Button variant="outlined" component="label">
            Choose File
            <input hidden ref={fileRef} type="file" />
          </Button>
          <TextField size="small" label="or URL" value={url} onChange={e=>setUrl(e.target.value)} sx={{ minWidth: 360, flex: 1 }} />
          <Button variant="contained" onClick={importNow}>Import</Button>
        </Stack>
      </CardContent>
    </Card>
  );
}

