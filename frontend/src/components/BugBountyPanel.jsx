import React, { useEffect, useState } from "react";
import { Box, Button, Card, CardContent, Chip, Divider, Stack, TextField, Typography } from "@mui/material";

export default function BugBountyPanel({ onAddTarget }) {
  const [programs, setPrograms] = useState([]);
  const [filter, setFilter] = useState("");

  useEffect(()=>{
    fetch("/api/bug-bounty/programs").then(r=>r.json()).then(d=>{
      setPrograms(Array.isArray(d.programs)? d.programs : []);
    }).catch(()=>{});
  },[]);

  const filtered = programs.filter(p=>{
    const s = JSON.stringify(p).toLowerCase();
    return !filter || s.includes(filter.toLowerCase());
  }).slice(0, 200);

  return (
    <Card>
      <CardContent>
        <Typography variant="subtitle2" color="text.secondary">Bug Bounty Programs</Typography>
        <Stack direction="row" spacing={1} sx={{ mt:1 }}>
          <TextField size="small" placeholder="Search programs or scopes…" value={filter} onChange={e=>setFilter(e.target.value)} fullWidth />
        </Stack>
        <Box sx={{ mt:1, maxHeight: 200, overflow: "auto" }}>
          {filtered.map((p, i)=>(
            <Stack key={i} direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
              <Typography variant="body2" sx={{ minWidth: 180, fontWeight: 600 }}>{p.name || p.program || "Program"}</Typography>
              <Typography variant="body2" sx={{ flex: 1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                {(p.scopes || p.targets || []).join(", ")}
              </Typography>
              <Button size="small" onClick={()=> onAddTarget?.((p.scopes || p.targets || [])[0])}>Add</Button>
            </Stack>
          ))}
          {!filtered.length && (<Typography variant="body2" color="text.secondary">No programs configured.</Typography>)}
        </Box>
      </CardContent>
    </Card>
  );
}

