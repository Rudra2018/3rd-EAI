import { useEffect, useState } from "react";
import { Box, Stack, TextField, MenuItem, Typography } from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import { getFindings } from "./api";

const severities = ["", "critical", "high", "medium", "low", "info"];

export default function FindingsTable(){
  const [rows, setRows] = useState([]);
  const [rowCount, setRowCount] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(50);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");

  useEffect(() => {
    let alive = true;
    setLoading(true);
    getFindings({ page: page+1, page_size: pageSize, q, severity })
      .then(d => {
        if (!alive) return;
        const list = (d.findings || []).map((f, i) => ({ id:`${page}-${i}`, ...f }));
        setRows(list);
        setRowCount(d.total || 0);
      })
      .catch(e => console.error("findings load:", e))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [page, pageSize, q, severity]);

  const columns = [
    { field:"type", headerName:"Type", flex:1, minWidth:160 },
    { field:"severity", headerName:"Severity", width:110,
      valueGetter:p => (p.row.severity||"").toUpperCase() },
    { field:"endpoint", headerName:"Endpoint", flex:1.3, minWidth:240 },
    { field:"method", headerName:"Method", width:100 },
    { field:"confidence", headerName:"Confidence", width:120,
      valueGetter:p => `${Math.round((p.row.confidence||0)*100)}%` },
    { field:"tags", headerName:"Tags", flex:1, minWidth:180,
      valueGetter:p => (p.row.tags||[]).join(", ") },
  ];

  return (
    <Box>
      <Stack direction="row" spacing={2} sx={{ mb: 1 }}>
        <TextField size="small" label="Search" value={q} onChange={e=>{ setPage(0); setQ(e.target.value); }} />
        <TextField size="small" select label="Severity" value={severity}
                   onChange={e=>{ setPage(0); setSeverity(e.target.value); }}>
          {severities.map(s => <MenuItem key={s} value={s}>{s || "All"}</MenuItem>)}
        </TextField>
        <Typography sx={{ ml: "auto", opacity: 0.7 }}>
          {rowCount.toLocaleString()} total
        </Typography>
      </Stack>

      <div style={{ height: 520, width: "100%" }}>
        <DataGrid
          rows={rows}
          columns={columns}
          pagination
          paginationMode="server"
          rowCount={rowCount}
          page={page}
          onPageChange={setPage}
          pageSize={pageSize}
          onPageSizeChange={setPageSize}
          rowsPerPageOptions={[25,50,100,200]}
          loading={loading}
          disableRowSelectionOnClick
        />
      </div>
    </Box>
  );
}

