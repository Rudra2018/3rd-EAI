import React from "react";
import { Button, Stack } from "@mui/material";

export default function ReportButtons() {
  const open = (fmt) => window.open(`/api/report?format=${fmt}`, "_blank");
  return (
    <Stack direction="row" spacing={1}>
      <Button variant="outlined" onClick={()=>open("html")}>View HTML Report</Button>
      <Button variant="outlined" onClick={()=>open("json")}>Download JSON</Button>
      <Button variant="outlined" onClick={()=>open("pdf")}>PDF (if supported)</Button>
    </Stack>
  );
}

