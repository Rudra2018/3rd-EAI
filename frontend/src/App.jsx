import React, { Suspense, lazy } from "react";
import { Container, CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import ErrorBoundary from "./components/ErrorBoundary.jsx";

const ScanDashboard = lazy(() => import("./components/ScanDashboard.jsx"));

const theme = createTheme({
  palette: { mode: "dark", background: { default: "#0b0e13", paper: "#121620" } }
});

export default function App(){
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container maxWidth="lg" sx={{ py: 2 }}>
        <ErrorBoundary>
          <Suspense fallback={<div style={{height:240}} />}>
            <ScanDashboard />
          </Suspense>
        </ErrorBoundary>
      </Container>
    </ThemeProvider>
  );
}

