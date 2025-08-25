import React from "react";
import { Alert, AlertTitle, Button } from "@mui/material";

export default class ErrorBoundary extends React.Component {
  constructor(props){ super(props); this.state = { hasError:false, info:null }; }
  static getDerivedStateFromError(){ return { hasError:true }; }
  componentDidCatch(error, info){ console.error("UI crashed:", error, info); this.setState({ info }); }

  render(){
    if (!this.state.hasError) return this.props.children;
    return (
      <Alert severity="error" sx={{ mt:2 }}>
        <AlertTitle>Something went wrong</AlertTitle>
        The UI hit an unexpected error and stopped rendering.
        <div style={{ marginTop: 8 }}>
          <Button variant="outlined" onClick={() => location.reload()}>Reload</Button>
        </div>
      </Alert>
    );
  }
}

