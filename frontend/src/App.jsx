import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Navigation from './components/Navigation';
import Dashboard from './components/Dashboard';
import URLScanner from './components/URLScanner';
import PostmanScanner from './components/PostmanScanner';
import GraphQLScanner from './components/GraphQLScanner';
import ScanResults from './components/ScanResults';
import ScanHistory from './components/ScanHistory';
import './App.css';

function App() {
  const [activeScans, setActiveScans] = useState(new Map());

  const updateScanStatus = (scanId, status) => {
    setActiveScans(prev => new Map(prev.set(scanId, status)));
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <Toaster position="top-right" />
        <Navigation />
        
        <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard activeScans={activeScans} />} />
            <Route 
              path="/scan/url" 
              element={<URLScanner onScanStart={updateScanStatus} />} 
            />
            <Route 
              path="/scan/postman" 
              element={<PostmanScanner onScanStart={updateScanStatus} />} 
            />
            <Route 
              path="/scan/graphql" 
              element={<GraphQLScanner onScanStart={updateScanStatus} />} 
            />
            <Route path="/results/:scanId" element={<ScanResults />} />
            <Route path="/history" element={<ScanHistory />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;

