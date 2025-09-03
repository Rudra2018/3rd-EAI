import React, { useState } from 'react';
import { toast } from 'react-hot-toast';
import { 
  Database, 
  Play, 
  Code, 
  Shield
} from 'lucide-react';
import ScanProgress from './ScanProgress';

const GraphQLScanner = ({ onScanStart }) => {
  const [endpoint, setEndpoint] = useState('');
  const [query, setQuery] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [activeScan, setActiveScan] = useState(null);

  const handleScan = async () => {
    if (!endpoint) {
      toast.error('Please enter a GraphQL endpoint');
      return;
    }

    setIsScanning(true);

    try {
      const response = await fetch('/api/scan/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          endpoint,
          query: query || null,
          auth_token: authToken || null,
          introspection_enabled: true,
          test_injections: true,
          ai_analysis: true
        }),
      });

      const result = await response.json();
      
      if (response.ok) {
        setActiveScan(result.scan_id);
        onScanStart(result.scan_id, { type: 'graphql', target: endpoint });
        toast.success('GraphQL scan started successfully!');
      } else {
        throw new Error(result.detail || 'Scan failed');
      }
    } catch (error) {
      toast.error(`Scan failed: ${error.message}`);
      setIsScanning(false);
    }
  };

  const handleScanComplete = () => {
    setIsScanning(false);
    setActiveScan(null);
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white rounded-lg shadow-lg">
        <div className="p-6 border-b">
          <h1 className="text-2xl font-bold text-gray-900 flex items-center">
            <Database className="mr-3 text-blue-600" />
            GraphQL Security Scanner
          </h1>
          <p className="text-gray-600 mt-2">
            Comprehensive security testing for GraphQL APIs
          </p>
        </div>

        <div className="p-6">
          {activeScan ? (
            <ScanProgress 
              scanId={activeScan} 
              onComplete={handleScanComplete}
            />
          ) : (
            <>
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  GraphQL Endpoint
                </label>
                <div className="flex">
                  <input
                    type="url"
                    value={endpoint}
                    onChange={(e) => setEndpoint(e.target.value)}
                    placeholder="https://api.example.com/graphql"
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-l-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    onClick={handleScan}
                    disabled={isScanning || !endpoint}
                    className="px-6 py-2 bg-blue-600 text-white rounded-r-md hover:bg-blue-700 disabled:bg-gray-400 flex items-center"
                  >
                    <Play className="h-4 w-4 mr-2" />
                    {isScanning ? 'Starting...' : 'Start Scan'}
                  </button>
                </div>
              </div>

              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Authentication Token (Optional)
                </label>
                <input
                  type="password"
                  value={authToken}
                  onChange={(e) => setAuthToken(e.target.value)}
                  placeholder="Bearer token or API key"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Custom Query (Optional)
                </label>
                <div className="relative">
                  <textarea
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Enter your GraphQL query here (optional)"
                    rows="8"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                  />
                  <Code className="absolute top-3 right-3 h-4 w-4 text-gray-400" />
                </div>
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
                <div className="flex items-start">
                  <Shield className="h-6 w-6 text-blue-600 mt-1 mr-3" />
                  <div>
                    <h3 className="text-lg font-semibold text-blue-900 mb-3">
                      GraphQL Security Tests
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <h4 className="font-medium text-blue-800 mb-2">Core Vulnerabilities</h4>
                        <ul className="text-sm text-blue-700 space-y-1">
                          <li>• Introspection disclosure</li>
                          <li>• Query depth limiting</li>
                          <li>• Query complexity analysis</li>
                          <li>• Rate limiting bypass</li>
                        </ul>
                      </div>
                      <div>
                        <h4 className="font-medium text-blue-800 mb-2">Advanced Analysis</h4>
                        <ul className="text-sm text-blue-700 space-y-1">
                          <li>• AI-powered injection testing</li>
                          <li>• Authorization bypass detection</li>
                          <li>• Schema poisoning checks</li>
                          <li>• Batch query abuse testing</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default GraphQLScanner;

