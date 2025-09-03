import React, { useState } from 'react';
import { toast } from 'react-hot-toast';
import { 
  Globe, 
  Play, 
  Settings, 
  Shield, 
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import ScanProgress from './ScanProgress';

const URLScanner = ({ onScanStart }) => {
  const [url, setUrl] = useState('');
  const [scanType, setScanType] = useState('comprehensive');
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [maxDepth, setMaxDepth] = useState(3);
  const [authToken, setAuthToken] = useState('');
  const [customHeaders, setCustomHeaders] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [activeScan, setActiveScan] = useState(null);

  const handleScan = async () => {
    if (!url) {
      toast.error('Please enter a URL to scan');
      return;
    }

    setIsScanning(true);
    
    try {
      const headers = customHeaders ? JSON.parse(customHeaders) : null;
      
      const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          scan_type: scanType,
          include_subdomains: includeSubdomains,
          max_depth: maxDepth,
          auth_token: authToken || null,
          custom_headers: headers,
          ai_enhanced: true,
          ml_enhanced: true
        }),
      });

      const result = await response.json();
      
      if (response.ok) {
        setActiveScan(result.scan_id);
        onScanStart(result.scan_id, { type: 'url', target: url });
        toast.success('URL scan started successfully!');
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
            <Globe className="mr-3 text-blue-600" />
            URL Security Scanner
          </h1>
          <p className="text-gray-600 mt-2">
            Comprehensive security scanning for web applications and APIs
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
                  Target URL
                </label>
                <div className="flex">
                  <input
                    type="url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-l-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    onClick={handleScan}
                    disabled={isScanning || !url}
                    className="px-6 py-2 bg-blue-600 text-white rounded-r-md hover:bg-blue-700 disabled:bg-gray-400 flex items-center"
                  >
                    <Play className="h-4 w-4 mr-2" />
                    {isScanning ? 'Starting...' : 'Start Scan'}
                  </button>
                </div>
              </div>

              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Scan Type
                </label>
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { 
                      value: 'basic', 
                      label: 'Basic Scan', 
                      description: 'Quick vulnerability assessment',
                      icon: Shield 
                    },
                    { 
                      value: 'comprehensive', 
                      label: 'Comprehensive', 
                      description: 'Thorough security analysis',
                      icon: AlertTriangle 
                    },
                    { 
                      value: 'advanced', 
                      label: 'Advanced Scan', 
                      description: 'Deep security testing with AI',
                      icon: Settings 
                    },
                  ].map((type) => {
                    const Icon = type.icon;
                    return (
                      <div
                        key={type.value}
                        className={`border-2 rounded-lg p-4 cursor-pointer transition-colors ${
                          scanType === type.value
                            ? 'border-blue-500 bg-blue-50'
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                        onClick={() => setScanType(type.value)}
                      >
                        <div className="flex items-center mb-2">
                          <Icon className="h-5 w-5 mr-2 text-blue-600" />
                          <span className="font-medium">{type.label}</span>
                        </div>
                        <p className="text-sm text-gray-600">{type.description}</p>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="flex items-start">
                  <Info className="h-5 w-5 text-blue-600 mt-0.5 mr-2" />
                  <div>
                    <h3 className="text-sm font-medium text-blue-800">
                      What this scan includes:
                    </h3>
                    <ul className="mt-2 text-sm text-blue-700 space-y-1">
                      <li>• AI-powered endpoint discovery and mapping</li>
                      <li>• ML-enhanced vulnerability assessment</li>
                      <li>• Advanced authentication testing</li>
                      <li>• Security header analysis</li>
                      <li>• Technology stack detection</li>
                      {scanType === 'advanced' && (
                        <li>• CrewAI autonomous threat analysis</li>
                      )}
                    </ul>
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

export default URLScanner;

