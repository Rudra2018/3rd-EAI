import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Loader, 
  CheckCircle, 
  XCircle, 
  AlertTriangle,
  Eye,
  Download
} from 'lucide-react';

const ScanProgress = ({ scanId, onComplete }) => {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch(`/api/scan/${scanId}/status`);
        const data = await response.json();
        setStatus(data);
        
        if (data.status === 'completed' || data.status === 'failed') {
          setLoading(false);
          if (onComplete) onComplete();
        }
      } catch (error) {
        console.error('Error fetching scan status:', error);
      }
    };

    fetchStatus();
    
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, [scanId, onComplete]);

  const getStatusIcon = () => {
    if (!status) return <Loader className="animate-spin h-6 w-6 text-blue-600" />;
    
    switch (status.status) {
      case 'completed':
        return <CheckCircle className="h-6 w-6 text-green-600" />;
      case 'failed':
        return <XCircle className="h-6 w-6 text-red-600" />;
      case 'scanning':
        return <Loader className="animate-spin h-6 w-6 text-blue-600" />;
      default:
        return <Loader className="animate-spin h-6 w-6 text-blue-600" />;
    }
  };

  const getStatusColor = () => {
    if (!status) return 'bg-blue-500';
    
    switch (status.status) {
      case 'completed':
        return 'bg-green-500';
      case 'failed':
        return 'bg-red-500';
      default:
        return 'bg-blue-500';
    }
  };

  const viewResults = () => {
    navigate(`/results/${scanId}`);
  };

  if (!status) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader className="animate-spin h-8 w-8 text-blue-600" />
        <span className="ml-2 text-gray-600">Loading scan status...</span>
      </div>
    );
  }

  return (
    <div className="bg-gray-50 rounded-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          {getStatusIcon()}
          <div className="ml-3">
            <h2 className="text-xl font-semibold text-gray-900">
              Scan Progress
            </h2>
            <p className="text-sm text-gray-600">
              Scan ID: {scanId}
            </p>
          </div>
        </div>
        
        {status.status === 'completed' && (
          <div className="flex space-x-2">
            <button
              onClick={viewResults}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 flex items-center"
            >
              <Eye className="h-4 w-4 mr-2" />
              View Results
            </button>
          </div>
        )}
      </div>

      <div className="mb-4">
        <div className="flex justify-between text-sm text-gray-600 mb-1">
          <span>Progress</span>
          <span>{status.progress}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div
            className={`h-2 rounded-full transition-all duration-300 ${getStatusColor()}`}
            style={{ width: `${status.progress}%` }}
          ></div>
        </div>
      </div>

      <div className="mb-4">
        <p className="text-sm font-medium text-gray-700">Current Task:</p>
        <p className="text-sm text-gray-600">{status.current_task}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <div className="bg-white p-4 rounded-md shadow-sm">
          <div className="flex items-center">
            <AlertTriangle className="h-5 w-5 text-yellow-500 mr-2" />
            <div>
              <p className="text-sm font-medium text-gray-700">Vulnerabilities</p>
              <p className="text-xl font-bold text-gray-900">
                {status.vulnerabilities_found || 0}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-md shadow-sm">
          <div className="flex items-center">
            <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
            <div>
              <p className="text-sm font-medium text-gray-700">Status</p>
              <p className="text-lg font-semibold capitalize text-gray-900">
                {status.status}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-md shadow-sm">
          <div className="flex items-center">
            <Loader className="h-5 w-5 text-blue-500 mr-2" />
            <div>
              <p className="text-sm font-medium text-gray-700">Started</p>
              <p className="text-sm text-gray-600">
                {new Date(status.started_at).toLocaleTimeString()}
              </p>
            </div>
          </div>
        </div>
      </div>

      {status.status === 'failed' && status.error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex items-start">
            <XCircle className="h-5 w-5 text-red-500 mt-0.5 mr-2" />
            <div>
              <h3 className="text-sm font-medium text-red-800">Scan Failed</h3>
              <p className="text-sm text-red-700 mt-1">{status.error}</p>
            </div>
          </div>
        </div>
      )}

      {status.status === 'completed' && (
        <div className="bg-green-50 border border-green-200 rounded-md p-4">
          <div className="flex items-start">
            <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 mr-2" />
            <div>
              <h3 className="text-sm font-medium text-green-800">Scan Completed</h3>
              <p className="text-sm text-green-700 mt-1">
                Your security scan has completed successfully. 
                {status.vulnerabilities_found > 0 
                  ? ` Found ${status.vulnerabilities_found} potential vulnerabilities.`
                  : ' No vulnerabilities detected.'
                }
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanProgress;

