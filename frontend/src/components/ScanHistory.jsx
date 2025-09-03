import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Clock, 
  CheckCircle, 
  XCircle, 
  Activity,
  Eye,
  AlertTriangle
} from 'lucide-react';

const ScanHistory = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetchScans();
  }, [filter]);

  const fetchScans = async () => {
    try {
      const response = await fetch(`/api/scans?status=${filter === 'all' ? '' : filter}`);
      const data = await response.json();
      setScans(data.scans || []);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-600" />;
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-600" />;
      case 'scanning':
        return <Activity className="h-5 w-5 text-blue-600" />;
      default:
        return <Clock className="h-5 w-5 text-gray-600" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800';
      case 'failed': return 'bg-red-100 text-red-800';
      case 'scanning': return 'bg-blue-100 text-blue-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="bg-white rounded-lg shadow">
        <div className="p-6 border-b">
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold text-gray-900 flex items-center">
              <Clock className="mr-3 text-blue-600" />
              Scan History
            </h1>
            <div className="flex space-x-2">
              {['all', 'completed', 'scanning', 'failed'].map((status) => (
                <button
                  key={status}
                  onClick={() => setFilter(status)}
                  className={`px-3 py-1 rounded-md text-sm font-medium ${
                    filter === status
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="divide-y divide-gray-200">
          {scans.length === 0 ? (
            <div className="p-12 text-center">
              <Clock className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No Scans Found</h3>
              <p className="text-gray-600">Start your first security scan to see results here.</p>
            </div>
          ) : (
            scans.map((scan) => (
              <div key={scan.scan_id} className="p-6 hover:bg-gray-50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="p-2 rounded-full bg-gray-100">
                      {getStatusIcon(scan.status)}
                    </div>
                    <div>
                      <h3 className="text-lg font-medium text-gray-900">
                        {scan.type?.charAt(0).toUpperCase() + scan.type?.slice(1)} Scan
                      </h3>
                      <p className="text-sm text-gray-500">
                        Started: {new Date(scan.started_at).toLocaleString()}
                      </p>
                      {scan.completed_at && (
                        <p className="text-sm text-gray-500">
                          Completed: {new Date(scan.completed_at).toLocaleString()}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(scan.status)}`}>
                        {scan.status}
                      </span>
                      {scan.progress !== undefined && scan.status === 'scanning' && (
                        <p className="text-sm text-gray-500 mt-1">
                          {scan.progress}% complete
                        </p>
                      )}
                    </div>

                    <div className="text-right">
                      <p className="text-sm font-medium text-gray-900">
                        {scan.vulnerabilities_found || 0} vulnerabilities
                      </p>
                      {scan.security_score && (
                        <p className="text-sm text-gray-500">
                          Security Score: {scan.security_score}/100
                        </p>
                      )}
                    </div>

                    {scan.status === 'completed' && (
                      <Link
                        to={`/results/${scan.scan_id}`}
                        className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 flex items-center text-sm"
                      >
                        <Eye className="h-4 w-4 mr-2" />
                        View Results
                      </Link>
                    )}
                  </div>
                </div>

                {scan.vulnerabilities_found > 0 && (
                  <div className="mt-4 flex items-center space-x-4 text-sm">
                    <div className="flex items-center">
                      <AlertTriangle className="h-4 w-4 text-red-500 mr-1" />
                      <span className="text-red-600">
                        {scan.critical_issues || 0} Critical
                      </span>
                    </div>
                    <div className="flex items-center">
                      <AlertTriangle className="h-4 w-4 text-orange-500 mr-1" />
                      <span className="text-orange-600">
                        {scan.high_issues || 0} High
                      </span>
                    </div>
                    <div className="flex items-center">
                      <AlertTriangle className="h-4 w-4 text-yellow-500 mr-1" />
                      <span className="text-yellow-600">
                        {scan.medium_issues || 0} Medium
                      </span>
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanHistory;

