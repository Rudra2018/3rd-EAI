import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Download,
  Eye,
  Clock
} from 'lucide-react';

const ScanResults = () => {
  const { scanId } = useParams();
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchResults();
  }, [scanId]);

  const fetchResults = async () => {
    try {
      const response = await fetch(`/api/scan/${scanId}/results`);
      if (response.ok) {
        const data = await response.json();
        setResults(data);
      } else {
        setError('Failed to load scan results');
      }
    } catch (err) {
      setError('Error fetching results');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6">
        <div className="flex items-center">
          <AlertTriangle className="h-6 w-6 text-red-600 mr-3" />
          <div>
            <h3 className="text-lg font-medium text-red-800">Error Loading Results</h3>
            <p className="text-red-600">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  if (!results) {
    return (
      <div className="text-center py-12">
        <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900">No Results Found</h3>
        <p className="text-gray-600">The scan results could not be found.</p>
      </div>
    );
  }

  const summary = results.summary || {};

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center">
              <Shield className="mr-3 text-blue-600" />
              Scan Results
            </h1>
            <p className="text-gray-600 mt-1">
              Target: {results.target || results.endpoint || 'Unknown'}
            </p>
            <p className="text-sm text-gray-500">
              Completed: {new Date(results.completed_at).toLocaleString()}
            </p>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => window.open(`/api/scan/${scanId}/export/html`)}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 flex items-center"
            >
              <Download className="h-4 w-4 mr-2" />
              Export HTML
            </button>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-md bg-blue-100">
              <Eye className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Security Score</p>
              <p className="text-2xl font-semibold text-gray-900">
                {summary.security_score || 0}/100
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-md bg-red-100">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Critical Issues</p>
              <p className="text-2xl font-semibold text-red-600">
                {summary.critical_issues || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-md bg-orange-100">
              <AlertTriangle className="h-6 w-6 text-orange-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">High Issues</p>
              <p className="text-2xl font-semibold text-orange-600">
                {summary.high_issues || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-md bg-green-100">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Vulnerabilities</p>
              <p className="text-2xl font-semibold text-gray-900">
                {summary.vulnerabilities_found || 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      {results.vulnerabilities && results.vulnerabilities.length > 0 ? (
        <div className="bg-white rounded-lg shadow">
          <div className="p-6 border-b">
            <h2 className="text-xl font-semibold text-gray-900">Vulnerabilities Found</h2>
          </div>
          <div className="divide-y divide-gray-200">
            {results.vulnerabilities.map((vuln, index) => (
              <div key={index} className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-medium text-gray-900">
                        {vuln.title || vuln.type || 'Unknown Vulnerability'}
                      </h3>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity || 'Unknown'}
                      </span>
                    </div>
                    <p className="text-gray-600 mb-3">
                      {vuln.description || 'No description available'}
                    </p>
                    {vuln.endpoint && (
                      <p className="text-sm text-gray-500 mb-2">
                        <strong>Endpoint:</strong> {vuln.endpoint}
                      </p>
                    )}
                    {vuln.evidence && (
                      <div className="bg-gray-50 rounded p-3">
                        <p className="text-sm font-medium text-gray-700 mb-1">Evidence:</p>
                        <p className="text-sm text-gray-600 font-mono">
                          {vuln.evidence.substring(0, 200)}
                          {vuln.evidence.length > 200 && '...'}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow p-6 text-center">
          <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No Vulnerabilities Found</h3>
          <p className="text-gray-600">Great! Your scan didn't detect any security vulnerabilities.</p>
        </div>
      )}

      {/* AI Insights */}
      {results.ai_insights && Object.keys(results.ai_insights).length > 0 && (
        <div className="bg-white rounded-lg shadow">
          <div className="p-6 border-b">
            <h2 className="text-xl font-semibold text-gray-900">AI Security Insights</h2>
          </div>
          <div className="p-6">
            <div className="bg-blue-50 rounded-lg p-4">
              <h3 className="font-medium text-blue-900 mb-3">Advanced Analysis</h3>
              <div className="space-y-2">
                {results.ai_insights.strategy_confidence && (
                  <p className="text-sm text-blue-800">
                    <strong>AI Confidence:</strong> {Math.round(results.ai_insights.strategy_confidence * 100)}%
                  </p>
                )}
                {results.ai_insights.risk_assessment?.risk_level && (
                  <p className="text-sm text-blue-800">
                    <strong>Risk Level:</strong> {results.ai_insights.risk_assessment.risk_level}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanResults;

