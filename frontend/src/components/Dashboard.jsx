import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  CheckCircle,
  Clock,
  TrendingUp,
  Users,
  Target
} from 'lucide-react';

const Dashboard = ({ activeScans }) => {
  const [stats, setStats] = useState({
    total_scans: 0,
    active_scans: 0,
    vulnerabilities_found: 0,
    critical_issues: 0
  });
  
  const [recentScans, setRecentScans] = useState([]);
  
  useEffect(() => {
    fetchDashboardData();
  }, []);
  
  const fetchDashboardData = async () => {
    try {
      const response = await fetch('/api/scans');
      const data = await response.json();
      
      setRecentScans(data.scans || []);
      
      const activeCount = data.scans?.filter(s => s.status === 'scanning').length || 0;
      const vulnCount = data.scans?.reduce((sum, s) => sum + (s.vulnerabilities_found || 0), 0) || 0;
      
      setStats({
        total_scans: data.scans?.length || 0,
        active_scans: activeCount,
        vulnerabilities_found: vulnCount,
        critical_issues: Math.floor(vulnCount * 0.1)
      });
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    }
  };
  
  const StatCard = ({ icon: Icon, title, value, color = "blue", trend = null }) => (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center">
        <div className={`flex-shrink-0 p-3 rounded-md bg-${color}-100`}>
          <Icon className={`h-6 w-6 text-${color}-600`} />
        </div>
        <div className="ml-4 flex-1">
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className="text-2xl font-semibold text-gray-900">{value}</p>
          {trend && (
            <div className="flex items-center mt-1">
              <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
              <span className="text-sm text-green-600">{trend}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
  
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="text-gray-600 mt-2">
          Monitor your API security scanning activities and results
        </p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={Target}
          title="Total Scans"
          value={stats.total_scans}
          color="blue"
          trend="+12% from last week"
        />
        <StatCard
          icon={Activity}
          title="Active Scans"
          value={stats.active_scans}
          color="green"
        />
        <StatCard
          icon={AlertTriangle}
          title="Vulnerabilities Found"
          value={stats.vulnerabilities_found}
          color="yellow"
        />
        <StatCard
          icon={Shield}
          title="Critical Issues"
          value={stats.critical_issues}
          color="red"
        />
      </div>
      
      <div className="bg-white rounded-lg shadow">
        <div className="p-6 border-b">
          <h2 className="text-xl font-semibold text-gray-900">Recent Scans</h2>
        </div>
        <div className="p-6">
          {recentScans.length === 0 ? (
            <p className="text-gray-500 text-center py-8">No scans yet. Start your first scan!</p>
          ) : (
            <div className="space-y-4">
              {recentScans.slice(0, 5).map((scan) => (
                <div key={scan.scan_id} className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex items-center space-x-4">
                    <div className={`p-2 rounded-full ${
                      scan.status === 'completed' ? 'bg-green-100' :
                      scan.status === 'scanning' ? 'bg-blue-100' : 'bg-red-100'
                    }`}>
                      {scan.status === 'completed' ? (
                        <CheckCircle className="h-5 w-5 text-green-600" />
                      ) : scan.status === 'scanning' ? (
                        <Activity className="h-5 w-5 text-blue-600" />
                      ) : (
                        <AlertTriangle className="h-5 w-5 text-red-600" />
                      )}
                    </div>
                    <div>
                      <p className="font-medium text-gray-900">
                        {scan.type} Scan
                      </p>
                      <p className="text-sm text-gray-500">
                        {new Date(scan.started_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <p className="text-sm font-medium text-gray-900">
                        {scan.vulnerabilities_found || 0} vulnerabilities
                      </p>
                      <p className="text-xs text-gray-500 capitalize">
                        {scan.status}
                      </p>
                    </div>
                    <button className="text-blue-600 hover:text-blue-800 text-sm font-medium">
                      View Details
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

