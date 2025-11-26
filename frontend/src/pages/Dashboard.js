import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import axios from 'axios';
import api from '../services/api';
import './Dashboard.css';

// Use relative URLs - nginx will proxy /api/ to gateway
const goApi = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

function Dashboard() {
  const [networkScans, setNetworkScans] = useState([]);
  const [vulnScans, setVulnScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalNetworkScans: 0,
    runningNetworkScans: 0,
    completedNetworkScans: 0,
    totalVulnScans: 0,
    runningVulnScans: 0,
    completedVulnScans: 0,
    totalVulnerabilities: 0,
    criticalVulns: 0,
    highVulns: 0,
  });

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadAllData = async () => {
    try {
      const [networkRes, vulnRes] = await Promise.all([
        api.get('/scans/'),
        goApi.get('/vulnerabilities/')
      ]);

      const networkData = networkRes.data || [];
      const vulnData = vulnRes.data || [];

      setNetworkScans(networkData.slice(0, 5));
      setVulnScans(vulnData.slice(0, 5));

      // Calculate stats
      const networkRunning = networkData.filter(s => s.status === 'running').length;
      const networkCompleted = networkData.filter(s => s.status === 'completed').length;
      const vulnRunning = vulnData.filter(s => s.status === 'running').length;
      const vulnCompleted = vulnData.filter(s => s.status === 'completed').length;

      // Load vulnerability stats for completed scans
      let totalVulns = 0;
      let criticalVulns = 0;
      let highVulns = 0;

      const completedVulnScans = vulnData.filter(s => s.status === 'completed');
      for (const scan of completedVulnScans.slice(0, 10)) {
        try {
          const statsRes = await goApi.get(`/vulnerabilities/${scan.id}/stats`);
          if (statsRes.data) {
            totalVulns += statsRes.data.total || 0;
            criticalVulns += statsRes.data.by_severity?.critical || 0;
            highVulns += statsRes.data.by_severity?.high || 0;
          }
        } catch (e) {
          // Ignore errors for individual stats
        }
      }

      setStats({
        totalNetworkScans: networkData.length,
        runningNetworkScans: networkRunning,
        completedNetworkScans: networkCompleted,
        totalVulnScans: vulnData.length,
        runningVulnScans: vulnRunning,
        completedVulnScans: vulnCompleted,
        totalVulnerabilities: totalVulns,
        criticalVulns,
        highVulns,
      });
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard home-dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon network-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.totalNetworkScans}</span>
            <span className="stat-label">Network Scans</span>
            <span className="stat-detail">{stats.runningNetworkScans} running, {stats.completedNetworkScans} completed</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon vuln-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.totalVulnScans}</span>
            <span className="stat-label">Vulnerability Scans</span>
            <span className="stat-detail">{stats.runningVulnScans} running, {stats.completedVulnScans} completed</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon findings-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.totalVulnerabilities}</span>
            <span className="stat-label">Vulnerabilities Found</span>
            <span className="stat-detail">
              {stats.criticalVulns > 0 && <span className="critical-count">{stats.criticalVulns} critical</span>}
              {stats.criticalVulns > 0 && stats.highVulns > 0 && ', '}
              {stats.highVulns > 0 && <span className="high-count">{stats.highVulns} high</span>}
              {stats.criticalVulns === 0 && stats.highVulns === 0 && 'No critical issues'}
            </span>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="quick-actions">
        <h2>Quick Actions</h2>
        <div className="actions-grid">
          <Link to="/new-scan" className="action-card">
            <div className="action-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 8v8M8 12h8"/>
              </svg>
            </div>
            <span>New Network Scan</span>
          </Link>
          <Link to="/new-vuln-scan" className="action-card">
            <div className="action-icon vuln">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M12 8v4M12 16h.01"/>
              </svg>
            </div>
            <span>New Vulnerability Scan</span>
          </Link>
          <Link to="/templates" className="action-card">
            <div className="action-icon templates">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                <line x1="3" y1="9" x2="21" y2="9"/>
                <line x1="9" y1="21" x2="9" y2="9"/>
              </svg>
            </div>
            <span>Scan Templates</span>
          </Link>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="recent-sections">
        <div className="recent-section">
          <div className="section-header">
            <h2>Recent Network Scans</h2>
            <Link to="/network-scans" className="view-all-link">View All</Link>
          </div>
          {networkScans.length === 0 ? (
            <div className="empty-state-small">
              <p>No network scans yet</p>
              <Link to="/new-scan" className="btn btn-secondary btn-sm">Create Scan</Link>
            </div>
          ) : (
            <div className="recent-list">
              {networkScans.map(scan => (
                <Link to={`/scan/${scan.id}`} key={scan.id} className="recent-item">
                  <div className="recent-item-info">
                    <span className="recent-item-name">{scan.name}</span>
                    <span className="recent-item-target">{scan.target}</span>
                  </div>
                  <div className="recent-item-meta">
                    <span className={`badge badge-${scan.status}`}>{scan.status}</span>
                    <span className="recent-item-date">
                      {format(new Date(scan.created_at), 'MMM dd, HH:mm')}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="recent-section">
          <div className="section-header">
            <h2>Recent Vulnerability Scans</h2>
            <Link to="/vulnerabilities" className="view-all-link">View All</Link>
          </div>
          {vulnScans.length === 0 ? (
            <div className="empty-state-small">
              <p>No vulnerability scans yet</p>
              <Link to="/new-vuln-scan" className="btn btn-secondary btn-sm">Create Scan</Link>
            </div>
          ) : (
            <div className="recent-list">
              {vulnScans.map(scan => (
                <Link to={`/vuln-scan/${scan.id}`} key={scan.id} className="recent-item">
                  <div className="recent-item-info">
                    <span className="recent-item-name">{scan.name}</span>
                    <span className="recent-item-target">{scan.target}</span>
                  </div>
                  <div className="recent-item-meta">
                    <span className={`badge badge-${scan.status}`}>{scan.status}</span>
                    <span className="recent-item-date">
                      {format(new Date(scan.created_at), 'MMM dd, HH:mm')}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
