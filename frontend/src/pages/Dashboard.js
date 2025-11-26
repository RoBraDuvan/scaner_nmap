import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './Dashboard.css';

function Dashboard() {
  const [networkScans, setNetworkScans] = useState([]);
  const [webScans, setWebScans] = useState([]);
  const [vulnScans, setVulnScans] = useState([]);
  const [reconScans, setReconScans] = useState([]);
  const [apiScans, setApiScans] = useState([]);
  const [cmsScans, setCmsScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalNetworkScans: 0,
    runningNetworkScans: 0,
    completedNetworkScans: 0,
    totalWebScans: 0,
    runningWebScans: 0,
    completedWebScans: 0,
    totalVulnScans: 0,
    runningVulnScans: 0,
    completedVulnScans: 0,
    totalReconScans: 0,
    runningReconScans: 0,
    completedReconScans: 0,
    totalApiScans: 0,
    runningApiScans: 0,
    completedApiScans: 0,
    totalCmsScans: 0,
    runningCmsScans: 0,
    completedCmsScans: 0,
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
      const [networkRes, webRes, vulnRes, reconRes, apiRes, cmsRes] = await Promise.all([
        api.get('/scans/'),
        api.get('/webscans/'),
        api.get('/vulnerabilities/'),
        api.get('/recon/'),
        api.get('/apiscans/').catch(() => ({ data: [] })),
        api.get('/cmsscans/').catch(() => ({ data: [] }))
      ]);

      const networkData = networkRes.data || [];
      const webData = webRes.data || [];
      const vulnData = vulnRes.data || [];
      const reconData = reconRes.data || [];
      const apiData = apiRes.data || [];
      const cmsData = cmsRes.data || [];

      setNetworkScans(networkData.slice(0, 5));
      setWebScans(webData.slice(0, 5));
      setVulnScans(vulnData.slice(0, 5));
      setReconScans(reconData.slice(0, 5));
      setApiScans(apiData.slice(0, 5));
      setCmsScans(cmsData.slice(0, 5));

      // Calculate stats
      const networkRunning = networkData.filter(s => s.status === 'running').length;
      const networkCompleted = networkData.filter(s => s.status === 'completed').length;
      const webRunning = webData.filter(s => s.status === 'running').length;
      const webCompleted = webData.filter(s => s.status === 'completed').length;
      const vulnRunning = vulnData.filter(s => s.status === 'running').length;
      const vulnCompleted = vulnData.filter(s => s.status === 'completed').length;
      const reconRunning = reconData.filter(s => s.status === 'running').length;
      const reconCompleted = reconData.filter(s => s.status === 'completed').length;
      const apiRunning = apiData.filter(s => s.status === 'running').length;
      const apiCompleted = apiData.filter(s => s.status === 'completed').length;
      const cmsRunning = cmsData.filter(s => s.status === 'running').length;
      const cmsCompleted = cmsData.filter(s => s.status === 'completed').length;

      // Load vulnerability stats for completed scans
      let totalVulns = 0;
      let criticalVulns = 0;
      let highVulns = 0;

      const completedVulnScans = vulnData.filter(s => s.status === 'completed');
      for (const scan of completedVulnScans.slice(0, 10)) {
        try {
          const statsRes = await api.get(`/vulnerabilities/${scan.id}/stats`);
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
        totalWebScans: webData.length,
        runningWebScans: webRunning,
        completedWebScans: webCompleted,
        totalVulnScans: vulnData.length,
        runningVulnScans: vulnRunning,
        completedVulnScans: vulnCompleted,
        totalReconScans: reconData.length,
        runningReconScans: reconRunning,
        completedReconScans: reconCompleted,
        totalApiScans: apiData.length,
        runningApiScans: apiRunning,
        completedApiScans: apiCompleted,
        totalCmsScans: cmsData.length,
        runningCmsScans: cmsRunning,
        completedCmsScans: cmsCompleted,
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

  const getToolIcon = (tool) => {
    switch (tool) {
      case 'ffuf': return '🔍';
      case 'gowitness': return '📸';
      case 'testssl': return '🔒';
      default: return '🛠️';
    }
  };

  const getScannerIcon = (scanner) => {
    switch (scanner) {
      case 'nmap': return '🔍';
      case 'masscan': return '⚡';
      case 'dns': return '🌐';
      default: return '🔍';
    }
  };

  const getReconTypeIcon = (scanType) => {
    switch (scanType) {
      case 'subdomain': return '🌐';
      case 'whois': return '📋';
      case 'dns': return '🔗';
      case 'tech': return '🔧';
      default: return '🔍';
    }
  };

  const getApiScanTypeIcon = (scanType) => {
    switch (scanType) {
      case 'kiterunner': return 'K';
      case 'arjun': return 'A';
      case 'graphql': return 'G';
      case 'swagger': return 'S';
      case 'full': return 'F';
      default: return '?';
    }
  };

  const getCmsScanTypeIcon = (scanType) => {
    switch (scanType) {
      case 'whatweb': return 'W';
      case 'cmseek': return 'C';
      case 'wpscan': return 'P';
      case 'full': return 'F';
      default: return '?';
    }
  };

  if (loading) {
    return <div className="loading">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard home-dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <span className="dashboard-subtitle">Security Scanner Overview</span>
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
          <div className="stat-icon web-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
              <line x1="3" y1="9" x2="21" y2="9"/>
              <line x1="9" y1="21" x2="9" y2="9"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.totalWebScans}</span>
            <span className="stat-label">Web Scans</span>
            <span className="stat-detail">{stats.runningWebScans} running, {stats.completedWebScans} completed</span>
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
          <div className="stat-icon recon-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"/>
              <path d="M21 21l-4.35-4.35"/>
              <path d="M11 8v6M8 11h6"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.totalReconScans}</span>
            <span className="stat-label">Recon Scans</span>
            <span className="stat-detail">{stats.runningReconScans} running, {stats.completedReconScans} completed</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon api-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
              <path d="M8 10h.01M12 10h.01M16 10h.01"/>
              <path d="M8 14h8"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.totalApiScans}</span>
            <span className="stat-label">API Discovery</span>
            <span className="stat-detail">{stats.runningApiScans} running, {stats.completedApiScans} completed</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon cms-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2L2 7l10 5 10-5-10-5z"/>
              <path d="M2 17l10 5 10-5"/>
              <path d="M2 12l10 5 10-5"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.totalCmsScans}</span>
            <span className="stat-label">CMS Detection</span>
            <span className="stat-detail">{stats.runningCmsScans} running, {stats.completedCmsScans} completed</span>
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
            <div className="action-icon network">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 8v8M8 12h8"/>
              </svg>
            </div>
            <span className="action-title">New Network Scan</span>
            <span className="action-desc">Nmap, Masscan, DNS</span>
          </Link>
          <Link to="/new-webscan" className="action-card">
            <div className="action-icon web">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                <path d="M12 8v8M8 12h8"/>
              </svg>
            </div>
            <span className="action-title">New Web Scan</span>
            <span className="action-desc">ffuf, Gowitness, testssl</span>
          </Link>
          <Link to="/new-vuln-scan" className="action-card">
            <div className="action-icon vuln">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M12 8v4M12 16h.01"/>
              </svg>
            </div>
            <span className="action-title">New Vuln Scan</span>
            <span className="action-desc">Nuclei templates</span>
          </Link>
          <Link to="/new-recon" className="action-card">
            <div className="action-icon recon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="M21 21l-4.35-4.35"/>
                <path d="M11 8v6M8 11h6"/>
              </svg>
            </div>
            <span className="action-title">New Recon Scan</span>
            <span className="action-desc">Subdomains, WHOIS, DNS, Tech</span>
          </Link>
          <Link to="/new-api-scan" className="action-card">
            <div className="action-icon api">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                <path d="M12 8v8M8 12h8"/>
              </svg>
            </div>
            <span className="action-title">New API Scan</span>
            <span className="action-desc">Kiterunner, Arjun, GraphQL</span>
          </Link>
          <Link to="/new-cms-scan" className="action-card">
            <div className="action-icon cms">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 2L2 7l10 5 10-5-10-5z"/>
                <path d="M2 17l10 5 10-5"/>
                <path d="M2 12l10 5 10-5"/>
              </svg>
            </div>
            <span className="action-title">New CMS Scan</span>
            <span className="action-desc">WhatWeb, CMSeeK, WPScan</span>
          </Link>
        </div>
      </div>

      {/* Recent Scans - 3 columns */}
      <div className="recent-sections">
        {/* Network Scans */}
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
                    <span className="recent-item-name">
                      <span className="item-icon">{getScannerIcon(scan.scanner)}</span>
                      {scan.name}
                    </span>
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

        {/* Web Scans */}
        <div className="recent-section">
          <div className="section-header">
            <h2>Recent Web Scans</h2>
            <Link to="/webscans" className="view-all-link">View All</Link>
          </div>
          {webScans.length === 0 ? (
            <div className="empty-state-small">
              <p>No web scans yet</p>
              <Link to="/new-webscan" className="btn btn-secondary btn-sm">Create Scan</Link>
            </div>
          ) : (
            <div className="recent-list">
              {webScans.map(scan => (
                <Link to={`/webscan/${scan.id}`} key={scan.id} className="recent-item">
                  <div className="recent-item-info">
                    <span className="recent-item-name">
                      <span className="item-icon">{getToolIcon(scan.tool)}</span>
                      {scan.name}
                    </span>
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

        {/* Vulnerability Scans */}
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
                    <span className="recent-item-name">
                      <span className="item-icon">🛡️</span>
                      {scan.name}
                    </span>
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

        {/* Recon Scans */}
        <div className="recent-section">
          <div className="section-header">
            <h2>Recent Recon Scans</h2>
            <Link to="/recon" className="view-all-link">View All</Link>
          </div>
          {reconScans.length === 0 ? (
            <div className="empty-state-small">
              <p>No recon scans yet</p>
              <Link to="/new-recon" className="btn btn-secondary btn-sm">Create Scan</Link>
            </div>
          ) : (
            <div className="recent-list">
              {reconScans.map(scan => (
                <Link to={`/recon/${scan.id}`} key={scan.id} className="recent-item">
                  <div className="recent-item-info">
                    <span className="recent-item-name">
                      <span className="item-icon">{getReconTypeIcon(scan.scan_type)}</span>
                      {scan.name}
                    </span>
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

        {/* API Discovery Scans */}
        <div className="recent-section">
          <div className="section-header">
            <h2>Recent API Scans</h2>
            <Link to="/api-scans" className="view-all-link">View All</Link>
          </div>
          {apiScans.length === 0 ? (
            <div className="empty-state-small">
              <p>No API scans yet</p>
              <Link to="/new-api-scan" className="btn btn-secondary btn-sm">Create Scan</Link>
            </div>
          ) : (
            <div className="recent-list">
              {apiScans.map(scan => (
                <Link to={`/api-scans/${scan.id}`} key={scan.id} className="recent-item">
                  <div className="recent-item-info">
                    <span className="recent-item-name">
                      <span className="item-icon api-type-icon">{getApiScanTypeIcon(scan.scan_type)}</span>
                      {scan.name}
                    </span>
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

        {/* CMS Detection Scans */}
        <div className="recent-section">
          <div className="section-header">
            <h2>Recent CMS Scans</h2>
            <Link to="/cms-scans" className="view-all-link">View All</Link>
          </div>
          {cmsScans.length === 0 ? (
            <div className="empty-state-small">
              <p>No CMS scans yet</p>
              <Link to="/new-cms-scan" className="btn btn-secondary btn-sm">Create Scan</Link>
            </div>
          ) : (
            <div className="recent-list">
              {cmsScans.map(scan => (
                <Link to={`/cms-scans/${scan.id}`} key={scan.id} className="recent-item">
                  <div className="recent-item-info">
                    <span className="recent-item-name">
                      <span className="item-icon cms-type-icon">{getCmsScanTypeIcon(scan.scan_type)}</span>
                      {scan.name}
                    </span>
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
