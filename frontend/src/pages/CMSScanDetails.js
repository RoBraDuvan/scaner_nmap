import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './CMSScanDetails.css';

function CMSScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState({ cms: [], technologies: [], wpscan: [] });
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('cms');

  const loadScanData = async () => {
    try {
      const [scanRes, resultsRes, logsRes] = await Promise.all([
        api.get(`/cmsscans/${id}`),
        api.get(`/cmsscans/${id}/results`),
        api.get(`/cmsscans/${id}/logs`)
      ]);
      setScan(scanRes.data);
      setResults(resultsRes.data || { cms: [], technologies: [], wpscan: [] });
      setLogs(logsRes.data || []);
    } catch (error) {
      console.error('Error loading scan data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScanData();
    const interval = setInterval(() => {
      if (scan?.status === 'running' || scan?.status === 'pending') {
        loadScanData();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [id, scan?.status]);

  const handleDelete = async () => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      try {
        await api.delete(`/cmsscans/${id}`);
        navigate('/cms-scans');
      } catch (error) {
        console.error('Error deleting scan:', error);
      }
    }
  };

  const handleCancel = async () => {
    try {
      await api.post(`/cmsscans/${id}/cancel`);
      loadScanData();
    } catch (error) {
      console.error('Error cancelling scan:', error);
    }
  };

  const getScanTypeLabel = (type) => {
    switch (type) {
      case 'whatweb': return 'WhatWeb';
      case 'cmseek': return 'CMSeeK';
      case 'wpscan': return 'WPScan';
      case 'full': return 'Full Scan';
      default: return type;
    }
  };

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'cms': return '📝';
      case 'framework': return '🔧';
      case 'server': return '🖥️';
      case 'language': return '💻';
      case 'plugin': return '🔌';
      case 'theme': return '🎨';
      case 'cdn': return '🌐';
      default: return '📦';
    }
  };

  if (loading) {
    return <div className="loading">Loading scan details...</div>;
  }

  if (!scan) {
    return <div className="error">Scan not found</div>;
  }

  const cmsResults = results.cms || [];
  const technologies = results.technologies || [];
  const wpscanResults = results.wpscan || [];

  // Group technologies by category
  const techByCategory = technologies.reduce((acc, tech) => {
    if (!acc[tech.category]) {
      acc[tech.category] = [];
    }
    acc[tech.category].push(tech);
    return acc;
  }, {});

  return (
    <div className="cms-scan-details">
      <div className="page-header">
        <div className="header-left">
          <Link to="/cms-scans" className="back-link">← Back to CMS Scans</Link>
          <h1>{scan.name}</h1>
          <div className="scan-meta">
            <span className={`type-badge type-${scan.scan_type}`}>
              {getScanTypeLabel(scan.scan_type)}
            </span>
            <span className={`status-badge status-${scan.status}`}>
              {scan.status}
            </span>
            <span className="target">{scan.target}</span>
          </div>
        </div>
        <div className="header-actions">
          {scan.status === 'running' && (
            <button className="btn btn-warning" onClick={handleCancel}>
              Cancel Scan
            </button>
          )}
          {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
            <button className="btn btn-danger" onClick={handleDelete}>
              Delete
            </button>
          )}
        </div>
      </div>

      {/* Progress */}
      {(scan.status === 'running' || scan.status === 'pending') && (
        <div className="progress-section card">
          <div className="progress-bar-large">
            <div className="progress-fill" style={{ width: `${scan.progress}%` }}></div>
            <span className="progress-text">{scan.progress}%</span>
          </div>
          <p className="progress-status">
            {scan.status === 'pending' ? 'Waiting to start...' : 'Scanning in progress...'}
          </p>
        </div>
      )}

      {/* Stats Summary */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{cmsResults.length}</div>
          <div className="stat-label">CMS Detected</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{technologies.length}</div>
          <div className="stat-label">Technologies</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            {wpscanResults.reduce((acc, r) => acc + (r.plugins?.length || 0), 0)}
          </div>
          <div className="stat-label">Plugins Found</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            {wpscanResults.reduce((acc, r) => acc + (r.vulnerabilities?.length || 0), 0)}
          </div>
          <div className="stat-label">Vulnerabilities</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs">
        <button
          className={`tab ${activeTab === 'cms' ? 'active' : ''}`}
          onClick={() => setActiveTab('cms')}
        >
          CMS Results ({cmsResults.length})
        </button>
        <button
          className={`tab ${activeTab === 'tech' ? 'active' : ''}`}
          onClick={() => setActiveTab('tech')}
        >
          Technologies ({technologies.length})
        </button>
        {wpscanResults.length > 0 && (
          <button
            className={`tab ${activeTab === 'wpscan' ? 'active' : ''}`}
            onClick={() => setActiveTab('wpscan')}
          >
            WordPress Details
          </button>
        )}
        <button
          className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          Logs ({logs.length})
        </button>
      </div>

      {/* CMS Results Tab */}
      {activeTab === 'cms' && (
        <div className="tab-content card">
          {cmsResults.length === 0 ? (
            <div className="empty-tab">
              <p>No CMS platforms detected yet</p>
            </div>
          ) : (
            <div className="cms-results">
              {cmsResults.map((cms, index) => (
                <div key={index} className="cms-item">
                  <div className="cms-header">
                    <h3>{cms.cms_name}</h3>
                    {cms.cms_version && (
                      <span className="version-badge">v{cms.cms_version}</span>
                    )}
                  </div>
                  <div className="cms-details">
                    <span className="confidence">
                      Confidence: {cms.confidence}%
                    </span>
                    <span className="source">
                      Source: {cms.source}
                    </span>
                  </div>
                  {cms.details && (
                    <p className="cms-extra">{cms.details}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Technologies Tab */}
      {activeTab === 'tech' && (
        <div className="tab-content card">
          {technologies.length === 0 ? (
            <div className="empty-tab">
              <p>No technologies detected yet</p>
            </div>
          ) : (
            <div className="tech-categories">
              {Object.entries(techByCategory).map(([category, techs]) => (
                <div key={category} className="tech-category">
                  <h3>
                    {getCategoryIcon(category)} {category.charAt(0).toUpperCase() + category.slice(1)}
                  </h3>
                  <div className="tech-list">
                    {techs.map((tech, index) => (
                      <div key={index} className="tech-item">
                        <span className="tech-name">{tech.name}</span>
                        {tech.version && (
                          <span className="tech-version">v{tech.version}</span>
                        )}
                        <span className="tech-confidence">{tech.confidence}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* WPScan Tab */}
      {activeTab === 'wpscan' && wpscanResults.length > 0 && (
        <div className="tab-content card">
          {wpscanResults.map((wp, index) => (
            <div key={index} className="wpscan-result">
              <div className="wp-header">
                <h3>WordPress Analysis</h3>
                {wp.wp_version && (
                  <span className="version-badge">WordPress {wp.wp_version}</span>
                )}
              </div>

              {wp.main_theme && (
                <div className="wp-section">
                  <h4>Theme</h4>
                  <p>{wp.main_theme} {wp.theme_version && `(v${wp.theme_version})`}</p>
                </div>
              )}

              {wp.plugins && wp.plugins.length > 0 && (
                <div className="wp-section">
                  <h4>Plugins ({wp.plugins.length})</h4>
                  <div className="plugin-list">
                    {wp.plugins.map((plugin, pIndex) => (
                      <div key={pIndex} className={`plugin-item ${plugin.outdated ? 'outdated' : ''}`}>
                        <span className="plugin-name">{plugin.name}</span>
                        {plugin.version && (
                          <span className="plugin-version">v{plugin.version}</span>
                        )}
                        {plugin.outdated && (
                          <span className="outdated-badge">Outdated</span>
                        )}
                        {plugin.vulnerabilities > 0 && (
                          <span className="vuln-badge">{plugin.vulnerabilities} vuln</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {wp.users && wp.users.length > 0 && (
                <div className="wp-section">
                  <h4>Users ({wp.users.length})</h4>
                  <div className="user-list">
                    {wp.users.map((user, uIndex) => (
                      <span key={uIndex} className="user-tag">
                        {user.username}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {wp.vulnerabilities && wp.vulnerabilities.length > 0 && (
                <div className="wp-section vulnerabilities">
                  <h4>Vulnerabilities ({wp.vulnerabilities.length})</h4>
                  <div className="vuln-list">
                    {wp.vulnerabilities.map((vuln, vIndex) => (
                      <div key={vIndex} className="vuln-item">
                        <div className="vuln-title">{vuln.title}</div>
                        <div className="vuln-meta">
                          <span className="vuln-component">{vuln.component}</span>
                          {vuln.type && <span className="vuln-type">{vuln.type}</span>}
                          {vuln.cve && <span className="vuln-cve">{vuln.cve}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Logs Tab */}
      {activeTab === 'logs' && (
        <div className="tab-content card">
          {logs.length === 0 ? (
            <div className="empty-tab">
              <p>No logs yet</p>
            </div>
          ) : (
            <div className="logs-container">
              {logs.map((log, index) => (
                <div key={index} className={`log-entry log-${log.level}`}>
                  <span className="log-time">
                    {format(new Date(log.created_at), 'HH:mm:ss')}
                  </span>
                  <span className={`log-level ${log.level}`}>{log.level}</span>
                  <span className="log-message">{log.message}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default CMSScanDetails;
