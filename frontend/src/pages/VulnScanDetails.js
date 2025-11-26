import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { format } from 'date-fns';
import axios from 'axios';
import './VulnScanDetails.css';

// Use relative URLs - nginx will proxy /api/ to gateway
const goApi = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

function VulnScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState('results');
  const [loading, setLoading] = useState(true);
  const [expandedVulns, setExpandedVulns] = useState({});
  const [severityFilter, setSeverityFilter] = useState('all');

  useEffect(() => {
    loadScanData();
    const interval = setInterval(loadScanData, 3000);
    return () => clearInterval(interval);
  }, [id]);

  const loadScanData = async () => {
    try {
      const [scanRes, resultsRes, logsRes, statsRes] = await Promise.all([
        goApi.get(`/vulnerabilities/${id}`),
        goApi.get(`/vulnerabilities/${id}/results`),
        goApi.get(`/vulnerabilities/${id}/logs`),
        goApi.get(`/vulnerabilities/${id}/stats`)
      ]);

      setScan(scanRes.data);
      setResults(resultsRes.data || []);
      setLogs(logsRes.data || []);
      setStats(statsRes.data);
    } catch (error) {
      console.error('Error loading scan data:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleVuln = (vulnId) => {
    setExpandedVulns(prev => ({
      ...prev,
      [vulnId]: !prev[vulnId]
    }));
  };

  const filteredResults = severityFilter === 'all'
    ? results
    : results.filter(v => v.severity === severityFilter);

  const getSeverityOrder = (severity) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[severity] ?? 5;
  };

  const sortedResults = [...filteredResults].sort(
    (a, b) => getSeverityOrder(a.severity) - getSeverityOrder(b.severity)
  );

  if (loading) {
    return <div className="loading">Loading vulnerability scan details...</div>;
  }

  if (!scan) {
    return <div className="error-message">Scan not found</div>;
  }

  return (
    <div className="vuln-scan-details">
      <div className="page-header">
        <div className="header-left">
          <Link to="/vulnerabilities" className="back-link">← Back to Vulnerability Scans</Link>
          <h1>{scan.name}</h1>
          <div className="scan-meta">
            <span className="type-badge type-nuclei">Nuclei</span>
            <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
            <span className="target">{scan.target}</span>
          </div>
        </div>
        <div className="header-actions">
          {(scan.status === 'pending' || scan.status === 'running') && (
            <button className="btn btn-warning" onClick={() => {}}>
              Cancel Scan
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
        <div className="stat-card severity-critical">
          <div className="stat-value">{stats?.by_severity?.critical || 0}</div>
          <div className="stat-label">Critical</div>
        </div>
        <div className="stat-card severity-high">
          <div className="stat-value">{stats?.by_severity?.high || 0}</div>
          <div className="stat-label">High</div>
        </div>
        <div className="stat-card severity-medium">
          <div className="stat-value">{stats?.by_severity?.medium || 0}</div>
          <div className="stat-label">Medium</div>
        </div>
        <div className="stat-card severity-low">
          <div className="stat-value">{stats?.by_severity?.low || 0}</div>
          <div className="stat-label">Low</div>
        </div>
        <div className="stat-card severity-info">
          <div className="stat-value">{stats?.by_severity?.info || 0}</div>
          <div className="stat-label">Info</div>
        </div>
      </div>

      {scan.error_message && (
        <div className="error-message">{scan.error_message}</div>
      )}

      <div className="tabs">
        <button
          className={`tab ${activeTab === 'results' ? 'active' : ''}`}
          onClick={() => setActiveTab('results')}
        >
          Vulnerabilities ({results.length})
        </button>
        <button
          className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          Logs ({logs.length})
        </button>
      </div>

      {activeTab === 'results' && (
        <div className="results-section">
          {results.length > 0 && (
            <div className="vuln-filter-bar">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          )}

          {sortedResults.length === 0 ? (
            <div className="no-vulns">
              {results.length === 0
                ? 'No vulnerabilities found'
                : 'No vulnerabilities match the selected filter'}
            </div>
          ) : (
            <div className="vulns-list">
              {sortedResults.map(vuln => (
                <div key={vuln.id} className="vuln-card">
                  <div
                    className="vuln-card-header"
                    onClick={() => toggleVuln(vuln.id)}
                  >
                    <div className="vuln-card-title">
                      <span className={`severity-badge ${vuln.severity}`}>
                        {vuln.severity}
                      </span>
                      <h3>{vuln.template_name}</h3>
                    </div>
                    <span className={`expand-icon ${expandedVulns[vuln.id] ? 'expanded' : ''}`}>
                      ▼
                    </span>
                  </div>

                  {expandedVulns[vuln.id] && (
                    <div className="vuln-card-body">
                      <div className="vuln-info-grid">
                        <div className="vuln-info-item">
                          <span className="label">Template ID</span>
                          <span className="value">{vuln.template_id}</span>
                        </div>
                        <div className="vuln-info-item">
                          <span className="label">Type</span>
                          <span className="value">{vuln.type}</span>
                        </div>
                        <div className="vuln-info-item">
                          <span className="label">Host</span>
                          <span className="value">{vuln.host}</span>
                        </div>
                        {vuln.matched_at && (
                          <div className="vuln-info-item">
                            <span className="label">Matched At</span>
                            <span className="value">{vuln.matched_at}</span>
                          </div>
                        )}
                      </div>

                      {vuln.metadata?.description && (
                        <div className="vuln-info-item" style={{ marginTop: '16px' }}>
                          <span className="label">Description</span>
                          <span className="value">{vuln.metadata.description}</span>
                        </div>
                      )}

                      {vuln.metadata?.tags && vuln.metadata.tags.length > 0 && (
                        <div className="vuln-info-item" style={{ marginTop: '16px' }}>
                          <span className="label">Tags</span>
                          <div className="vuln-tags-list">
                            {vuln.metadata.tags.map(tag => (
                              <span key={tag} className="vuln-tag">{tag}</span>
                            ))}
                          </div>
                        </div>
                      )}

                      {vuln.metadata?.reference && vuln.metadata.reference.length > 0 && (
                        <div className="vuln-references">
                          <h4>References</h4>
                          <ul>
                            {vuln.metadata.reference.map((ref, idx) => (
                              <li key={idx}>
                                <a href={ref} target="_blank" rel="noopener noreferrer">
                                  {ref}
                                </a>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {vuln.curl_command && (
                        <div className="vuln-curl-command">
                          <h4>cURL Command</h4>
                          <pre className="curl-code">{vuln.curl_command}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="logs-section">
          <h2>Scan Logs</h2>
          {logs.length === 0 ? (
            <div className="empty-state">No logs yet</div>
          ) : (
            <div className="logs-list card">
              {logs.map(log => (
                <div key={log.id} className={`log-entry log-${log.level}`}>
                  <span className="log-time">
                    {format(new Date(log.created_at), 'HH:mm:ss')}
                  </span>
                  <span className="log-level">{log.level}</span>
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

export default VulnScanDetails;
