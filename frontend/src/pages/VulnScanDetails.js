import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { format } from 'date-fns';
import axios from 'axios';
import './VulnScanDetails.css';

const GO_API_URL = process.env.REACT_APP_GO_API_URL || 'http://localhost:8001';

const goApi = axios.create({
  baseURL: `${GO_API_URL}/api`,
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
    <div className="scan-details">
      <div className="vuln-details-header">
        <div className="header-left">
          <button className="btn btn-secondary btn-back" onClick={() => navigate('/vulnerabilities')}>
            ← Back
          </button>
          <div className="header-title">
            <h1>{scan.name}</h1>
            <span className={`badge badge-${scan.status}`}>{scan.status}</span>
          </div>
        </div>
      </div>

      {stats && stats.total > 0 && (
        <div className="vuln-summary-stats">
          {stats.by_severity?.critical > 0 && (
            <div className="vuln-stat critical">
              <span className="count">{stats.by_severity.critical}</span>
              <span className="label">Critical</span>
            </div>
          )}
          {stats.by_severity?.high > 0 && (
            <div className="vuln-stat high">
              <span className="count">{stats.by_severity.high}</span>
              <span className="label">High</span>
            </div>
          )}
          {stats.by_severity?.medium > 0 && (
            <div className="vuln-stat medium">
              <span className="count">{stats.by_severity.medium}</span>
              <span className="label">Medium</span>
            </div>
          )}
          {stats.by_severity?.low > 0 && (
            <div className="vuln-stat low">
              <span className="count">{stats.by_severity.low}</span>
              <span className="label">Low</span>
            </div>
          )}
          {stats.by_severity?.info > 0 && (
            <div className="vuln-stat info">
              <span className="count">{stats.by_severity.info}</span>
              <span className="label">Info</span>
            </div>
          )}
        </div>
      )}

      <div className="scan-meta card">
        <div className="vuln-meta-grid">
          <div className="meta-item">
            <span className="meta-label">Target</span>
            <span className="meta-value">{scan.target}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Created</span>
            <span className="meta-value">
              {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm:ss')}
            </span>
          </div>
          {scan.started_at && (
            <div className="meta-item">
              <span className="meta-label">Started</span>
              <span className="meta-value">
                {format(new Date(scan.started_at), 'MMM dd, yyyy HH:mm:ss')}
              </span>
            </div>
          )}
          {scan.completed_at && (
            <div className="meta-item">
              <span className="meta-label">Completed</span>
              <span className="meta-value">
                {format(new Date(scan.completed_at), 'MMM dd, yyyy HH:mm:ss')}
              </span>
            </div>
          )}
          <div className="meta-item">
            <span className="meta-label">Findings</span>
            <span className="meta-value">{stats?.total || 0}</span>
          </div>
        </div>

        {scan.status === 'running' && (
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${scan.progress}%` }} />
          </div>
        )}

        {scan.error_message && (
          <div className="error-message">{scan.error_message}</div>
        )}
      </div>

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
