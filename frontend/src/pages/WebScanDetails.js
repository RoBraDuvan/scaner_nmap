import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './WebScanDetails.css';

function WebScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState('results');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScanData();
    const interval = setInterval(loadScanData, 3000);
    return () => clearInterval(interval);
  }, [id]);

  const loadScanData = async () => {
    try {
      const [scanRes, resultsRes, logsRes, statsRes] = await Promise.all([
        api.get(`/webscans/${id}`),
        api.get(`/webscans/${id}/results`),
        api.get(`/webscans/${id}/logs`),
        api.get(`/webscans/${id}/stats`)
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

  const cancelScan = async () => {
    if (!scan) return;

    try {
      await api.post(`/webscans/${id}/cancel`);
      loadScanData();
    } catch (error) {
      console.error('Error cancelling scan:', error);
      alert('Failed to cancel scan');
    }
  };

  const deleteScan = async () => {
    if (!window.confirm('Are you sure you want to delete this scan?')) return;

    try {
      await api.delete(`/webscans/${id}`);
      navigate('/webscans');
    } catch (error) {
      console.error('Error deleting scan:', error);
      alert('Failed to delete scan');
    }
  };

  const getToolBadgeClass = (tool) => {
    switch (tool) {
      case 'ffuf': return 'tool-ffuf';
      case 'gowitness': return 'tool-gowitness';
      case 'testssl': return 'tool-testssl';
      default: return '';
    }
  };

  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'severity-critical';
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      case 'low': return 'severity-low';
      case 'info': return 'severity-info';
      default: return '';
    }
  };

  if (loading) {
    return <div className="loading">Loading scan details...</div>;
  }

  if (!scan) {
    return <div className="error-message">Scan not found</div>;
  }

  const getToolLabel = (tool) => {
    switch (tool) {
      case 'ffuf': return 'FFUF';
      case 'gowitness': return 'GoWitness';
      case 'testssl': return 'TestSSL';
      default: return tool;
    }
  };

  return (
    <div className="webscan-details">
      <div className="page-header">
        <div className="header-left">
          <Link to="/webscans" className="back-link">← Back to Web Scans</Link>
          <h1>{scan.name}</h1>
          <div className="scan-meta">
            <span className={`type-badge ${getToolBadgeClass(scan.tool)}`}>
              {getToolLabel(scan.tool)}
            </span>
            <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
            <span className="target">{scan.target}</span>
          </div>
        </div>
        <div className="header-actions">
          {(scan.status === 'pending' || scan.status === 'running') && (
            <button className="btn btn-warning" onClick={cancelScan}>
              Cancel Scan
            </button>
          )}
          {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
            <button className="btn btn-danger" onClick={deleteScan}>
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
          <div className="stat-value">{stats?.total || 0}</div>
          <div className="stat-label">Total Results</div>
        </div>
        {scan.tool === 'ffuf' && stats?.by_status_code && (
          Object.entries(stats.by_status_code).slice(0, 3).map(([code, count]) => (
            <div key={code} className="stat-card">
              <div className="stat-value">{count}</div>
              <div className="stat-label">HTTP {code}</div>
            </div>
          ))
        )}
        {scan.tool === 'gowitness' && (
          <div className="stat-card">
            <div className="stat-value">{stats?.screenshots || 0}</div>
            <div className="stat-label">Screenshots</div>
          </div>
        )}
        {scan.tool === 'testssl' && stats?.by_severity && (
          Object.entries(stats.by_severity).map(([severity, count]) => (
            <div key={severity} className={`stat-card ${getSeverityClass(severity)}`}>
              <div className="stat-value">{count}</div>
              <div className="stat-label">{severity}</div>
            </div>
          ))
        )}
      </div>

      {scan.error_message && (
        <div className="error-message">{scan.error_message}</div>
      )}

      <div className="tabs">
        <button
          className={`tab ${activeTab === 'results' ? 'active' : ''}`}
          onClick={() => setActiveTab('results')}
        >
          Results ({results.length})
        </button>
        <button
          className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          Logs ({logs.length})
        </button>
        {scan.configuration && (
          <button
            className={`tab ${activeTab === 'config' ? 'active' : ''}`}
            onClick={() => setActiveTab('config')}
          >
            Configuration
          </button>
        )}
      </div>

      {activeTab === 'results' && (
        <div className="results-section">
          {results.length === 0 ? (
            <div className="empty-state">No results yet</div>
          ) : (
            <div className="results-list">
              {/* ffuf results */}
              {scan.tool === 'ffuf' && results.map(result => (
                <div key={result.id} className="result-card card">
                  <div className="result-header">
                    <a href={result.url} target="_blank" rel="noopener noreferrer" className="result-url">
                      {result.url}
                    </a>
                    <span className={`status-code status-${Math.floor(result.status_code / 100)}xx`}>
                      {result.status_code}
                    </span>
                  </div>
                  <div className="result-meta">
                    <span>Size: {result.content_length} bytes</span>
                    <span>Words: {result.words}</span>
                    <span>Lines: {result.lines}</span>
                    {result.content_type && <span>Type: {result.content_type}</span>}
                    {result.redirect_url && <span>→ {result.redirect_url}</span>}
                  </div>
                </div>
              ))}

              {/* gowitness results */}
              {scan.tool === 'gowitness' && (
                <div className="screenshots-grid">
                  {results.map(result => (
                    <div key={result.id} className="screenshot-card card">
                      {result.screenshot_b64 && (
                        <img
                          src={`data:image/png;base64,${result.screenshot_b64}`}
                          alt={result.url}
                          className="screenshot-img"
                        />
                      )}
                      <div className="screenshot-info">
                        <a href={result.url} target="_blank" rel="noopener noreferrer">
                          {result.url}
                        </a>
                        {result.title && <p className="page-title">{result.title}</p>}
                        {result.status_code > 0 && (
                          <span className={`status-code status-${Math.floor(result.status_code / 100)}xx`}>
                            {result.status_code}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* testssl results */}
              {scan.tool === 'testssl' && results.map(result => (
                <div key={result.id} className={`result-card card finding-${result.severity?.toLowerCase()}`}>
                  <div className="result-header">
                    <span className="finding-id">{result.finding_id}</span>
                    <span className={`severity-badge ${getSeverityClass(result.severity)}`}>
                      {result.severity}
                    </span>
                  </div>
                  <p className="finding-text">{result.finding_text}</p>
                  {result.cve && <span className="cve-badge">CVE: {result.cve}</span>}
                  {result.cwe && <span className="cwe-badge">CWE: {result.cwe}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="logs-section">
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

      {activeTab === 'config' && scan.configuration && (
        <div className="config-section card">
          <h3>Scan Configuration</h3>
          <pre className="config-json">
            {JSON.stringify(scan.configuration, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default WebScanDetails;
