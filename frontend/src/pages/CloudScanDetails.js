import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './CloudScanDetails.css';

function CloudScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('findings');
  const [severityFilter, setSeverityFilter] = useState('all');
  const logsEndRef = useRef(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [id]);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const loadData = async () => {
    try {
      const [scanRes, resultsRes, logsRes] = await Promise.all([
        api.get(`/cloudscans/${id}`),
        api.get(`/cloudscans/${id}/results`),
        api.get(`/cloudscans/${id}/logs`)
      ]);

      setScan(scanRes.data);
      setResults(resultsRes.data);
      setLogs(logsRes.data || []);
    } catch (error) {
      console.error('Error loading scan data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = async () => {
    try {
      await api.post(`/cloudscans/${id}/cancel`);
      loadData();
    } catch (error) {
      console.error('Error cancelling scan:', error);
    }
  };

  const handleDelete = async () => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      try {
        await api.delete(`/cloudscans/${id}`);
        navigate('/cloud-scans');
      } catch (error) {
        console.error('Error deleting scan:', error);
      }
    }
  };

  const getProviderIcon = (provider) => {
    switch (provider) {
      case 'aws': return '☁️';
      case 'azure': return '🔷';
      case 'gcp': return '🔶';
      case 'docker': return '🐳';
      default: return '☁️';
    }
  };

  const getSeverityClass = (severity) => {
    return `severity-${severity.toLowerCase()}`;
  };

  const filteredFindings = results?.findings?.filter(f => {
    if (severityFilter === 'all') return true;
    return f.severity === severityFilter;
  }) || [];

  if (loading) {
    return <div className="loading">Loading scan details...</div>;
  }

  if (!scan) {
    return <div className="error-state">Scan not found</div>;
  }

  return (
    <div className="cloud-scan-details">
      <div className="page-header">
        <div className="header-left">
          <Link to="/cloud-scans" className="back-link">← Back to Cloud Scans</Link>
          <h1>{scan.name}</h1>
          <div className="scan-meta">
            <span className={`provider-badge provider-${scan.provider}`}>
              {getProviderIcon(scan.provider)} {scan.provider.toUpperCase()}
            </span>
            <span className={`status-badge status-${scan.status}`}>
              {scan.status}
            </span>
            <span className="scan-type">{scan.scan_type}</span>
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

      {/* Progress bar for running scans */}
      {scan.status === 'running' && (
        <div className="progress-section card">
          <div className="progress-bar-large">
            <div className="progress-fill" style={{ width: `${scan.progress}%` }}></div>
            <span className="progress-text">{scan.progress}%</span>
          </div>
          <p className="progress-status">Scanning in progress...</p>
        </div>
      )}

      {/* Summary Section */}
      {results?.summary && (
        <div className="summary-section">
          <div className="summary-card card">
            <div className="summary-title">Total Findings</div>
            <div className="summary-value">{results.summary.total_findings}</div>
          </div>
          <div className="summary-card card severity-critical">
            <div className="summary-title">Critical</div>
            <div className="summary-value">{results.summary.critical}</div>
          </div>
          <div className="summary-card card severity-high">
            <div className="summary-title">High</div>
            <div className="summary-value">{results.summary.high}</div>
          </div>
          <div className="summary-card card severity-medium">
            <div className="summary-title">Medium</div>
            <div className="summary-value">{results.summary.medium}</div>
          </div>
          <div className="summary-card card severity-low">
            <div className="summary-title">Low</div>
            <div className="summary-value">{results.summary.low}</div>
          </div>
          <div className="summary-card card passed">
            <div className="summary-title">Passed</div>
            <div className="summary-value">{results.summary.passed}</div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="tabs">
        <button
          className={`tab ${activeTab === 'findings' ? 'active' : ''}`}
          onClick={() => setActiveTab('findings')}
        >
          Findings ({results?.findings?.length || 0})
        </button>
        <button
          className={`tab ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
          onClick={() => setActiveTab('vulnerabilities')}
        >
          Vulnerabilities ({results?.vulnerabilities?.length || 0})
        </button>
        <button
          className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          Logs ({logs.length})
        </button>
        <button
          className={`tab ${activeTab === 'info' ? 'active' : ''}`}
          onClick={() => setActiveTab('info')}
        >
          Info
        </button>
      </div>

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <div className="tab-content card">
          <div className="tab-toolbar">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="severity-filter"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
          </div>

          {filteredFindings.length === 0 ? (
            <div className="empty-state">
              <p>No findings to display</p>
            </div>
          ) : (
            <div className="findings-list">
              {filteredFindings.map(finding => (
                <div key={finding.id} className={`finding-item ${getSeverityClass(finding.severity)}`}>
                  <div className="finding-header">
                    <span className={`severity-badge ${getSeverityClass(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <span className={`status-badge status-${finding.status.toLowerCase()}`}>
                      {finding.status}
                    </span>
                    <span className="finding-service">{finding.service}</span>
                    {finding.region && <span className="finding-region">{finding.region}</span>}
                  </div>
                  <div className="finding-title">{finding.title}</div>
                  {finding.resource_id && (
                    <div className="finding-resource">
                      <strong>Resource:</strong> {finding.resource_arn || finding.resource_id}
                    </div>
                  )}
                  {finding.description && (
                    <div className="finding-description">{finding.description}</div>
                  )}
                  {finding.remediation && (
                    <div className="finding-remediation">
                      <strong>Remediation:</strong> {finding.remediation}
                    </div>
                  )}
                  {finding.compliance && finding.compliance.length > 0 && (
                    <div className="finding-compliance">
                      {finding.compliance.map((comp, i) => (
                        <span key={i} className="compliance-tag">{comp}</span>
                      ))}
                    </div>
                  )}
                  <div className="finding-source">Source: {finding.source}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Vulnerabilities Tab */}
      {activeTab === 'vulnerabilities' && (
        <div className="tab-content card">
          {results?.vulnerabilities?.length === 0 ? (
            <div className="empty-state">
              <p>No vulnerabilities found</p>
            </div>
          ) : (
            <table className="vulnerabilities-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Severity</th>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Fixed In</th>
                  <th>Title</th>
                </tr>
              </thead>
              <tbody>
                {results?.vulnerabilities?.map(vuln => (
                  <tr key={vuln.id}>
                    <td>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${vuln.vulnerability_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="cve-link"
                      >
                        {vuln.vulnerability_id}
                      </a>
                    </td>
                    <td>
                      <span className={`severity-badge ${getSeverityClass(vuln.severity)}`}>
                        {vuln.severity}
                      </span>
                    </td>
                    <td className="pkg-name">{vuln.pkg_name}</td>
                    <td className="version">{vuln.installed_version}</td>
                    <td className="version">{vuln.fixed_version || '-'}</td>
                    <td className="vuln-title" title={vuln.description}>
                      {vuln.title || vuln.description?.substring(0, 100)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Logs Tab */}
      {activeTab === 'logs' && (
        <div className="tab-content card logs-container">
          <div className="logs-list">
            {logs.map(log => (
              <div key={log.id} className={`log-entry log-${log.level}`}>
                <span className="log-time">
                  {format(new Date(log.created_at), 'HH:mm:ss')}
                </span>
                <span className={`log-level level-${log.level}`}>[{log.level.toUpperCase()}]</span>
                <span className="log-message">{log.message}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>
      )}

      {/* Info Tab */}
      {activeTab === 'info' && (
        <div className="tab-content card">
          <div className="info-grid">
            <div className="info-item">
              <label>Scan ID</label>
              <span className="monospace">{scan.id}</span>
            </div>
            <div className="info-item">
              <label>Provider</label>
              <span>{scan.provider.toUpperCase()}</span>
            </div>
            <div className="info-item">
              <label>Scan Type</label>
              <span>{scan.scan_type}</span>
            </div>
            <div className="info-item">
              <label>Target</label>
              <span className="monospace">{scan.target || '-'}</span>
            </div>
            <div className="info-item">
              <label>Status</label>
              <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
            </div>
            <div className="info-item">
              <label>Progress</label>
              <span>{scan.progress}%</span>
            </div>
            <div className="info-item">
              <label>Created</label>
              <span>{format(new Date(scan.created_at), 'PPpp')}</span>
            </div>
            <div className="info-item">
              <label>Updated</label>
              <span>{format(new Date(scan.updated_at), 'PPpp')}</span>
            </div>
            {scan.completed_at && (
              <div className="info-item">
                <label>Completed</label>
                <span>{format(new Date(scan.completed_at), 'PPpp')}</span>
              </div>
            )}
          </div>

          {scan.config && (
            <div className="config-section">
              <h3>Configuration</h3>
              <pre>{JSON.stringify(scan.config, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default CloudScanDetails;
