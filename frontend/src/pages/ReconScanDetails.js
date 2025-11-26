import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './ReconScanDetails.css';

function ReconScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState(null);
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState('results');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScanData();
    const interval = setInterval(loadScanData, 3000);
    return () => clearInterval(interval);
  }, [id]);

  const loadScanData = async () => {
    try {
      const [scanRes, resultsRes, logsRes] = await Promise.all([
        api.get(`/recon/${id}`),
        api.get(`/recon/${id}/results`),
        api.get(`/recon/${id}/logs`)
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

  const cancelScan = async () => {
    if (!scan) return;

    try {
      await api.post(`/recon/${id}/cancel`);
      loadScanData();
    } catch (error) {
      console.error('Error cancelling scan:', error);
      alert('Failed to cancel scan');
    }
  };

  const deleteScan = async () => {
    if (!window.confirm('Are you sure you want to delete this scan?')) return;

    try {
      await api.delete(`/recon/${id}`);
      navigate('/recon');
    } catch (error) {
      console.error('Error deleting scan:', error);
      alert('Failed to delete scan');
    }
  };

  const getScanTypeBadgeClass = (scanType) => {
    switch (scanType) {
      case 'subdomain': return 'type-subdomain';
      case 'whois': return 'type-whois';
      case 'dns': return 'type-dns';
      case 'tech': return 'type-tech';
      default: return '';
    }
  };

  const getScanTypeLabel = (scanType) => {
    switch (scanType) {
      case 'subdomain': return 'Subdomains';
      case 'whois': return 'WHOIS';
      case 'dns': return 'DNS';
      case 'tech': return 'Tech Detection';
      default: return scanType;
    }
  };

  const getScanTypeIcon = (scanType) => {
    switch (scanType) {
      case 'subdomain': return '🌐';
      case 'whois': return '📋';
      case 'dns': return '🔗';
      case 'tech': return '🔧';
      default: return '🔍';
    }
  };

  const formatWhoisDate = (dateStr) => {
    if (!dateStr) return 'N/A';
    try {
      return format(new Date(dateStr), 'MMM dd, yyyy');
    } catch {
      return dateStr;
    }
  };

  if (loading) {
    return <div className="loading">Loading scan details...</div>;
  }

  if (!scan) {
    return <div className="error-message">Scan not found</div>;
  }

  const renderResults = () => {
    if (!results) {
      return <div className="empty-state">No results yet</div>;
    }

    switch (scan.scan_type) {
      case 'subdomain':
        return renderSubdomainResults();
      case 'whois':
        return renderWhoisResults();
      case 'dns':
        return renderDnsResults();
      case 'tech':
        return renderTechResults();
      default:
        return <div className="empty-state">Unknown scan type</div>;
    }
  };

  const renderSubdomainResults = () => {
    const subdomains = results.subdomains || [];
    return (
      <div className="results-section">
        <div className="results-header">
          <h3>Found {subdomains.length} Subdomains</h3>
        </div>
        {subdomains.length === 0 ? (
          <div className="empty-state">No subdomains found yet</div>
        ) : (
          <div className="subdomain-list card">
            <table>
              <thead>
                <tr>
                  <th>Subdomain</th>
                  <th>Source</th>
                  <th>IP Address</th>
                </tr>
              </thead>
              <tbody>
                {subdomains.map((sub, index) => (
                  <tr key={index}>
                    <td className="subdomain-name">{sub.subdomain}</td>
                    <td>
                      <span className="source-badge">{sub.source}</span>
                    </td>
                    <td className="ip-address">{sub.ip_address || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  };

  const renderWhoisResults = () => {
    const whois = results.whois;
    if (!whois) {
      return <div className="empty-state">WHOIS data not available yet</div>;
    }

    return (
      <div className="whois-results card">
        <div className="whois-section">
          <h3>Registrar Information</h3>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">Registrar</span>
              <span className="info-value">{whois.registrar || 'N/A'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Registrar URL</span>
              <span className="info-value">
                {whois.registrar_url ? (
                  <a href={whois.registrar_url} target="_blank" rel="noopener noreferrer">
                    {whois.registrar_url}
                  </a>
                ) : 'N/A'}
              </span>
            </div>
          </div>
        </div>

        <div className="whois-section">
          <h3>Dates</h3>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">Created</span>
              <span className="info-value">{formatWhoisDate(whois.created_date)}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Updated</span>
              <span className="info-value">{formatWhoisDate(whois.updated_date)}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Expires</span>
              <span className="info-value">{formatWhoisDate(whois.expiry_date)}</span>
            </div>
          </div>
        </div>

        {whois.name_servers && whois.name_servers.length > 0 && (
          <div className="whois-section">
            <h3>Name Servers</h3>
            <ul className="ns-list">
              {whois.name_servers.map((ns, index) => (
                <li key={index}>{ns}</li>
              ))}
            </ul>
          </div>
        )}

        {whois.status && whois.status.length > 0 && (
          <div className="whois-section">
            <h3>Domain Status</h3>
            <div className="status-tags">
              {whois.status.map((status, index) => (
                <span key={index} className="status-tag">{status}</span>
              ))}
            </div>
          </div>
        )}

        {whois.registrant && (
          <div className="whois-section">
            <h3>Registrant</h3>
            <div className="info-grid">
              {whois.registrant.name && (
                <div className="info-item">
                  <span className="info-label">Name</span>
                  <span className="info-value">{whois.registrant.name}</span>
                </div>
              )}
              {whois.registrant.organization && (
                <div className="info-item">
                  <span className="info-label">Organization</span>
                  <span className="info-value">{whois.registrant.organization}</span>
                </div>
              )}
              {whois.registrant.country && (
                <div className="info-item">
                  <span className="info-label">Country</span>
                  <span className="info-value">{whois.registrant.country}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {whois.raw && (
          <div className="whois-section">
            <h3>Raw WHOIS Data</h3>
            <pre className="raw-whois">{whois.raw}</pre>
          </div>
        )}
      </div>
    );
  };

  const renderDnsResults = () => {
    const dns = results.dns || {};
    const dnsRecordKeys = ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt'];
    const recordTypes = dnsRecordKeys.filter(key => dns[key] && Array.isArray(dns[key]) && dns[key].length > 0);

    if (recordTypes.length === 0 && !dns.soa) {
      return <div className="empty-state">No DNS records found yet</div>;
    }

    const formatRecordLabel = (key) => {
      const labels = { a: 'A', aaaa: 'AAAA', cname: 'CNAME', mx: 'MX', ns: 'NS', txt: 'TXT' };
      return labels[key] || key.toUpperCase();
    };

    return (
      <div className="dns-results">
        {recordTypes.map(recordType => (
          <div key={recordType} className="dns-section card">
            <h3>{formatRecordLabel(recordType)} Records</h3>
            <table className="dns-table">
              <thead>
                <tr>
                  <th>Value</th>
                  {recordType === 'mx' && <th>Priority</th>}
                </tr>
              </thead>
              <tbody>
                {dns[recordType].map((record, index) => (
                  <tr key={index}>
                    <td className="record-value">
                      {typeof record === 'string' ? record : (record.host || record.value || JSON.stringify(record))}
                    </td>
                    {recordType === 'mx' && <td>{record.priority}</td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
        {dns.soa && (
          <div className="dns-section card">
            <h3>SOA Record</h3>
            <table className="dns-table">
              <tbody>
                <tr><td><strong>Primary NS</strong></td><td>{dns.soa.primary_ns}</td></tr>
                <tr><td><strong>Email</strong></td><td>{dns.soa.email}</td></tr>
                <tr><td><strong>Serial</strong></td><td>{dns.soa.serial}</td></tr>
                <tr><td><strong>Refresh</strong></td><td>{dns.soa.refresh}</td></tr>
                <tr><td><strong>Retry</strong></td><td>{dns.soa.retry}</td></tr>
                <tr><td><strong>Expire</strong></td><td>{dns.soa.expire}</td></tr>
                <tr><td><strong>Min TTL</strong></td><td>{dns.soa.min_ttl}</td></tr>
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  };

  const renderTechResults = () => {
    const techs = results.technologies || [];

    if (techs.length === 0) {
      return <div className="empty-state">No technologies detected yet</div>;
    }

    return (
      <div className="tech-results">
        {techs.map((tech, index) => (
          <div key={index} className="tech-card card">
            <div className="tech-header">
              <h3>{tech.url}</h3>
              {tech.status_code && (
                <span className={`status-code status-${Math.floor(tech.status_code / 100)}xx`}>
                  {tech.status_code}
                </span>
              )}
            </div>

            {tech.title && (
              <div className="tech-info">
                <span className="info-label">Title:</span>
                <span className="info-value">{tech.title}</span>
              </div>
            )}

            {tech.webserver && (
              <div className="tech-info">
                <span className="info-label">Web Server:</span>
                <span className="tech-tag">{tech.webserver}</span>
              </div>
            )}

            {tech.technologies && tech.technologies.length > 0 && (
              <div className="tech-info">
                <span className="info-label">Technologies:</span>
                <div className="tech-tags">
                  {tech.technologies.map((t, i) => (
                    <span key={i} className="tech-tag" title={`Category: ${t.category || 'N/A'}, Confidence: ${t.confidence || 0}%`}>
                      {typeof t === 'string' ? t : t.name}
                      {t.version && ` v${t.version}`}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {tech.cdn && (
              <div className="tech-info">
                <span className="info-label">CDN:</span>
                <span className="tech-tag">{tech.cdn}</span>
              </div>
            )}

            {tech.content_type && (
              <div className="tech-info">
                <span className="info-label">Content-Type:</span>
                <span className="info-value">{tech.content_type}</span>
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  const getResultsCount = () => {
    if (!results) return 0;
    switch (scan.scan_type) {
      case 'subdomain': return results.subdomains?.length || 0;
      case 'dns': return Object.keys(results.dns || {}).length;
      case 'tech': return results.technologies?.length || 0;
      default: return scan.results_count || 0;
    }
  };

  return (
    <div className="recon-scan-details">
      <div className="page-header">
        <div className="header-left">
          <Link to="/recon" className="back-link">← Back to Recon Scans</Link>
          <h1>{scan.name}</h1>
          <div className="scan-meta">
            <span className={`type-badge ${getScanTypeBadgeClass(scan.scan_type)}`}>
              {getScanTypeIcon(scan.scan_type)} {getScanTypeLabel(scan.scan_type)}
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
            <div className="progress-fill" style={{ width: `${scan.progress || 0}%` }}></div>
            <span className="progress-text">{scan.progress || 0}%</span>
          </div>
          <p className="progress-status">
            {scan.status === 'pending' ? 'Waiting to start...' : 'Scanning in progress...'}
          </p>
        </div>
      )}

      {/* Stats Summary */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{getResultsCount()}</div>
          <div className="stat-label">Results</div>
        </div>
        {scan.scan_type === 'subdomain' && (
          <div className="stat-card">
            <div className="stat-value">{results?.subdomains?.filter(s => s.ip_address)?.length || 0}</div>
            <div className="stat-label">With IPs</div>
          </div>
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
          Results
        </button>
        <button
          className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          Logs ({logs.length})
        </button>
        {scan.config && (
          <button
            className={`tab ${activeTab === 'config' ? 'active' : ''}`}
            onClick={() => setActiveTab('config')}
          >
            Configuration
          </button>
        )}
      </div>

      {activeTab === 'results' && renderResults()}

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

      {activeTab === 'config' && scan.config && (
        <div className="config-section card">
          <h3>Scan Configuration</h3>
          <pre className="config-json">
            {JSON.stringify(scan.config, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default ReconScanDetails;
