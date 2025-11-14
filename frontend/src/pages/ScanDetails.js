import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './ScanDetails.css';

function ScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState([]);
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
        api.get(`/scans/${id}`),
        api.get(`/scans/${id}/results`),
        api.get(`/scans/${id}/logs`)
      ]);

      setScan(scanRes.data);
      setResults(resultsRes.data);
      setLogs(logsRes.data);
    } catch (error) {
      console.error('Error loading scan data:', error);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async (format) => {
    try {
      const response = await api.get(`/reports/${id}/${format}`, {
        responseType: format === 'html' ? 'text' : 'blob'
      });

      const blob = new Blob([response.data], {
        type: format === 'html' ? 'text/html' : format === 'json' ? 'application/json' : 'text/csv'
      });

      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `scan_${id}.${format}`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading report:', error);
      alert('Failed to download report');
    }
  };

  if (loading) {
    return <div className="loading">Loading scan details...</div>;
  }

  if (!scan) {
    return <div className="error-message">Scan not found</div>;
  }

  return (
    <div className="scan-details">
      <div className="details-header">
        <div>
          <h1>{scan.name}</h1>
          <span className={`badge badge-${scan.status}`}>{scan.status}</span>
        </div>
        <button className="btn btn-secondary" onClick={() => navigate('/')}>
          Back to Dashboard
        </button>
      </div>

      <div className="scan-meta card">
        <div className="meta-grid">
          <div className="meta-item">
            <span className="meta-label">Target</span>
            <span className="meta-value">{scan.target}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Scan Type</span>
            <span className="meta-value">{scan.scan_type}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Created</span>
            <span className="meta-value">
              {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm:ss')}
            </span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Progress</span>
            <span className="meta-value">{scan.progress}%</span>
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
          Results ({results.length})
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
          <div className="results-header">
            <h2>Scan Results</h2>
            <div className="download-buttons">
              <button className="btn btn-secondary" onClick={() => downloadReport('json')}>
                Download JSON
              </button>
              <button className="btn btn-secondary" onClick={() => downloadReport('csv')}>
                Download CSV
              </button>
              <button className="btn btn-secondary" onClick={() => downloadReport('html')}>
                Download HTML
              </button>
            </div>
          </div>

          {results.length === 0 ? (
            <div className="empty-state">No results yet</div>
          ) : (
            <div className="results-list">
              {results.map(result => (
                <div key={result.id} className="result-card card">
                  <div className="result-header">
                    <h3>
                      {result.host}
                      {result.hostname && <span className="hostname-badge"> ({result.hostname})</span>}
                    </h3>
                    <span className={`state-badge ${result.state}`}>
                      {result.state}
                    </span>
                  </div>

                  {result.mac_vendor && (
                    <p className="device-info mac-vendor">
                      <strong>Manufacturer:</strong> {result.mac_vendor}
                      {result.mac_address && <span className="mac-address"> ({result.mac_address})</span>}
                    </p>
                  )}

                  {result.os_detection && result.os_detection.matches && result.os_detection.matches.length > 0 && (
                    <p className="device-info">
                      <strong>Device:</strong> {result.os_detection.matches[0].name}
                    </p>
                  )}

                  {!result.hostname && !result.mac_vendor && result.services && result.services.length > 0 && (
                    <p className="device-info">
                      <strong>Services:</strong> {result.services.slice(0, 3).join(', ')}
                    </p>
                  )}

                  {result.ports && result.ports.length > 0 && (
                    <div className="ports-section">
                      <h4>Open Ports ({result.ports.length})</h4>
                      <table className="ports-table">
                        <thead>
                          <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                          </tr>
                        </thead>
                        <tbody>
                          {result.ports.map((port, idx) => (
                            <tr key={idx}>
                              <td>{port.port}</td>
                              <td>{port.protocol}</td>
                              <td><span className="port-state">{port.state}</span></td>
                              <td>{port.service}</td>
                              <td>{port.version || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {result.os_detection && result.os_detection.matches && result.os_detection.matches.length > 0 && (
                    <div className="os-section">
                      <h4>OS Detection</h4>
                      <ul className="os-list">
                        {result.os_detection.matches.slice(0, 3).map((os, idx) => (
                          <li key={idx}>
                            {os.name} <span className="accuracy">({os.accuracy}% accuracy)</span>
                          </li>
                        ))}
                      </ul>
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

export default ScanDetails;
