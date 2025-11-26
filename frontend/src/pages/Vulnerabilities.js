import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import axios from 'axios';
import './Vulnerabilities.css';

const GO_API_URL = process.env.REACT_APP_GO_API_URL || 'http://localhost:8001';

const goApi = axios.create({
  baseURL: `${GO_API_URL}/api`,
  headers: { 'Content-Type': 'application/json' },
});

function Vulnerabilities() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [scanStats, setScanStats] = useState({});

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [filter]);

  const loadScans = async () => {
    try {
      const params = filter !== 'all' ? { status: filter } : {};
      const response = await goApi.get('/vulnerabilities/', { params });
      setScans(response.data || []);

      // Load stats for completed scans
      const statsPromises = (response.data || [])
        .filter(s => s.status === 'completed')
        .map(async (scan) => {
          try {
            const statsRes = await goApi.get(`/vulnerabilities/${scan.id}/stats`);
            return { id: scan.id, stats: statsRes.data };
          } catch {
            return { id: scan.id, stats: null };
          }
        });

      const statsResults = await Promise.all(statsPromises);
      const statsMap = {};
      statsResults.forEach(({ id, stats }) => {
        if (stats) statsMap[id] = stats;
      });
      setScanStats(statsMap);
    } catch (error) {
      console.error('Error loading vulnerability scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const deleteScan = async (scanId) => {
    if (!window.confirm('Are you sure you want to delete this scan?')) return;
    try {
      await goApi.delete(`/vulnerabilities/${scanId}`);
      loadScans();
    } catch (error) {
      console.error('Error deleting scan:', error);
      alert('Failed to delete scan');
    }
  };

  const cancelScan = async (scanId) => {
    try {
      await goApi.post(`/vulnerabilities/${scanId}/cancel`);
      loadScans();
    } catch (error) {
      console.error('Error cancelling scan:', error);
      alert('Failed to cancel scan');
    }
  };

  if (loading) {
    return <div className="loading">Loading vulnerability scans...</div>;
  }

  return (
    <div className="dashboard">
      <div className="vulnerabilities-header">
        <h1>Vulnerability Scans</h1>
        <Link to="/new-vuln-scan" className="btn btn-primary">
          + New Vuln Scan
        </Link>
      </div>

      <div className="filters">
        {['all', 'pending', 'running', 'completed', 'failed'].map(status => (
          <button
            key={status}
            className={`filter-btn ${filter === status ? 'active' : ''}`}
            onClick={() => setFilter(status)}
          >
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </button>
        ))}
      </div>

      {scans.length === 0 ? (
        <div className="empty-state">
          <p>No vulnerability scans found</p>
          <Link to="/new-vuln-scan" className="btn btn-primary">
            Create your first vulnerability scan
          </Link>
        </div>
      ) : (
        <div className="vuln-scans-grid">
          {scans.map(scan => (
            <div key={scan.id} className="scan-card card vuln-scan-card">
              <div className="vuln-scan-header">
                <h3>{scan.name}</h3>
                <span className={`badge badge-${scan.status}`}>
                  {scan.status}
                </span>
              </div>

              <div className="vuln-scan-info">
                <div className="info-row">
                  <span className="label">Target:</span>
                  <span className="value">{scan.target}</span>
                </div>
                <div className="info-row">
                  <span className="label">Created:</span>
                  <span className="value">
                    {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm')}
                  </span>
                </div>

                {scan.severity && scan.severity.length > 0 && (
                  <div className="vuln-tags">
                    {scan.severity.map(sev => (
                      <span key={sev} className={`tag severity-${sev}`}>
                        {sev}
                      </span>
                    ))}
                  </div>
                )}

                {scan.tags && scan.tags.length > 0 && (
                  <div className="vuln-tags">
                    {scan.tags.map(tag => (
                      <span key={tag} className="tag">{tag}</span>
                    ))}
                  </div>
                )}

                {scan.status === 'running' && (
                  <div className="progress-bar">
                    <div className="progress-fill" style={{ width: `${scan.progress}%` }} />
                  </div>
                )}

                {scanStats[scan.id] && scanStats[scan.id].total > 0 && (
                  <div className="vuln-stats">
                    {scanStats[scan.id].by_severity?.critical > 0 && (
                      <span className="stat-badge critical">
                        {scanStats[scan.id].by_severity.critical} Critical
                      </span>
                    )}
                    {scanStats[scan.id].by_severity?.high > 0 && (
                      <span className="stat-badge high">
                        {scanStats[scan.id].by_severity.high} High
                      </span>
                    )}
                    {scanStats[scan.id].by_severity?.medium > 0 && (
                      <span className="stat-badge medium">
                        {scanStats[scan.id].by_severity.medium} Medium
                      </span>
                    )}
                    {scanStats[scan.id].by_severity?.low > 0 && (
                      <span className="stat-badge low">
                        {scanStats[scan.id].by_severity.low} Low
                      </span>
                    )}
                    {scanStats[scan.id].by_severity?.info > 0 && (
                      <span className="stat-badge info">
                        {scanStats[scan.id].by_severity.info} Info
                      </span>
                    )}
                  </div>
                )}
              </div>

              <div className="vuln-scan-actions">
                <Link to={`/vuln-scan/${scan.id}`} className="btn btn-secondary">
                  View Details
                </Link>
                {scan.status === 'running' && (
                  <button className="btn btn-danger" onClick={() => cancelScan(scan.id)}>
                    Cancel
                  </button>
                )}
                {['completed', 'failed', 'cancelled'].includes(scan.status) && (
                  <button className="btn btn-danger" onClick={() => deleteScan(scan.id)}>
                    Delete
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default Vulnerabilities;
