import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import axios from 'axios';
import './Vulnerabilities.css';

// Use relative URLs - nginx will proxy /api/ to gateway
const goApi = axios.create({
  baseURL: '/api',
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

  const renderSeverityBadges = (scan) => {
    const stats = scanStats[scan.id];
    if (!stats || !stats.by_severity) return null;

    const severities = ['critical', 'high', 'medium', 'low', 'info'];
    const badges = severities
      .filter(sev => stats.by_severity[sev] > 0)
      .map(sev => (
        <span key={sev} className={`severity-badge severity-${sev}`}>
          {stats.by_severity[sev]}
        </span>
      ));

    return badges.length > 0 ? <div className="severity-badges">{badges}</div> : null;
  };

  if (loading) {
    return <div className="loading">Loading vulnerability scans...</div>;
  }

  return (
    <div className="vulnerabilities">
      <div className="page-header">
        <h1>Vulnerability Scans</h1>
        <Link to="/new-vuln-scan" className="btn btn-primary">
          + New Vuln Scan
        </Link>
      </div>

      <div className="filters-container">
        <div className="filter-group">
          <span className="filter-group-label">Status:</span>
          <div className="filter-buttons">
            {['all', 'pending', 'running', 'completed', 'failed', 'cancelled'].map(status => (
              <button
                key={status}
                className={`filter-btn ${filter === status ? 'active' : ''}`}
                data-status={status}
                onClick={() => setFilter(status)}
              >
                {status === 'all' ? 'All' : status.charAt(0).toUpperCase() + status.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="card empty-state">
          <h3>No vulnerability scans found</h3>
          <p>Start scanning for vulnerabilities with Nuclei</p>
          <Link to="/new-vuln-scan" className="btn btn-primary">
            Create your first vulnerability scan
          </Link>
        </div>
      ) : (
        <div className="card scans-table">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Target</th>
                <th>Severity Filter</th>
                <th>Findings</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.id}>
                  <td>
                    <Link to={`/vuln-scan/${scan.id}`} className="scan-name">
                      {scan.name}
                    </Link>
                  </td>
                  <td className="target-cell" title={scan.target}>
                    {scan.target}
                  </td>
                  <td>
                    {scan.severity && scan.severity.length > 0 ? (
                      <div className="severity-tags">
                        {scan.severity.map(sev => (
                          <span key={sev} className={`tag severity-${sev}`}>
                            {sev}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="tag">all</span>
                    )}
                  </td>
                  <td>
                    {scan.status === 'completed' && scanStats[scan.id] ? (
                      renderSeverityBadges(scan) || <span className="no-findings">0</span>
                    ) : (
                      <span className="no-findings">-</span>
                    )}
                  </td>
                  <td>
                    <span className={`status-badge status-${scan.status}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>
                    {scan.status === 'running' ? (
                      <div className="progress-bar">
                        <div
                          className="progress-fill"
                          style={{ width: `${scan.progress || 0}%` }}
                        />
                        <span className="progress-text">{scan.progress || 0}%</span>
                      </div>
                    ) : scan.status === 'completed' ? (
                      <span className="progress-complete">100%</span>
                    ) : (
                      <span className="progress-na">-</span>
                    )}
                  </td>
                  <td className="date-cell">
                    {format(new Date(scan.created_at), 'MMM dd, HH:mm')}
                  </td>
                  <td>
                    <div className="actions-cell">
                      <Link to={`/vuln-scan/${scan.id}`} className="btn btn-secondary btn-sm">
                        View
                      </Link>
                      {scan.status === 'running' && (
                        <button
                          className="btn btn-warning btn-sm"
                          onClick={() => cancelScan(scan.id)}
                        >
                          Cancel
                        </button>
                      )}
                      {['completed', 'failed', 'cancelled'].includes(scan.status) && (
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => deleteScan(scan.id)}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default Vulnerabilities;
