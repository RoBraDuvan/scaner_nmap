import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import './ReconScans.css';

function ReconScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [filterType, filterStatus]);

  const loadScans = async () => {
    try {
      const params = new URLSearchParams();
      if (filterType !== 'all') params.append('type', filterType);
      if (filterStatus !== 'all') params.append('status', filterStatus);
      const queryString = params.toString() ? `?${params.toString()}` : '';
      const response = await api.get(`/recon/${queryString}`);
      setScans(response.data || []);
      setError('');
    } catch (error) {
      console.error('Error loading scans:', error);
      setError('Failed to load recon scans');
    } finally {
      setLoading(false);
    }
  };

  const deleteScan = async (id) => {
    if (!window.confirm('Are you sure you want to delete this scan?')) return;
    try {
      await api.delete(`/recon/${id}`);
      loadScans();
    } catch (error) {
      alert(error.response?.data?.error || 'Failed to delete scan');
    }
  };

  const cancelScan = async (id) => {
    try {
      await api.post(`/recon/${id}/cancel`);
      loadScans();
    } catch (error) {
      alert(error.response?.data?.error || 'Failed to cancel scan');
    }
  };

  const getStatusBadge = (status) => {
    const statusClasses = {
      pending: 'status-pending',
      running: 'status-running',
      completed: 'status-completed',
      failed: 'status-failed',
      cancelled: 'status-cancelled'
    };
    return <span className={`status-badge ${statusClasses[status] || ''}`}>{status}</span>;
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

  const getScanTypeBadge = (scanType) => {
    const labels = {
      subdomain: 'Subdomains',
      whois: 'WHOIS',
      dns: 'DNS',
      tech: 'Tech Detection'
    };
    return <span className={`type-badge type-${scanType}`}>{getScanTypeIcon(scanType)} {labels[scanType] || scanType}</span>;
  };

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleString();
  };

  if (loading) {
    return <div className="loading">Loading recon scans...</div>;
  }

  return (
    <div className="recon-scans">
      <div className="page-header">
        <h1>Recon Scans</h1>
        <Link to="/new-recon" className="btn btn-primary">
          + New Recon Scan
        </Link>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="filters">
        <div className="filter-group">
          <label>Type:</label>
          <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
            <option value="all">All Types</option>
            <option value="subdomain">Subdomains</option>
            <option value="whois">WHOIS</option>
            <option value="dns">DNS</option>
            <option value="tech">Tech Detection</option>
          </select>
        </div>
        <div className="filter-group">
          <label>Status:</label>
          <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
            <option value="all">All Status</option>
            <option value="pending">Pending</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="empty-state card">
          <h3>No recon scans yet</h3>
          <p>Create your first scan to discover subdomains, WHOIS info, DNS records, or technologies.</p>
          <Link to="/new-recon" className="btn btn-primary">Create Recon Scan</Link>
        </div>
      ) : (
        <div className="scans-table card">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Target</th>
                <th>Status</th>
                <th>Results</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.id}>
                  <td>
                    <Link to={`/recon/${scan.id}`} className="scan-name">
                      {scan.name}
                    </Link>
                  </td>
                  <td>{getScanTypeBadge(scan.scan_type)}</td>
                  <td className="target-cell" title={scan.target}>
                    {scan.target.length > 40 ? scan.target.substring(0, 40) + '...' : scan.target}
                  </td>
                  <td>{getStatusBadge(scan.status)}</td>
                  <td>{scan.results_count || 0}</td>
                  <td>{formatDate(scan.created_at)}</td>
                  <td className="actions-cell">
                    <Link to={`/recon/${scan.id}`} className="btn btn-sm btn-secondary">
                      View
                    </Link>
                    {(scan.status === 'pending' || scan.status === 'running') && (
                      <button
                        className="btn btn-sm btn-warning"
                        onClick={() => cancelScan(scan.id)}
                      >
                        Cancel
                      </button>
                    )}
                    {scan.status !== 'running' && (
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => deleteScan(scan.id)}
                      >
                        Delete
                      </button>
                    )}
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

export default ReconScans;
