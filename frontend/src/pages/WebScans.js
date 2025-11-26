import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import './WebScans.css';

function WebScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterTool, setFilterTool] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [filterTool, filterStatus]);

  const loadScans = async () => {
    try {
      const params = new URLSearchParams();
      if (filterTool !== 'all') params.append('tool', filterTool);
      if (filterStatus !== 'all') params.append('status', filterStatus);
      const queryString = params.toString() ? `?${params.toString()}` : '';
      const response = await api.get(`/webscans/${queryString}`);
      setScans(response.data || []);
      setError('');
    } catch (error) {
      console.error('Error loading scans:', error);
      setError('Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  const deleteScan = async (id) => {
    if (!window.confirm('Are you sure you want to delete this scan?')) return;
    try {
      await api.delete(`/webscans/${id}`);
      loadScans();
    } catch (error) {
      alert(error.response?.data?.error || 'Failed to delete scan');
    }
  };

  const cancelScan = async (id) => {
    try {
      await api.post(`/webscans/${id}/cancel`);
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

  const getToolIcon = (tool) => {
    switch (tool) {
      case 'ffuf': return '🔍';
      case 'gowitness': return '📸';
      case 'testssl': return '🔒';
      default: return '🛠️';
    }
  };

  const getToolBadge = (tool) => {
    return <span className={`tool-badge tool-${tool}`}>{getToolIcon(tool)} {tool}</span>;
  };

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleString();
  };

  if (loading) {
    return <div className="loading">Loading web scans...</div>;
  }

  return (
    <div className="web-scans">
      <div className="page-header">
        <h1>Web Scans</h1>
        <Link to="/new-webscan" className="btn btn-primary">
          + New Web Scan
        </Link>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="filters">
        <div className="filter-group">
          <label>Tool:</label>
          <select value={filterTool} onChange={(e) => setFilterTool(e.target.value)}>
            <option value="all">All Tools</option>
            <option value="ffuf">ffuf</option>
            <option value="gowitness">Gowitness</option>
            <option value="testssl">testssl</option>
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
          <h3>No web scans yet</h3>
          <p>Create your first scan to discover directories, capture screenshots, or analyze SSL/TLS.</p>
          <Link to="/new-webscan" className="btn btn-primary">Create Web Scan</Link>
        </div>
      ) : (
        <div className="scans-table card">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Tool</th>
                <th>Target</th>
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
                    <Link to={`/webscan/${scan.id}`} className="scan-name">
                      {scan.name}
                    </Link>
                  </td>
                  <td>{getToolBadge(scan.tool)}</td>
                  <td className="target-cell" title={scan.target}>
                    {scan.target.length > 40 ? scan.target.substring(0, 40) + '...' : scan.target}
                  </td>
                  <td>{getStatusBadge(scan.status)}</td>
                  <td>
                    <div className="progress-bar">
                      <div
                        className="progress-fill"
                        style={{ width: `${scan.progress}%` }}
                      ></div>
                      <span className="progress-text">{scan.progress}%</span>
                    </div>
                  </td>
                  <td>{formatDate(scan.created_at)}</td>
                  <td className="actions-cell">
                    <Link to={`/webscan/${scan.id}`} className="btn btn-sm btn-secondary">
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

export default WebScans;
