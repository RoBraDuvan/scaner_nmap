import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './APIScans.css';

function APIScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
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

      const response = await api.get(`/apiscans/?${params.toString()}`);
      setScans(response.data || []);
    } catch (error) {
      console.error('Error loading API scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id, e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this scan?')) return;

    try {
      await api.delete(`/apiscans/${id}`);
      loadScans();
    } catch (error) {
      console.error('Error deleting scan:', error);
    }
  };

  const handleCancel = async (id, e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await api.post(`/apiscans/${id}/cancel`);
      loadScans();
    } catch (error) {
      console.error('Error cancelling scan:', error);
    }
  };

  const getScanTypeIcon = (scanType) => {
    switch (scanType) {
      case 'kiterunner': return '🦅';
      case 'arjun': return '🎯';
      case 'graphql': return '⬡';
      case 'swagger': return '📖';
      case 'full': return '🔍';
      default: return '🔌';
    }
  };

  const getScanTypeName = (scanType) => {
    switch (scanType) {
      case 'kiterunner': return 'Kiterunner';
      case 'arjun': return 'Arjun';
      case 'graphql': return 'GraphQL';
      case 'swagger': return 'Swagger/OpenAPI';
      case 'full': return 'Full Scan';
      default: return scanType;
    }
  };

  if (loading) {
    return <div className="loading">Loading API scans...</div>;
  }

  return (
    <div className="api-scans-page">
      <div className="page-header">
        <div className="header-content">
          <h1>API Discovery Scans</h1>
          <p className="subtitle">Discover API endpoints, parameters, GraphQL schemas and OpenAPI specs</p>
        </div>
        <Link to="/new-api-scan" className="btn btn-primary">
          + New API Scan
        </Link>
      </div>

      <div className="filters">
        <div className="filter-group">
          <label>Scan Type:</label>
          <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
            <option value="all">All Types</option>
            <option value="kiterunner">Kiterunner</option>
            <option value="arjun">Arjun</option>
            <option value="graphql">GraphQL</option>
            <option value="swagger">Swagger/OpenAPI</option>
            <option value="full">Full Scan</option>
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
          <h3>No API scans yet</h3>
          <p>Start discovering APIs with Kiterunner, Arjun, GraphQL introspection, and more</p>
          <Link to="/new-api-scan" className="btn btn-primary">Create Your First API Scan</Link>
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
                <th>Progress</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.id}>
                  <td>
                    <Link to={`/api-scans/${scan.id}`} className="scan-name">
                      {scan.name}
                    </Link>
                  </td>
                  <td>
                    <span className={`type-badge type-${scan.scan_type}`}>
                      {getScanTypeIcon(scan.scan_type)} {getScanTypeName(scan.scan_type)}
                    </span>
                  </td>
                  <td className="target-cell" title={scan.target}>
                    {scan.target.length > 40 ? scan.target.substring(0, 40) + '...' : scan.target}
                  </td>
                  <td>
                    <span className={`status-badge status-${scan.status}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>
                    <div className="progress-bar">
                      <div
                        className="progress-fill"
                        style={{ width: `${scan.progress}%` }}
                      ></div>
                      <span className="progress-text">{scan.progress}%</span>
                    </div>
                  </td>
                  <td>{format(new Date(scan.created_at), 'MMM dd, HH:mm')}</td>
                  <td className="actions-cell">
                    <Link to={`/api-scans/${scan.id}`} className="btn btn-sm btn-secondary">
                      View
                    </Link>
                    {scan.status === 'running' && (
                      <button
                        className="btn btn-sm btn-warning"
                        onClick={(e) => handleCancel(scan.id, e)}
                      >
                        Cancel
                      </button>
                    )}
                    {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={(e) => handleDelete(scan.id, e)}
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

export default APIScans;
