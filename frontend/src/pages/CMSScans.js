import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './CMSScans.css';

function CMSScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  const loadScans = async () => {
    try {
      const response = await api.get('/cmsscans/');
      setScans(response.data || []);
      setError('');
    } catch (error) {
      console.error('Error loading scans:', error);
      setError('Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleDelete = async (id, e) => {
    e.preventDefault();
    e.stopPropagation();
    if (window.confirm('Are you sure you want to delete this scan?')) {
      try {
        await api.delete(`/cmsscans/${id}`);
        loadScans();
      } catch (error) {
        console.error('Error deleting scan:', error);
      }
    }
  };

  const handleCancel = async (id, e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await api.post(`/cmsscans/${id}/cancel`);
      loadScans();
    } catch (error) {
      console.error('Error cancelling scan:', error);
    }
  };

  const getScanTypeIcon = (type) => {
    switch (type) {
      case 'whatweb': return '🔍';
      case 'cmseek': return '🎯';
      case 'wpscan': return '📝';
      case 'full': return '🚀';
      default: return '📋';
    }
  };

  const getScanTypeName = (type) => {
    switch (type) {
      case 'whatweb': return 'WhatWeb';
      case 'cmseek': return 'CMSeeK';
      case 'wpscan': return 'WPScan';
      case 'full': return 'Full Scan';
      default: return type;
    }
  };

  const filteredScans = scans.filter(scan => {
    if (filterType !== 'all' && scan.scan_type !== filterType) return false;
    if (filterStatus !== 'all' && scan.status !== filterStatus) return false;
    return true;
  });

  if (loading) {
    return <div className="loading">Loading CMS scans...</div>;
  }

  return (
    <div className="cms-scans">
      <div className="page-header">
        <div className="header-content">
          <h1>CMS Detection</h1>
          <p className="subtitle">Detect CMS platforms, frameworks, and technologies</p>
        </div>
        <Link to="/new-cms-scan" className="btn btn-primary">
          + New CMS Scan
        </Link>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="filters">
        <div className="filter-group">
          <label>Type:</label>
          <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
            <option value="all">All Types</option>
            <option value="whatweb">WhatWeb</option>
            <option value="cmseek">CMSeeK</option>
            <option value="wpscan">WPScan</option>
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

      {filteredScans.length === 0 ? (
        <div className="empty-state card">
          <h3>No CMS scans yet</h3>
          <p>Detect CMS platforms like WordPress, Drupal, Joomla, and more with WhatWeb, CMSeeK, or WPScan</p>
          <Link to="/new-cms-scan" className="btn btn-primary">Create Your First CMS Scan</Link>
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
              {filteredScans.map(scan => (
                <tr key={scan.id}>
                  <td>
                    <Link to={`/cms-scans/${scan.id}`} className="scan-name">
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
                    <Link to={`/cms-scans/${scan.id}`} className="btn btn-sm btn-secondary">
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

export default CMSScans;
