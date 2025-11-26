import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './Dashboard.css';

function NetworkScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [filter]);

  const loadScans = async () => {
    try {
      const params = filter !== 'all' ? { status: filter } : {};
      const response = await api.get('/scans/', { params });
      setScans(response.data);
    } catch (error) {
      console.error('Error loading scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const deleteScan = async (scanId) => {
    if (!window.confirm('Are you sure you want to delete this scan?')) {
      return;
    }

    try {
      await api.delete(`/scans/${scanId}`);
      loadScans();
    } catch (error) {
      console.error('Error deleting scan:', error);
      alert('Failed to delete scan');
    }
  };

  const cancelScan = async (scanId) => {
    try {
      await api.post(`/scans/${scanId}/cancel`);
      loadScans();
    } catch (error) {
      console.error('Error cancelling scan:', error);
      alert('Failed to cancel scan');
    }
  };

  if (loading) {
    return <div className="loading">Loading scans...</div>;
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Network Scans</h1>
        <Link to="/new-scan" className="btn btn-primary">
          + New Scan
        </Link>
      </div>

      <div className="filters">
        <button
          className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
          onClick={() => setFilter('all')}
        >
          All
        </button>
        <button
          className={`filter-btn ${filter === 'pending' ? 'active' : ''}`}
          onClick={() => setFilter('pending')}
        >
          Pending
        </button>
        <button
          className={`filter-btn ${filter === 'running' ? 'active' : ''}`}
          onClick={() => setFilter('running')}
        >
          Running
        </button>
        <button
          className={`filter-btn ${filter === 'completed' ? 'active' : ''}`}
          onClick={() => setFilter('completed')}
        >
          Completed
        </button>
        <button
          className={`filter-btn ${filter === 'failed' ? 'active' : ''}`}
          onClick={() => setFilter('failed')}
        >
          Failed
        </button>
      </div>

      {scans.length === 0 ? (
        <div className="empty-state">
          <p>No scans found</p>
          <Link to="/new-scan" className="btn btn-primary">
            Create your first scan
          </Link>
        </div>
      ) : (
        <div className="scans-grid">
          {scans.map(scan => (
            <div key={scan.id} className="scan-card card">
              <div className="scan-header">
                <h3>{scan.name}</h3>
                <span className={`badge badge-${scan.status}`}>
                  {scan.status}
                </span>
              </div>

              <div className="scan-info">
                <div className="info-row">
                  <span className="label">Target:</span>
                  <span className="value">{scan.target}</span>
                </div>
                <div className="info-row">
                  <span className="label">Type:</span>
                  <span className="value">{scan.scan_type}</span>
                </div>
                <div className="info-row">
                  <span className="label">Created:</span>
                  <span className="value">
                    {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm')}
                  </span>
                </div>
                {scan.status === 'running' && (
                  <div className="progress-bar">
                    <div
                      className="progress-fill"
                      style={{ width: `${scan.progress}%` }}
                    />
                  </div>
                )}
              </div>

              <div className="scan-actions">
                <Link to={`/scan/${scan.id}`} className="btn btn-secondary">
                  View Details
                </Link>
                {scan.status === 'running' && (
                  <button
                    className="btn btn-danger"
                    onClick={() => cancelScan(scan.id)}
                  >
                    Cancel
                  </button>
                )}
                {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
                  <button
                    className="btn btn-danger"
                    onClick={() => deleteScan(scan.id)}
                  >
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

export default NetworkScans;
