import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './NetworkScans.css';

function NetworkScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [filterScanner, setFilterScanner] = useState('all');

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [filter, filterScanner]);

  const loadScans = async () => {
    try {
      const params = {};
      if (filter !== 'all') params.status = filter;
      if (filterScanner !== 'all') params.scanner = filterScanner;
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

  const getScannerBadge = (scanner) => {
    const scannerIcons = {
      nmap: '🔍',
      masscan: '⚡',
      dns: '🌐'
    };
    return (
      <span className={`scanner-badge scanner-${scanner || 'nmap'}`}>
        {scannerIcons[scanner] || '🔍'} {scanner || 'nmap'}
      </span>
    );
  };

  if (loading) {
    return <div className="loading">Loading scans...</div>;
  }

  return (
    <div className="network-scans">
      <div className="page-header">
        <h1>Network Scans</h1>
        <Link to="/new-scan" className="btn btn-primary">
          + New Scan
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
        <div className="filter-separator" />
        <div className="filter-group">
          <span className="filter-group-label">Scanner:</span>
          <div className="filter-buttons">
            <button
              className={`filter-btn ${filterScanner === 'all' ? 'active' : ''}`}
              onClick={() => setFilterScanner('all')}
            >
              All
            </button>
            <button
              className={`filter-btn ${filterScanner === 'nmap' ? 'active' : ''}`}
              onClick={() => setFilterScanner('nmap')}
            >
              🔍 nmap
            </button>
            <button
              className={`filter-btn ${filterScanner === 'masscan' ? 'active' : ''}`}
              onClick={() => setFilterScanner('masscan')}
            >
              ⚡ masscan
            </button>
            <button
              className={`filter-btn ${filterScanner === 'dns' ? 'active' : ''}`}
              onClick={() => setFilterScanner('dns')}
            >
              🌐 dns
            </button>
          </div>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="empty-state card">
          <h3>No scans found</h3>
          <p>Create your first network scan to discover hosts, ports, and services.</p>
          <Link to="/new-scan" className="btn btn-primary">
            Create your first scan
          </Link>
        </div>
      ) : (
        <div className="scans-table card">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Scanner</th>
                <th>Target</th>
                <th>Type</th>
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
                    <Link to={`/scan/${scan.id}`} className="scan-name">
                      {scan.name}
                    </Link>
                  </td>
                  <td>{getScannerBadge(scan.scanner)}</td>
                  <td className="target-cell" title={scan.target}>
                    {scan.target.length > 30 ? scan.target.substring(0, 30) + '...' : scan.target}
                  </td>
                  <td>
                    <span className="type-badge">{scan.scan_type}</span>
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
                    <Link to={`/scan/${scan.id}`} className="btn btn-sm btn-secondary">
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
                    {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
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

export default NetworkScans;
