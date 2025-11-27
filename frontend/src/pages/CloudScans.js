import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './CloudScans.css';

function CloudScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterProvider, setFilterProvider] = useState('all');
  const [filterType, setFilterType] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  const loadScans = async () => {
    try {
      const response = await api.get('/cloudscans/');
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
        await api.delete(`/cloudscans/${id}`);
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
      await api.post(`/cloudscans/${id}/cancel`);
      loadScans();
    } catch (error) {
      console.error('Error cancelling scan:', error);
    }
  };

  const getProviderIcon = (provider) => {
    switch (provider) {
      case 'aws': return '☁️';
      case 'azure': return '🔷';
      case 'gcp': return '🔶';
      case 'docker': return '🐳';
      default: return '☁️';
    }
  };

  const getProviderName = (provider) => {
    switch (provider) {
      case 'aws': return 'AWS';
      case 'azure': return 'Azure';
      case 'gcp': return 'GCP';
      case 'docker': return 'Docker';
      default: return provider;
    }
  };

  const getScanTypeIcon = (type) => {
    switch (type) {
      case 'trivy': return '🔍';
      case 'prowler': return '🦁';
      case 'scoutsuite': return '🔭';
      case 'image': return '📦';
      case 'config': return '⚙️';
      case 'full': return '🚀';
      default: return '📋';
    }
  };

  const getScanTypeName = (type) => {
    switch (type) {
      case 'trivy': return 'Trivy';
      case 'prowler': return 'Prowler';
      case 'scoutsuite': return 'ScoutSuite';
      case 'image': return 'Image Scan';
      case 'config': return 'IaC Scan';
      case 'full': return 'Full Scan';
      default: return type;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#dc3545';
      case 'high': return '#fd7e14';
      case 'medium': return '#ffc107';
      case 'low': return '#28a745';
      default: return '#6c757d';
    }
  };

  const filteredScans = scans.filter(scan => {
    if (filterProvider !== 'all' && scan.provider !== filterProvider) return false;
    if (filterType !== 'all' && scan.scan_type !== filterType) return false;
    if (filterStatus !== 'all' && scan.status !== filterStatus) return false;
    return true;
  });

  if (loading) {
    return <div className="loading">Loading cloud security scans...</div>;
  }

  return (
    <div className="cloud-scans">
      <div className="page-header">
        <div className="header-content">
          <h1>Cloud Security</h1>
          <p className="subtitle">Scan cloud infrastructure, containers, and IaC for security issues</p>
        </div>
        <Link to="/new-cloud-scan" className="btn btn-primary">
          + New Cloud Scan
        </Link>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="filters">
        <div className="filter-group">
          <label>Provider:</label>
          <select value={filterProvider} onChange={(e) => setFilterProvider(e.target.value)}>
            <option value="all">All Providers</option>
            <option value="aws">AWS</option>
            <option value="azure">Azure</option>
            <option value="gcp">GCP</option>
            <option value="docker">Docker</option>
          </select>
        </div>
        <div className="filter-group">
          <label>Type:</label>
          <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
            <option value="all">All Types</option>
            <option value="trivy">Trivy</option>
            <option value="prowler">Prowler</option>
            <option value="scoutsuite">ScoutSuite</option>
            <option value="image">Image Scan</option>
            <option value="config">IaC Scan</option>
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
          <h3>No cloud security scans yet</h3>
          <p>Scan your cloud infrastructure with Trivy, Prowler, or ScoutSuite to find security misconfigurations and vulnerabilities</p>
          <Link to="/new-cloud-scan" className="btn btn-primary">Create Your First Cloud Scan</Link>
        </div>
      ) : (
        <div className="scans-table card">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Provider</th>
                <th>Type</th>
                <th>Target</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredScans.map(scan => (
                <tr key={scan.id}>
                  <td>
                    <Link to={`/cloud-scans/${scan.id}`} className="scan-name">
                      {scan.name}
                    </Link>
                  </td>
                  <td>
                    <span className={`provider-badge provider-${scan.provider}`}>
                      {getProviderIcon(scan.provider)} {getProviderName(scan.provider)}
                    </span>
                  </td>
                  <td>
                    <span className={`type-badge type-${scan.scan_type}`}>
                      {getScanTypeIcon(scan.scan_type)} {getScanTypeName(scan.scan_type)}
                    </span>
                  </td>
                  <td className="target-cell" title={scan.target}>
                    {scan.target ? (scan.target.length > 30 ? scan.target.substring(0, 30) + '...' : scan.target) : '-'}
                  </td>
                  <td>
                    <span className={`status-badge status-${scan.status}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>
                    {scan.summary ? (
                      <div className="findings-summary">
                        {scan.summary.critical > 0 && (
                          <span className="finding-count critical" title="Critical">{scan.summary.critical}</span>
                        )}
                        {scan.summary.high > 0 && (
                          <span className="finding-count high" title="High">{scan.summary.high}</span>
                        )}
                        {scan.summary.medium > 0 && (
                          <span className="finding-count medium" title="Medium">{scan.summary.medium}</span>
                        )}
                        {scan.summary.low > 0 && (
                          <span className="finding-count low" title="Low">{scan.summary.low}</span>
                        )}
                        {scan.summary.total_findings === 0 && <span className="no-findings">Clean</span>}
                      </div>
                    ) : (
                      <span className="no-data">-</span>
                    )}
                  </td>
                  <td>{format(new Date(scan.created_at), 'MMM dd, HH:mm')}</td>
                  <td className="actions-cell">
                    <Link to={`/cloud-scans/${scan.id}`} className="btn btn-sm btn-secondary">
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

export default CloudScans;
