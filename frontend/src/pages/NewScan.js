import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import './NewScan.css';

function NewScan() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    target: '',
    scan_type: 'quick',
    nmap_arguments: ''
  });
  const [templates, setTemplates] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      const response = await api.get('/templates/builtin');
      setTemplates(response.data);
    } catch (error) {
      console.error('Error loading templates:', error);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));

    // Update nmap arguments when scan type changes
    if (name === 'scan_type' && templates[value]) {
      setFormData(prev => ({
        ...prev,
        nmap_arguments: templates[value].arguments
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await api.post('/scans/', formData);
      navigate(`/scan/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="new-scan">
      <h1>Create New Scan</h1>

      {error && (
        <div className="error-message">{error}</div>
      )}

      <form onSubmit={handleSubmit} className="scan-form card">
        <div className="form-group">
          <label htmlFor="name">Scan Name *</label>
          <input
            type="text"
            id="name"
            name="name"
            value={formData.name}
            onChange={handleChange}
            placeholder="e.g., Production Network Scan"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="target">Target *</label>
          <input
            type="text"
            id="target"
            name="target"
            value={formData.target}
            onChange={handleChange}
            placeholder="e.g., 192.168.1.0/24, scanme.nmap.org, 10.0.0.1-50"
            required
          />
          <small>IP address, hostname, CIDR notation, or IP range</small>
        </div>

        <div className="form-group">
          <label htmlFor="scan_type">Scan Type *</label>
          <select
            id="scan_type"
            name="scan_type"
            value={formData.scan_type}
            onChange={handleChange}
            required
          >
            {Object.entries(templates).map(([key, template]) => (
              <option key={key} value={key}>
                {template.name} - {template.description}
              </option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="nmap_arguments">Nmap Arguments</label>
          <input
            type="text"
            id="nmap_arguments"
            name="nmap_arguments"
            value={formData.nmap_arguments}
            onChange={handleChange}
            placeholder="e.g., -sV -O -T4"
          />
          <small>Custom nmap command-line arguments (optional)</small>
        </div>

        <div className="template-info">
          {formData.scan_type && templates[formData.scan_type] && (
            <>
              <h3>Template Details</h3>
              <p><strong>Name:</strong> {templates[formData.scan_type].name}</p>
              <p><strong>Description:</strong> {templates[formData.scan_type].description}</p>
              <p><strong>Default Arguments:</strong> <code>{templates[formData.scan_type].arguments}</code></p>
            </>
          )}
        </div>

        <div className="form-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate('/network-scans')}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
          >
            {loading ? 'Creating...' : 'Start Scan'}
          </button>
        </div>
      </form>

      <div className="scan-types-info card">
        <h2>Available Scan Types</h2>
        <div className="scan-types-grid">
          {Object.entries(templates).map(([key, template]) => (
            <div key={key} className="scan-type-card">
              <h3>{template.name}</h3>
              <p>{template.description}</p>
              <code>{template.arguments}</code>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default NewScan;
