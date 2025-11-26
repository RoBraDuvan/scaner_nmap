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
    nmap_arguments: '',
    configuration: {}
  });
  const [templates, setTemplates] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeScanner, setActiveScanner] = useState('nmap');

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      const response = await api.get('/scans/templates/all');
      setTemplates(response.data);
    } catch (error) {
      console.error('Error loading templates:', error);
      // Fallback to builtin templates
      try {
        const fallback = await api.get('/templates/builtin');
        setTemplates(fallback.data);
      } catch (e) {
        console.error('Error loading fallback templates:', e);
      }
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));

    // Update arguments/configuration when scan type changes
    if (name === 'scan_type' && templates[value]) {
      const template = templates[value];
      if (template.scanner === 'nmap') {
        setFormData(prev => ({
          ...prev,
          nmap_arguments: template.arguments || '',
          configuration: {}
        }));
      } else if (template.scanner === 'masscan') {
        setFormData(prev => ({
          ...prev,
          nmap_arguments: '',
          configuration: {
            ports: template.ports,
            rate: template.rate
          }
        }));
      } else {
        setFormData(prev => ({
          ...prev,
          nmap_arguments: '',
          configuration: {}
        }));
      }
    }
  };

  const handleConfigChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      configuration: {
        ...prev.configuration,
        [name]: name === 'rate' ? parseInt(value) || 10000 : value
      }
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: formData.name,
        target: formData.target,
        scan_type: formData.scan_type,
      };

      // Add nmap_arguments only for nmap scans
      if (formData.nmap_arguments && getCurrentScanner() === 'nmap') {
        payload.nmap_arguments = formData.nmap_arguments;
      }

      // Add configuration for masscan
      if (getCurrentScanner() === 'masscan' && Object.keys(formData.configuration).length > 0) {
        payload.configuration = formData.configuration;
      }

      const response = await api.post('/scans/', payload);
      navigate(`/scan/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const getCurrentScanner = () => {
    if (templates[formData.scan_type]) {
      return templates[formData.scan_type].scanner;
    }
    return 'nmap';
  };

  const getTemplatesByScanner = (scanner) => {
    return Object.entries(templates).filter(([_, t]) => t.scanner === scanner);
  };

  const getScannerIcon = (scanner) => {
    switch (scanner) {
      case 'nmap': return '🔍';
      case 'masscan': return '⚡';
      case 'dns': return '🌐';
      default: return '📡';
    }
  };

  const filterTemplates = () => {
    if (activeScanner === 'all') return Object.entries(templates);
    return getTemplatesByScanner(activeScanner);
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
            placeholder={getCurrentScanner() === 'dns'
              ? "e.g., example.com"
              : "e.g., 192.168.1.0/24, scanme.nmap.org"}
            required
          />
          <small>
            {getCurrentScanner() === 'dns'
              ? 'Domain name to scan for DNS records'
              : 'IP address, hostname, CIDR notation, or IP range'}
          </small>
        </div>

        <div className="form-group">
          <label>Scanner Type</label>
          <div className="scanner-tabs">
            <button
              type="button"
              className={`scanner-tab ${activeScanner === 'nmap' ? 'active' : ''}`}
              onClick={() => {
                setActiveScanner('nmap');
                const firstNmap = getTemplatesByScanner('nmap')[0];
                if (firstNmap) {
                  setFormData(prev => ({ ...prev, scan_type: firstNmap[0] }));
                }
              }}
            >
              🔍 Nmap
            </button>
            <button
              type="button"
              className={`scanner-tab ${activeScanner === 'masscan' ? 'active' : ''}`}
              onClick={() => {
                setActiveScanner('masscan');
                const firstMasscan = getTemplatesByScanner('masscan')[0];
                if (firstMasscan) {
                  setFormData(prev => ({ ...prev, scan_type: firstMasscan[0] }));
                }
              }}
            >
              ⚡ Masscan
            </button>
            <button
              type="button"
              className={`scanner-tab ${activeScanner === 'dns' ? 'active' : ''}`}
              onClick={() => {
                setActiveScanner('dns');
                const firstDns = getTemplatesByScanner('dns')[0];
                if (firstDns) {
                  setFormData(prev => ({ ...prev, scan_type: firstDns[0] }));
                }
              }}
            >
              🌐 DNS
            </button>
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="scan_type">Scan Template *</label>
          <select
            id="scan_type"
            name="scan_type"
            value={formData.scan_type}
            onChange={handleChange}
            required
          >
            {filterTemplates().map(([key, template]) => (
              <option key={key} value={key}>
                {getScannerIcon(template.scanner)} {template.name} - {template.description}
              </option>
            ))}
          </select>
        </div>

        {/* Nmap-specific options */}
        {getCurrentScanner() === 'nmap' && (
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
        )}

        {/* Masscan-specific options */}
        {getCurrentScanner() === 'masscan' && (
          <>
            <div className="form-group">
              <label htmlFor="ports">Ports</label>
              <input
                type="text"
                id="ports"
                name="ports"
                value={formData.configuration.ports || ''}
                onChange={handleConfigChange}
                placeholder="e.g., 80,443,8080 or 1-1000"
              />
              <small>Ports to scan (default from template)</small>
            </div>
            <div className="form-group">
              <label htmlFor="rate">Scan Rate (packets/sec)</label>
              <input
                type="number"
                id="rate"
                name="rate"
                value={formData.configuration.rate || 10000}
                onChange={handleConfigChange}
                min="100"
                max="1000000"
              />
              <small>Higher rate = faster but may miss results</small>
            </div>
          </>
        )}

        <div className="template-info">
          {formData.scan_type && templates[formData.scan_type] && (
            <>
              <h3>Template Details</h3>
              <p><strong>Name:</strong> {templates[formData.scan_type].name}</p>
              <p><strong>Scanner:</strong> {templates[formData.scan_type].scanner?.toUpperCase()}</p>
              <p><strong>Description:</strong> {templates[formData.scan_type].description}</p>
              {templates[formData.scan_type].arguments && (
                <p><strong>Arguments:</strong> <code>{templates[formData.scan_type].arguments}</code></p>
              )}
              {templates[formData.scan_type].ports && (
                <p><strong>Ports:</strong> <code>{templates[formData.scan_type].ports}</code></p>
              )}
              {templates[formData.scan_type].rate && (
                <p><strong>Rate:</strong> {templates[formData.scan_type].rate} pkt/s</p>
              )}
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
        <div className="scanner-filter">
          <button
            className={activeScanner === 'all' ? 'active' : ''}
            onClick={() => setActiveScanner('all')}
          >
            All
          </button>
          <button
            className={activeScanner === 'nmap' ? 'active' : ''}
            onClick={() => setActiveScanner('nmap')}
          >
            🔍 Nmap
          </button>
          <button
            className={activeScanner === 'masscan' ? 'active' : ''}
            onClick={() => setActiveScanner('masscan')}
          >
            ⚡ Masscan
          </button>
          <button
            className={activeScanner === 'dns' ? 'active' : ''}
            onClick={() => setActiveScanner('dns')}
          >
            🌐 DNS
          </button>
        </div>
        <div className="scan-types-grid">
          {filterTemplates().map(([key, template]) => (
            <div
              key={key}
              className={`scan-type-card ${formData.scan_type === key ? 'selected' : ''}`}
              onClick={() => {
                setFormData(prev => ({ ...prev, scan_type: key }));
                setActiveScanner(template.scanner);
              }}
            >
              <div className="scanner-badge">{getScannerIcon(template.scanner)} {template.scanner}</div>
              <h3>{template.name}</h3>
              <p>{template.description}</p>
              {template.arguments && <code>{template.arguments}</code>}
              {template.ports && <code>Ports: {template.ports}</code>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default NewScan;
