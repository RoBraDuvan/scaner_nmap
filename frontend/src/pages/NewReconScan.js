import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import './NewReconScan.css';

function NewReconScan() {
  const navigate = useNavigate();
  const [activeScanType, setActiveScanType] = useState('subdomain');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Subdomain form data
  const [subdomainForm, setSubdomainForm] = useState({
    name: '',
    domain: '',
    tools: ['subfinder'],
    recursive: false
  });

  // WHOIS form data
  const [whoisForm, setWhoisForm] = useState({
    name: '',
    domain: ''
  });

  // DNS form data
  const [dnsForm, setDnsForm] = useState({
    name: '',
    domain: '',
    record_types: ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
  });

  // Tech form data
  const [techForm, setTechForm] = useState({
    name: '',
    urls: ''
  });

  const handleSubdomainSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: subdomainForm.name,
        scan_type: 'subdomain',
        target: subdomainForm.domain,
        config: {
          tools: subdomainForm.tools,
          recursive: subdomainForm.recursive
        }
      };

      const response = await api.post('/recon/', payload);
      navigate(`/recon/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleWhoisSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: whoisForm.name,
        scan_type: 'whois',
        target: whoisForm.domain,
        config: {}
      };

      const response = await api.post('/recon/', payload);
      navigate(`/recon/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleDnsSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: dnsForm.name,
        scan_type: 'dns',
        target: dnsForm.domain,
        config: {
          record_types: dnsForm.record_types
        }
      };

      const response = await api.post('/recon/', payload);
      navigate(`/recon/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleTechSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // Pass all URLs as target (comma-separated), backend will parse them
      const urls = techForm.urls.split('\n').map(u => u.trim()).filter(u => u);
      const payload = {
        name: techForm.name,
        scan_type: 'tech',
        target: urls.join(','),
        config: {
          urls: urls
        }
      };

      const response = await api.post('/recon/', payload);
      navigate(`/recon/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const toggleTool = (tool) => {
    const tools = subdomainForm.tools.includes(tool)
      ? subdomainForm.tools.filter(t => t !== tool)
      : [...subdomainForm.tools, tool];
    setSubdomainForm({ ...subdomainForm, tools });
  };

  const toggleRecordType = (type) => {
    const types = dnsForm.record_types.includes(type)
      ? dnsForm.record_types.filter(t => t !== type)
      : [...dnsForm.record_types, type];
    setDnsForm({ ...dnsForm, record_types: types });
  };

  return (
    <div className="new-recon-scan">
      <h1>Create Recon Scan</h1>

      {error && <div className="error-message">{error}</div>}

      <div className="scan-type-tabs">
        <button
          className={`scan-type-tab ${activeScanType === 'subdomain' ? 'active' : ''}`}
          onClick={() => setActiveScanType('subdomain')}
        >
          🌐 Subdomain Enumeration
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'whois' ? 'active' : ''}`}
          onClick={() => setActiveScanType('whois')}
        >
          📋 WHOIS Lookup
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'dns' ? 'active' : ''}`}
          onClick={() => setActiveScanType('dns')}
        >
          🔗 DNS Records
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'tech' ? 'active' : ''}`}
          onClick={() => setActiveScanType('tech')}
        >
          🔧 Tech Detection
        </button>
      </div>

      {/* Subdomain Enumeration Form */}
      {activeScanType === 'subdomain' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>🌐 Subdomain Enumeration</h2>
            <p>Discover subdomains using Subfinder and Amass</p>
          </div>

          <form onSubmit={handleSubdomainSubmit}>
            <div className="form-group">
              <label htmlFor="subdomain-name">Scan Name *</label>
              <input
                type="text"
                id="subdomain-name"
                value={subdomainForm.name}
                onChange={(e) => setSubdomainForm({...subdomainForm, name: e.target.value})}
                placeholder="e.g., Example.com Subdomain Scan"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="subdomain-domain">Target Domain *</label>
              <input
                type="text"
                id="subdomain-domain"
                value={subdomainForm.domain}
                onChange={(e) => setSubdomainForm({...subdomainForm, domain: e.target.value})}
                placeholder="e.g., example.com"
                required
              />
              <small>Enter the root domain without http/https</small>
            </div>

            <div className="form-group">
              <label>Tools to Use</label>
              <div className="checkbox-grid">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={subdomainForm.tools.includes('subfinder')}
                    onChange={() => toggleTool('subfinder')}
                  />
                  Subfinder (Fast, passive)
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={subdomainForm.tools.includes('amass')}
                    onChange={() => toggleTool('amass')}
                  />
                  Amass (Comprehensive, slower)
                </label>
              </div>
            </div>

            <div className="form-group checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={subdomainForm.recursive}
                  onChange={(e) => setSubdomainForm({...subdomainForm, recursive: e.target.checked})}
                />
                Enable Recursive Enumeration (scan found subdomains)
              </label>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/recon')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading || subdomainForm.tools.length === 0}>
                {loading ? 'Creating...' : 'Start Subdomain Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* WHOIS Lookup Form */}
      {activeScanType === 'whois' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>📋 WHOIS Lookup</h2>
            <p>Get domain registration and ownership information</p>
          </div>

          <form onSubmit={handleWhoisSubmit}>
            <div className="form-group">
              <label htmlFor="whois-name">Scan Name *</label>
              <input
                type="text"
                id="whois-name"
                value={whoisForm.name}
                onChange={(e) => setWhoisForm({...whoisForm, name: e.target.value})}
                placeholder="e.g., Example.com WHOIS"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="whois-domain">Target Domain *</label>
              <input
                type="text"
                id="whois-domain"
                value={whoisForm.domain}
                onChange={(e) => setWhoisForm({...whoisForm, domain: e.target.value})}
                placeholder="e.g., example.com"
                required
              />
              <small>Enter the domain to lookup WHOIS information</small>
            </div>

            <div className="info-box">
              <h4>Information Retrieved:</h4>
              <ul>
                <li>Registrar information</li>
                <li>Registration and expiration dates</li>
                <li>Name servers</li>
                <li>Registrant contact (if available)</li>
                <li>Domain status</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/recon')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start WHOIS Lookup'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* DNS Records Form */}
      {activeScanType === 'dns' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>🔗 DNS Records</h2>
            <p>Query DNS records for a domain</p>
          </div>

          <form onSubmit={handleDnsSubmit}>
            <div className="form-group">
              <label htmlFor="dns-name">Scan Name *</label>
              <input
                type="text"
                id="dns-name"
                value={dnsForm.name}
                onChange={(e) => setDnsForm({...dnsForm, name: e.target.value})}
                placeholder="e.g., Example.com DNS Records"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="dns-domain">Target Domain *</label>
              <input
                type="text"
                id="dns-domain"
                value={dnsForm.domain}
                onChange={(e) => setDnsForm({...dnsForm, domain: e.target.value})}
                placeholder="e.g., example.com"
                required
              />
              <small>Enter the domain to query DNS records</small>
            </div>

            <div className="form-group">
              <label>Record Types</label>
              <div className="checkbox-grid">
                {['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV'].map(type => (
                  <label key={type} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={dnsForm.record_types.includes(type)}
                      onChange={() => toggleRecordType(type)}
                    />
                    {type}
                  </label>
                ))}
              </div>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/recon')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading || dnsForm.record_types.length === 0}>
                {loading ? 'Creating...' : 'Start DNS Lookup'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tech Detection Form */}
      {activeScanType === 'tech' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>🔧 Technology Detection</h2>
            <p>Detect technologies, frameworks, and services using httpx</p>
          </div>

          <form onSubmit={handleTechSubmit}>
            <div className="form-group">
              <label htmlFor="tech-name">Scan Name *</label>
              <input
                type="text"
                id="tech-name"
                value={techForm.name}
                onChange={(e) => setTechForm({...techForm, name: e.target.value})}
                placeholder="e.g., Example.com Tech Stack"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="tech-urls">Target URLs (one per line) *</label>
              <textarea
                id="tech-urls"
                value={techForm.urls}
                onChange={(e) => setTechForm({...techForm, urls: e.target.value})}
                placeholder="https://example.com&#10;https://app.example.com&#10;https://api.example.com"
                rows="6"
                required
              />
              <small>Enter URLs including http/https protocol</small>
            </div>

            <div className="info-box">
              <h4>Information Detected:</h4>
              <ul>
                <li>Web servers (nginx, Apache, IIS, etc.)</li>
                <li>Programming languages and frameworks</li>
                <li>CMS platforms (WordPress, Drupal, etc.)</li>
                <li>JavaScript libraries</li>
                <li>CDN and hosting providers</li>
                <li>Security headers and SSL info</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/recon')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Tech Detection'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

export default NewReconScan;
