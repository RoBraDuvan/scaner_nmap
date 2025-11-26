import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './NewScan.css';
import './NewVulnScan.css';

const GO_API_URL = process.env.REACT_APP_GO_API_URL || 'http://localhost:8001';
const PYTHON_API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const goApi = axios.create({
  baseURL: `${GO_API_URL}/api`,
  headers: { 'Content-Type': 'application/json' },
});

const pythonApi = axios.create({
  baseURL: `${PYTHON_API_URL}/api`,
  headers: { 'Content-Type': 'application/json' },
});

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function NewVulnScan() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    target: '',
    severity: ['medium', 'high', 'critical'],
    tags: [],
  });
  const [tagInput, setTagInput] = useState('');
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      const response = await pythonApi.get('/vulnerability-templates/');
      setTemplates(response.data || []);
    } catch (error) {
      console.error('Error loading vulnerability templates:', error);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const toggleSeverity = (sev) => {
    setFormData(prev => ({
      ...prev,
      severity: prev.severity.includes(sev)
        ? prev.severity.filter(s => s !== sev)
        : [...prev.severity, sev]
    }));
  };

  const addTag = (tag) => {
    const trimmedTag = tag.trim().toLowerCase();
    if (trimmedTag && !formData.tags.includes(trimmedTag)) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, trimmedTag]
      }));
    }
    setTagInput('');
  };

  const removeTag = (tag) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(t => t !== tag)
    }));
  };

  const handleTagKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addTag(tagInput);
    }
  };

  const applyTemplate = (template) => {
    setFormData(prev => ({
      ...prev,
      name: prev.name || template.name,
      tags: template.nuclei_tags || [],
      severity: template.severity_filter || ['medium', 'high', 'critical'],
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
        severity: formData.severity,
        tags: formData.tags.length > 0 ? formData.tags : undefined,
      };

      const response = await goApi.post('/vulnerabilities/', payload);
      navigate(`/vuln-scan/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create vulnerability scan');
    } finally {
      setLoading(false);
    }
  };

  // Group templates by category
  const templatesByCategory = templates.reduce((acc, t) => {
    const cat = t.category || 'other';
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(t);
    return acc;
  }, {});

  return (
    <div className="new-scan">
      <h1>New Vulnerability Scan</h1>

      {error && <div className="error-message">{error}</div>}

      <form onSubmit={handleSubmit} className="scan-form card vuln-scan-form">
        <div className="form-group">
          <label htmlFor="name">Scan Name *</label>
          <input
            type="text"
            id="name"
            name="name"
            value={formData.name}
            onChange={handleChange}
            placeholder="e.g., Production Web Security Scan"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="target">Target URL/IP *</label>
          <input
            type="text"
            id="target"
            name="target"
            value={formData.target}
            onChange={handleChange}
            placeholder="e.g., https://example.com, 192.168.1.100"
            required
          />
          <small>URL or IP address to scan for vulnerabilities</small>
        </div>

        <div className="form-group">
          <label>Severity Levels</label>
          <div className="severity-checkboxes">
            {SEVERITIES.map(sev => (
              <label
                key={sev}
                className={`severity-checkbox ${formData.severity.includes(sev) ? 'selected' : ''}`}
              >
                <input
                  type="checkbox"
                  checked={formData.severity.includes(sev)}
                  onChange={() => toggleSeverity(sev)}
                />
                <span className={`indicator ${sev}`} />
                <span>{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
              </label>
            ))}
          </div>
          <small>Select which severity levels to scan for</small>
        </div>

        <div className="form-group">
          <label>Nuclei Tags</label>
          <div className="tags-input-container">
            {formData.tags.map(tag => (
              <span key={tag} className="tag-pill">
                {tag}
                <button type="button" onClick={() => removeTag(tag)}>×</button>
              </span>
            ))}
            <input
              type="text"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={handleTagKeyDown}
              onBlur={() => tagInput && addTag(tagInput)}
              placeholder="Add tag and press Enter"
            />
          </div>
          <small>
            Filter by Nuclei template tags (e.g., cve, xss, sqli, wordpress, tech).
            Leave empty to use all templates.
          </small>
        </div>

        <div className="form-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate('/vulnerabilities')}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
          >
            {loading ? 'Creating...' : 'Start Vulnerability Scan'}
          </button>
        </div>
      </form>

      {templates.length > 0 && (
        <div className="preset-templates card">
          <h2>Quick Start Templates</h2>
          <div className="templates-by-category">
            {Object.entries(templatesByCategory).map(([category, catTemplates]) => (
              <div key={category} className="category-section">
                <h3>{category}</h3>
                <div className="template-cards">
                  {catTemplates.map(template => (
                    <div
                      key={template.id}
                      className="preset-card"
                      onClick={() => applyTemplate(template)}
                    >
                      <h4>{template.name}</h4>
                      <p>{template.description}</p>
                      <div className="preset-tags">
                        {template.nuclei_tags?.slice(0, 3).map(tag => (
                          <span key={tag} className="preset-tag">{tag}</span>
                        ))}
                        {template.severity_filter?.slice(0, 2).map(sev => (
                          <span key={sev} className="preset-tag severity">{sev}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default NewVulnScan;
