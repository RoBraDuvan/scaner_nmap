import React, { useState, useEffect } from 'react';
import api from '../services/api';
import './Templates.css';

function Templates() {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      const response = await api.get('/templates/');
      setTemplates(response.data);
    } catch (error) {
      console.error('Error loading templates:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading templates...</div>;
  }

  return (
    <div className="templates">
      <h1>Scan Templates</h1>
      <p className="subtitle">
        Pre-configured scan templates for different use cases
      </p>

      <div className="templates-grid">
        {templates.map(template => (
          <div key={template.id} className="template-card card">
            <div className="template-header">
              <h3>{template.name}</h3>
              {template.is_default === 'true' && (
                <span className="default-badge">Default</span>
              )}
            </div>

            <p className="template-description">{template.description}</p>

            <div className="template-details">
              <div className="detail-row">
                <span className="detail-label">Type:</span>
                <span className="detail-value">{template.scan_type}</span>
              </div>

              <div className="detail-row">
                <span className="detail-label">Arguments:</span>
                <code className="detail-code">{template.nmap_arguments}</code>
              </div>

              {template.configuration && (
                <div className="detail-row">
                  <span className="detail-label">Config:</span>
                  <div className="config-details">
                    {template.configuration.timeout && (
                      <span>Timeout: {template.configuration.timeout}s</span>
                    )}
                    {template.configuration.max_hosts && (
                      <span>Max Hosts: {template.configuration.max_hosts}</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Templates;
