import React, { useState, useEffect } from 'react';
import api from '../services/api';
import './Templates.css';

function Templates() {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    scan_type: '',
    nmap_arguments: '',
    is_default: false
  });
  const [error, setError] = useState('');

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      const response = await api.get('/templates/');
      setTemplates(response.data);
    } catch (error) {
      console.error('Error loading templates:', error);
      setError('Failed to load templates');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    setEditingTemplate(null);
    setFormData({
      name: '',
      description: '',
      scan_type: '',
      nmap_arguments: '',
      is_default: false
    });
    setError('');
    setShowModal(true);
  };

  const handleEdit = (template) => {
    setEditingTemplate(template);
    setFormData({
      name: template.name,
      description: template.description || '',
      scan_type: template.scan_type,
      nmap_arguments: template.nmap_arguments || '',
      is_default: template.is_default
    });
    setError('');
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    try {
      if (editingTemplate) {
        await api.put(`/templates/${editingTemplate.id}`, formData);
      } else {
        await api.post('/templates/', formData);
      }

      setShowModal(false);
      loadTemplates();
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to save template');
    }
  };

  const handleDelete = async (id) => {
    try {
      await api.delete(`/templates/${id}`);
      setDeleteConfirm(null);
      loadTemplates();
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to delete template');
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  if (loading) {
    return <div className="loading">Loading templates...</div>;
  }

  return (
    <div className="templates">
      <div className="page-header">
        <div>
          <h1>Scan Templates</h1>
          <p className="subtitle">
            Pre-configured scan templates for different use cases
          </p>
        </div>
        <button className="btn btn-primary" onClick={handleCreate}>
          + Create New Template
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="templates-grid">
        {templates.map(template => (
          <div key={template.id} className="template-card card">
            <div className="template-header">
              <h3>{template.name}</h3>
              {template.is_default && <span className="badge badge-default">Default</span>}
            </div>

            <p className="template-description">{template.description}</p>

            <div className="template-details">
              <div className="detail-row">
                <span className="detail-label">Type:</span>
                <span className="detail-value">{template.scan_type}</span>
              </div>

              <div className="detail-row">
                <span className="detail-label">Arguments:</span>
                <code className="detail-value">{template.nmap_arguments}</code>
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

            <div className="template-actions">
              <button
                className="btn btn-secondary"
                onClick={() => handleEdit(template)}
              >
                Edit
              </button>
              <button
                className="btn btn-danger"
                onClick={() => setDeleteConfirm(template)}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{editingTemplate ? 'Edit Template' : 'Create New Template'}</h2>
              <button className="modal-close" onClick={() => setShowModal(false)}>×</button>
            </div>

            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label htmlFor="name">Template Name *</label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  required
                  placeholder="e.g., Custom Web Scan"
                />
              </div>

              <div className="form-group">
                <label htmlFor="description">Description</label>
                <textarea
                  id="description"
                  name="description"
                  value={formData.description}
                  onChange={handleChange}
                  rows="3"
                  placeholder="Describe what this template does..."
                />
              </div>

              <div className="form-group">
                <label htmlFor="scan_type">Scan Type *</label>
                <input
                  type="text"
                  id="scan_type"
                  name="scan_type"
                  value={formData.scan_type}
                  onChange={handleChange}
                  required
                  placeholder="e.g., custom_web"
                />
              </div>

              <div className="form-group">
                <label htmlFor="nmap_arguments">Nmap Arguments *</label>
                <input
                  type="text"
                  id="nmap_arguments"
                  name="nmap_arguments"
                  value={formData.nmap_arguments}
                  onChange={handleChange}
                  required
                  placeholder="e.g., -p 80,443 -sV -T4"
                />
                <small>Nmap command line arguments for this scan</small>
              </div>

              <div className="form-group checkbox-group">
                <label>
                  <input
                    type="checkbox"
                    name="is_default"
                    checked={formData.is_default}
                    onChange={handleChange}
                  />
                  <span>Set as default template</span>
                </label>
              </div>

              {error && <div className="form-error">{error}</div>}

              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setShowModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  {editingTemplate ? 'Update Template' : 'Create Template'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="modal-overlay" onClick={() => setDeleteConfirm(null)}>
          <div className="modal-content modal-small" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Confirm Delete</h2>
              <button className="modal-close" onClick={() => setDeleteConfirm(null)}>×</button>
            </div>

            <div className="modal-body">
              <p>Are you sure you want to delete the template <strong>"{deleteConfirm.name}"</strong>?</p>
              <p className="warning-text">This action cannot be undone.</p>
            </div>

            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={() => setDeleteConfirm(null)}>
                Cancel
              </button>
              <button className="btn btn-danger" onClick={() => handleDelete(deleteConfirm.id)}>
                Delete Template
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Templates;
