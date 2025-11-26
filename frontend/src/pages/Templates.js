import React, { useState, useEffect } from 'react';
import api from '../services/api';
import './Templates.css';

function Templates() {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const [filterScanner, setFilterScanner] = useState('all');
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

  // Determine scanner type from scan_type
  const getScannerType = (scanType) => {
    if (!scanType) return 'nmap';
    const lower = scanType.toLowerCase();
    if (lower.startsWith('masscan')) return 'masscan';
    if (lower.startsWith('dns')) return 'dns';
    return 'nmap';
  };

  // Filter templates by scanner
  const filteredTemplates = filterScanner === 'all'
    ? templates
    : templates.filter(t => getScannerType(t.scan_type) === filterScanner);

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

      <div className="filters-container">
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

      {filteredTemplates.length === 0 ? (
        <div className="card empty-state">
          <h3>No templates found</h3>
          <p>Create a new template to get started</p>
          <button className="btn btn-primary" onClick={handleCreate}>
            Create your first template
          </button>
        </div>
      ) : (
        <div className="card templates-table">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Scanner</th>
                <th>Scan Type</th>
                <th>Arguments</th>
                <th>Default</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredTemplates.map(template => {
                const scannerType = getScannerType(template.scan_type);
                const scannerIcons = { nmap: '🔍', masscan: '⚡', dns: '🌐' };
                return (
                  <tr key={template.id}>
                    <td>
                      <span className="template-name">{template.name}</span>
                    </td>
                    <td className="description-cell" title={template.description}>
                      {template.description || '-'}
                    </td>
                    <td>
                      <span className={`scanner-badge scanner-${scannerType}`}>
                        {scannerIcons[scannerType]} {scannerType}
                      </span>
                    </td>
                    <td>
                      <span className="type-badge">{template.scan_type}</span>
                    </td>
                    <td>
                      <code className="args-code">{template.nmap_arguments || '-'}</code>
                    </td>
                    <td>
                      {template.is_default ? (
                        <span className="default-badge">Default</span>
                      ) : (
                        <span className="not-default">-</span>
                      )}
                    </td>
                    <td>
                      <div className="actions-cell">
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleEdit(template)}
                        >
                          Edit
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => setDeleteConfirm(template)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

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
