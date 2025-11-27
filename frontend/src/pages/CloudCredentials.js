import React, { useState, useEffect } from 'react';
import api from '../services/api';
import './CloudCredentials.css';

function CloudCredentials() {
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeProvider, setActiveProvider] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // AWS form
  const [awsForm, setAwsForm] = useState({
    access_key_id: '',
    secret_access_key: '',
    region: 'us-east-1',
    profile_name: 'default'
  });

  // GCP form
  const [gcpForm, setGcpForm] = useState({
    service_account_json: '',
    project_id: ''
  });

  // Azure form
  const [azureForm, setAzureForm] = useState({
    tenant_id: '',
    client_id: '',
    client_secret: '',
    subscription_id: ''
  });

  useEffect(() => {
    loadCredentials();
  }, []);

  const loadCredentials = async () => {
    try {
      const response = await api.get('/credentials/');
      setCredentials(response.data.credentials || []);
    } catch (err) {
      console.error('Error loading credentials:', err);
    } finally {
      setLoading(false);
    }
  };

  const getProviderStatus = (provider) => {
    const cred = credentials.find(c => c.provider === provider);
    return cred || { provider, configured: false };
  };

  const handleAWSSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    try {
      await api.post('/credentials/aws', awsForm);
      setSuccess('AWS credentials configured successfully');
      loadCredentials();
      setActiveProvider(null);
      setAwsForm({ access_key_id: '', secret_access_key: '', region: 'us-east-1', profile_name: 'default' });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to configure AWS credentials');
    }
  };

  const handleGCPSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    try {
      await api.post('/credentials/gcp', gcpForm);
      setSuccess('GCP credentials configured successfully');
      loadCredentials();
      setActiveProvider(null);
      setGcpForm({ service_account_json: '', project_id: '' });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to configure GCP credentials');
    }
  };

  const handleGCPFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    setError('');
    setSuccess('');
    try {
      await api.post('/credentials/gcp/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setSuccess('GCP credentials uploaded successfully');
      loadCredentials();
      setActiveProvider(null);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to upload GCP credentials');
    }
  };

  const handleAzureSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    try {
      await api.post('/credentials/azure', azureForm);
      setSuccess('Azure credentials configured successfully');
      loadCredentials();
      setActiveProvider(null);
      setAzureForm({ tenant_id: '', client_id: '', client_secret: '', subscription_id: '' });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to configure Azure credentials');
    }
  };

  const handleDelete = async (provider) => {
    if (!window.confirm(`Are you sure you want to remove ${provider.toUpperCase()} credentials?`)) {
      return;
    }
    setError('');
    setSuccess('');
    try {
      await api.delete(`/credentials/${provider}`);
      setSuccess(`${provider.toUpperCase()} credentials removed`);
      loadCredentials();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to remove credentials');
    }
  };

  const getProviderIcon = (provider) => {
    switch (provider) {
      case 'aws': return '☁️';
      case 'gcp': return '🔶';
      case 'azure': return '🔷';
      default: return '☁️';
    }
  };

  if (loading) {
    return <div className="loading">Loading credentials...</div>;
  }

  return (
    <div className="cloud-credentials">
      <div className="page-header">
        <h1>Cloud Credentials</h1>
        <p className="page-description">
          Configure cloud provider credentials to enable security scanning with Prowler and ScoutSuite.
        </p>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="credentials-grid">
        {/* AWS */}
        <div className={`credential-card ${getProviderStatus('aws').configured ? 'configured' : ''}`}>
          <div className="card-header">
            <div className="provider-info">
              <span className="provider-icon">{getProviderIcon('aws')}</span>
              <div>
                <h3>Amazon Web Services</h3>
                <span className={`status ${getProviderStatus('aws').configured ? 'active' : 'inactive'}`}>
                  {getProviderStatus('aws').configured ? 'Configured' : 'Not Configured'}
                </span>
              </div>
            </div>
            <div className="card-actions">
              {getProviderStatus('aws').configured && (
                <button className="btn btn-danger btn-sm" onClick={() => handleDelete('aws')}>
                  Remove
                </button>
              )}
              <button
                className="btn btn-primary btn-sm"
                onClick={() => setActiveProvider(activeProvider === 'aws' ? null : 'aws')}
              >
                {activeProvider === 'aws' ? 'Cancel' : (getProviderStatus('aws').configured ? 'Update' : 'Configure')}
              </button>
            </div>
          </div>

          {getProviderStatus('aws').configured && !activeProvider && (
            <div className="credential-details">
              <div className="detail-item">
                <span className="label">Account ID:</span>
                <span className="value">{getProviderStatus('aws').account_id || 'N/A'}</span>
              </div>
              <div className="detail-item">
                <span className="label">Region:</span>
                <span className="value">{getProviderStatus('aws').region || 'us-east-1'}</span>
              </div>
            </div>
          )}

          {activeProvider === 'aws' && (
            <form className="credential-form" onSubmit={handleAWSSubmit}>
              <div className="form-group">
                <label>Access Key ID *</label>
                <input
                  type="text"
                  value={awsForm.access_key_id}
                  onChange={(e) => setAwsForm({...awsForm, access_key_id: e.target.value})}
                  placeholder="AKIAIOSFODNN7EXAMPLE"
                  required
                />
              </div>
              <div className="form-group">
                <label>Secret Access Key *</label>
                <input
                  type="password"
                  value={awsForm.secret_access_key}
                  onChange={(e) => setAwsForm({...awsForm, secret_access_key: e.target.value})}
                  placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                  required
                />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Region</label>
                  <select
                    value={awsForm.region}
                    onChange={(e) => setAwsForm({...awsForm, region: e.target.value})}
                  >
                    <option value="us-east-1">US East (N. Virginia)</option>
                    <option value="us-east-2">US East (Ohio)</option>
                    <option value="us-west-1">US West (N. California)</option>
                    <option value="us-west-2">US West (Oregon)</option>
                    <option value="eu-west-1">EU (Ireland)</option>
                    <option value="eu-west-2">EU (London)</option>
                    <option value="eu-central-1">EU (Frankfurt)</option>
                    <option value="ap-northeast-1">Asia Pacific (Tokyo)</option>
                    <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                    <option value="ap-southeast-2">Asia Pacific (Sydney)</option>
                    <option value="sa-east-1">South America (São Paulo)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Profile Name</label>
                  <input
                    type="text"
                    value={awsForm.profile_name}
                    onChange={(e) => setAwsForm({...awsForm, profile_name: e.target.value})}
                    placeholder="default"
                  />
                </div>
              </div>
              <button type="submit" className="btn btn-primary">Save AWS Credentials</button>
            </form>
          )}
        </div>

        {/* GCP */}
        <div className={`credential-card ${getProviderStatus('gcp').configured ? 'configured' : ''}`}>
          <div className="card-header">
            <div className="provider-info">
              <span className="provider-icon">{getProviderIcon('gcp')}</span>
              <div>
                <h3>Google Cloud Platform</h3>
                <span className={`status ${getProviderStatus('gcp').configured ? 'active' : 'inactive'}`}>
                  {getProviderStatus('gcp').configured ? 'Configured' : 'Not Configured'}
                </span>
              </div>
            </div>
            <div className="card-actions">
              {getProviderStatus('gcp').configured && (
                <button className="btn btn-danger btn-sm" onClick={() => handleDelete('gcp')}>
                  Remove
                </button>
              )}
              <button
                className="btn btn-primary btn-sm"
                onClick={() => setActiveProvider(activeProvider === 'gcp' ? null : 'gcp')}
              >
                {activeProvider === 'gcp' ? 'Cancel' : (getProviderStatus('gcp').configured ? 'Update' : 'Configure')}
              </button>
            </div>
          </div>

          {getProviderStatus('gcp').configured && !activeProvider && (
            <div className="credential-details">
              <div className="detail-item">
                <span className="label">Project ID:</span>
                <span className="value">{getProviderStatus('gcp').project_id || 'N/A'}</span>
              </div>
            </div>
          )}

          {activeProvider === 'gcp' && (
            <form className="credential-form" onSubmit={handleGCPSubmit}>
              <div className="form-group">
                <label>Service Account JSON File</label>
                <div className="file-upload">
                  <input
                    type="file"
                    accept=".json"
                    onChange={handleGCPFileUpload}
                    id="gcp-file"
                  />
                  <label htmlFor="gcp-file" className="file-label">
                    Choose JSON file or drag here
                  </label>
                </div>
              </div>
              <div className="divider">OR paste JSON content</div>
              <div className="form-group">
                <label>Service Account JSON *</label>
                <textarea
                  value={gcpForm.service_account_json}
                  onChange={(e) => setGcpForm({...gcpForm, service_account_json: e.target.value})}
                  placeholder='{"type": "service_account", "project_id": "...", ...}'
                  rows={6}
                />
              </div>
              <div className="form-group">
                <label>Project ID (optional)</label>
                <input
                  type="text"
                  value={gcpForm.project_id}
                  onChange={(e) => setGcpForm({...gcpForm, project_id: e.target.value})}
                  placeholder="my-project-123"
                />
              </div>
              <button type="submit" className="btn btn-primary" disabled={!gcpForm.service_account_json}>
                Save GCP Credentials
              </button>
            </form>
          )}
        </div>

        {/* Azure */}
        <div className={`credential-card ${getProviderStatus('azure').configured ? 'configured' : ''}`}>
          <div className="card-header">
            <div className="provider-info">
              <span className="provider-icon">{getProviderIcon('azure')}</span>
              <div>
                <h3>Microsoft Azure</h3>
                <span className={`status ${getProviderStatus('azure').configured ? 'active' : 'inactive'}`}>
                  {getProviderStatus('azure').configured ? 'Configured' : 'Not Configured'}
                </span>
              </div>
            </div>
            <div className="card-actions">
              {getProviderStatus('azure').configured && (
                <button className="btn btn-danger btn-sm" onClick={() => handleDelete('azure')}>
                  Remove
                </button>
              )}
              <button
                className="btn btn-primary btn-sm"
                onClick={() => setActiveProvider(activeProvider === 'azure' ? null : 'azure')}
              >
                {activeProvider === 'azure' ? 'Cancel' : (getProviderStatus('azure').configured ? 'Update' : 'Configure')}
              </button>
            </div>
          </div>

          {getProviderStatus('azure').configured && !activeProvider && (
            <div className="credential-details">
              <div className="detail-item">
                <span className="label">Tenant ID:</span>
                <span className="value">{getProviderStatus('azure').tenant_id || 'N/A'}</span>
              </div>
            </div>
          )}

          {activeProvider === 'azure' && (
            <form className="credential-form" onSubmit={handleAzureSubmit}>
              <div className="form-group">
                <label>Tenant ID *</label>
                <input
                  type="text"
                  value={azureForm.tenant_id}
                  onChange={(e) => setAzureForm({...azureForm, tenant_id: e.target.value})}
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  required
                />
              </div>
              <div className="form-group">
                <label>Client ID (App ID) *</label>
                <input
                  type="text"
                  value={azureForm.client_id}
                  onChange={(e) => setAzureForm({...azureForm, client_id: e.target.value})}
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  required
                />
              </div>
              <div className="form-group">
                <label>Client Secret *</label>
                <input
                  type="password"
                  value={azureForm.client_secret}
                  onChange={(e) => setAzureForm({...azureForm, client_secret: e.target.value})}
                  placeholder="Your client secret"
                  required
                />
              </div>
              <div className="form-group">
                <label>Subscription ID</label>
                <input
                  type="text"
                  value={azureForm.subscription_id}
                  onChange={(e) => setAzureForm({...azureForm, subscription_id: e.target.value})}
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                />
              </div>
              <button type="submit" className="btn btn-primary">Save Azure Credentials</button>
            </form>
          )}
        </div>
      </div>

      <div className="info-section card">
        <h3>Getting Cloud Credentials</h3>
        <div className="info-grid">
          <div className="info-item">
            <h4>AWS</h4>
            <p>Create an IAM user with SecurityAudit policy or use AWS CLI to configure credentials.</p>
            <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html" target="_blank" rel="noopener noreferrer">
              AWS Documentation
            </a>
          </div>
          <div className="info-item">
            <h4>GCP</h4>
            <p>Create a service account with Viewer role and download the JSON key file.</p>
            <a href="https://cloud.google.com/iam/docs/service-accounts-create" target="_blank" rel="noopener noreferrer">
              GCP Documentation
            </a>
          </div>
          <div className="info-item">
            <h4>Azure</h4>
            <p>Register an application in Azure AD and create a client secret.</p>
            <a href="https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app" target="_blank" rel="noopener noreferrer">
              Azure Documentation
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CloudCredentials;
