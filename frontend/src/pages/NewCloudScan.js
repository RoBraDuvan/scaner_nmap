import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import './NewCloudScan.css';

function NewCloudScan() {
  const navigate = useNavigate();
  const [activeScanType, setActiveScanType] = useState('trivy');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Trivy form data
  const [trivyForm, setTrivyForm] = useState({
    name: '',
    target: '',
    targetType: 'image',
    severities: ['CRITICAL', 'HIGH', 'MEDIUM'],
    ignoreUnfixed: false
  });

  // Prowler form data
  const [prowlerForm, setProwlerForm] = useState({
    name: '',
    provider: 'aws',
    compliance: ''
  });

  // ScoutSuite form data
  const [scoutsuiteForm, setScoutsuiteForm] = useState({
    name: '',
    provider: 'aws',
    services: ''
  });

  // Full scan form data
  const [fullForm, setFullForm] = useState({
    name: '',
    provider: 'aws',
    target: ''
  });

  const handleTrivySubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: trivyForm.name,
        provider: 'docker',
        scan_type: trivyForm.targetType === 'image' ? 'image' : 'trivy',
        target: trivyForm.target,
        config: {
          trivy_target: trivyForm.target,
          trivy_target_type: trivyForm.targetType,
          trivy_severities: trivyForm.severities,
          trivy_ignore_unfixed: trivyForm.ignoreUnfixed
        }
      };

      const response = await api.post('/cloudscans/', payload);
      navigate(`/cloud-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleProwlerSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: prowlerForm.name,
        provider: prowlerForm.provider,
        scan_type: 'prowler',
        target: prowlerForm.provider,
        config: {
          prowler_compliance: prowlerForm.compliance
        }
      };

      const response = await api.post('/cloudscans/', payload);
      navigate(`/cloud-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleScoutSuiteSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: scoutsuiteForm.name,
        provider: scoutsuiteForm.provider,
        scan_type: 'scoutsuite',
        target: scoutsuiteForm.provider,
        config: {
          scoutsuite_services: scoutsuiteForm.services ? scoutsuiteForm.services.split(',').map(s => s.trim()) : []
        }
      };

      const response = await api.post('/cloudscans/', payload);
      navigate(`/cloud-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleFullSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: fullForm.name,
        provider: fullForm.provider,
        scan_type: 'full',
        target: fullForm.target || fullForm.provider,
        config: {}
      };

      const response = await api.post('/cloudscans/', payload);
      navigate(`/cloud-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const toggleSeverity = (severity) => {
    const sev = trivyForm.severities.includes(severity)
      ? trivyForm.severities.filter(s => s !== severity)
      : [...trivyForm.severities, severity];
    setTrivyForm({ ...trivyForm, severities: sev });
  };

  return (
    <div className="new-cloud-scan">
      <h1>Create Cloud Security Scan</h1>

      {error && <div className="error-message">{error}</div>}

      <div className="scan-type-tabs">
        <button
          className={`scan-type-tab ${activeScanType === 'trivy' ? 'active' : ''}`}
          onClick={() => setActiveScanType('trivy')}
        >
          Trivy
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'prowler' ? 'active' : ''}`}
          onClick={() => setActiveScanType('prowler')}
        >
          Prowler
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'scoutsuite' ? 'active' : ''}`}
          onClick={() => setActiveScanType('scoutsuite')}
        >
          ScoutSuite
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'full' ? 'active' : ''}`}
          onClick={() => setActiveScanType('full')}
        >
          Full Scan
        </button>
      </div>

      {/* Trivy Form */}
      {activeScanType === 'trivy' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>Trivy - Container & IaC Security</h2>
            <p>Scan container images, filesystems, and infrastructure as code</p>
          </div>

          <form onSubmit={handleTrivySubmit}>
            <div className="form-group">
              <label htmlFor="trivy-name">Scan Name *</label>
              <input
                type="text"
                id="trivy-name"
                value={trivyForm.name}
                onChange={(e) => setTrivyForm({...trivyForm, name: e.target.value})}
                placeholder="e.g., Container Scan - nginx:latest"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="trivy-type">Scan Type</label>
              <select
                id="trivy-type"
                value={trivyForm.targetType}
                onChange={(e) => setTrivyForm({...trivyForm, targetType: e.target.value})}
              >
                <option value="image">Container Image</option>
                <option value="fs">Filesystem</option>
                <option value="config">IaC Configuration</option>
                <option value="repo">Git Repository</option>
              </select>
            </div>

            <div className="form-group">
              <label htmlFor="trivy-target">Target *</label>
              <input
                type="text"
                id="trivy-target"
                value={trivyForm.target}
                onChange={(e) => setTrivyForm({...trivyForm, target: e.target.value})}
                placeholder={
                  trivyForm.targetType === 'image' ? 'nginx:latest or myregistry/myimage:tag' :
                  trivyForm.targetType === 'repo' ? 'https://github.com/user/repo' :
                  '/path/to/scan'
                }
                required
              />
              <small>
                {trivyForm.targetType === 'image' && 'Docker image name with optional tag'}
                {trivyForm.targetType === 'fs' && 'Local filesystem path to scan'}
                {trivyForm.targetType === 'config' && 'Path to Terraform, CloudFormation, or Kubernetes files'}
                {trivyForm.targetType === 'repo' && 'Git repository URL'}
              </small>
            </div>

            <div className="form-group">
              <label>Severity Filter</label>
              <div className="checkbox-grid">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                  <label key={sev} className={`checkbox-label severity-${sev.toLowerCase()}`}>
                    <input
                      type="checkbox"
                      checked={trivyForm.severities.includes(sev)}
                      onChange={() => toggleSeverity(sev)}
                    />
                    {sev}
                  </label>
                ))}
              </div>
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={trivyForm.ignoreUnfixed}
                  onChange={(e) => setTrivyForm({...trivyForm, ignoreUnfixed: e.target.checked})}
                />
                Ignore unfixed vulnerabilities
              </label>
              <small>Only show vulnerabilities with available fixes</small>
            </div>

            <div className="info-box">
              <h4>Trivy Scans For:</h4>
              <ul>
                <li>OS package vulnerabilities (Alpine, Debian, Ubuntu, etc.)</li>
                <li>Application dependencies (npm, pip, gem, etc.)</li>
                <li>IaC misconfigurations (Terraform, CloudFormation, K8s)</li>
                <li>Sensitive data and secrets</li>
                <li>License compliance issues</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/cloud-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Trivy Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Prowler Form */}
      {activeScanType === 'prowler' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>Prowler - Cloud Security Audit</h2>
            <p>Comprehensive security assessment for AWS, Azure, and GCP</p>
          </div>

          <form onSubmit={handleProwlerSubmit}>
            <div className="form-group">
              <label htmlFor="prowler-name">Scan Name *</label>
              <input
                type="text"
                id="prowler-name"
                value={prowlerForm.name}
                onChange={(e) => setProwlerForm({...prowlerForm, name: e.target.value})}
                placeholder="e.g., AWS Security Audit - Production"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="prowler-provider">Cloud Provider *</label>
              <select
                id="prowler-provider"
                value={prowlerForm.provider}
                onChange={(e) => setProwlerForm({...prowlerForm, provider: e.target.value})}
              >
                <option value="aws">Amazon Web Services (AWS)</option>
                <option value="azure">Microsoft Azure</option>
                <option value="gcp">Google Cloud Platform (GCP)</option>
              </select>
              <small>Credentials must be configured in Cloud Credentials</small>
            </div>

            <div className="form-group">
              <label htmlFor="prowler-compliance">Compliance Framework (optional)</label>
              <select
                id="prowler-compliance"
                value={prowlerForm.compliance}
                onChange={(e) => setProwlerForm({...prowlerForm, compliance: e.target.value})}
              >
                <option value="">All checks</option>
                <option value="cis_1.4">CIS AWS Foundations 1.4</option>
                <option value="cis_1.5">CIS AWS Foundations 1.5</option>
                <option value="pci_3.2.1">PCI-DSS 3.2.1</option>
                <option value="hipaa">HIPAA</option>
                <option value="gdpr">GDPR</option>
                <option value="soc2">SOC 2</option>
              </select>
            </div>

            <div className="info-box info-box-warning">
              <h4>Prowler Checks Include:</h4>
              <ul>
                <li>Identity and Access Management (IAM)</li>
                <li>Logging and monitoring configuration</li>
                <li>Network security (VPC, Security Groups)</li>
                <li>Data encryption (S3, EBS, RDS)</li>
                <li>Compliance with industry standards</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/cloud-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Prowler Audit'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ScoutSuite Form */}
      {activeScanType === 'scoutsuite' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>ScoutSuite - Multi-Cloud Security</h2>
            <p>Security auditing tool for AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud</p>
          </div>

          <form onSubmit={handleScoutSuiteSubmit}>
            <div className="form-group">
              <label htmlFor="scout-name">Scan Name *</label>
              <input
                type="text"
                id="scout-name"
                value={scoutsuiteForm.name}
                onChange={(e) => setScoutsuiteForm({...scoutsuiteForm, name: e.target.value})}
                placeholder="e.g., Cloud Config Audit - AWS Prod"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="scout-provider">Cloud Provider *</label>
              <select
                id="scout-provider"
                value={scoutsuiteForm.provider}
                onChange={(e) => setScoutsuiteForm({...scoutsuiteForm, provider: e.target.value})}
              >
                <option value="aws">Amazon Web Services (AWS)</option>
                <option value="azure">Microsoft Azure</option>
                <option value="gcp">Google Cloud Platform (GCP)</option>
              </select>
              <small>Credentials must be configured in Cloud Credentials</small>
            </div>

            <div className="form-group">
              <label htmlFor="scout-services">Services (optional)</label>
              <input
                type="text"
                id="scout-services"
                value={scoutsuiteForm.services}
                onChange={(e) => setScoutsuiteForm({...scoutsuiteForm, services: e.target.value})}
                placeholder="iam, s3, ec2, rds"
              />
              <small>Comma-separated list of services to audit (default: all)</small>
            </div>

            <div className="info-box">
              <h4>ScoutSuite Analyzes:</h4>
              <ul>
                <li>Service configurations across your cloud</li>
                <li>Security best practices compliance</li>
                <li>Dangerous settings and misconfigurations</li>
                <li>Resource permissions and access policies</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/cloud-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start ScoutSuite Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Full Scan Form */}
      {activeScanType === 'full' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>Full Cloud Security Scan</h2>
            <p>Comprehensive scan combining ScoutSuite, Prowler, and Trivy</p>
          </div>

          <form onSubmit={handleFullSubmit}>
            <div className="form-group">
              <label htmlFor="full-name">Scan Name *</label>
              <input
                type="text"
                id="full-name"
                value={fullForm.name}
                onChange={(e) => setFullForm({...fullForm, name: e.target.value})}
                placeholder="e.g., Complete Security Audit - Production"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="full-provider">Cloud Provider *</label>
              <select
                id="full-provider"
                value={fullForm.provider}
                onChange={(e) => setFullForm({...fullForm, provider: e.target.value})}
              >
                <option value="aws">Amazon Web Services (AWS)</option>
                <option value="azure">Microsoft Azure</option>
                <option value="gcp">Google Cloud Platform (GCP)</option>
              </select>
              <small>Credentials must be configured in Cloud Credentials</small>
            </div>

            <div className="form-group">
              <label htmlFor="full-target">Container Image (optional)</label>
              <input
                type="text"
                id="full-target"
                value={fullForm.target}
                onChange={(e) => setFullForm({...fullForm, target: e.target.value})}
                placeholder="nginx:latest"
              />
              <small>If provided, Trivy will also scan this container image</small>
            </div>

            <div className="info-box info-box-highlight">
              <h4>Full Scan Includes:</h4>
              <ol>
                <li><strong>ScoutSuite</strong> - Configuration audit across all services</li>
                <li><strong>Prowler</strong> - Compliance and security checks</li>
                <li><strong>Trivy</strong> - Container vulnerability scan (if target provided)</li>
              </ol>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/cloud-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Full Cloud Scan'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

export default NewCloudScan;
