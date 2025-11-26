import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import './NewAPIScan.css';

function NewAPIScan() {
  const navigate = useNavigate();
  const [activeScanType, setActiveScanType] = useState('kiterunner');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Kiterunner form data
  const [kiterunnerForm, setKiterunnerForm] = useState({
    name: '',
    target: '',
    wordlist: 'routes-large',
    threads: 10,
    timeout: 10
  });

  // Arjun form data
  const [arjunForm, setArjunForm] = useState({
    name: '',
    target: '',
    methods: ['GET', 'POST'],
    threads: 10
  });

  // GraphQL form data
  const [graphqlForm, setGraphqlForm] = useState({
    name: '',
    target: ''
  });

  // Swagger form data
  const [swaggerForm, setSwaggerForm] = useState({
    name: '',
    target: ''
  });

  // Full scan form data
  const [fullForm, setFullForm] = useState({
    name: '',
    target: '',
    kiterunnerWordlist: 'routes-large',
    arjunMethods: ['GET', 'POST'],
    threads: 10
  });

  const kiterunnerWordlists = [
    { value: 'routes-large', label: 'Routes Large (Full API Discovery)' },
    { value: 'routes-small', label: 'Routes Small (Quick Scan)' }
  ];

  const handleKiterunnerSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: kiterunnerForm.name,
        scan_type: 'kiterunner',
        target: kiterunnerForm.target,
        config: {
          kiterunner_wordlist: kiterunnerForm.wordlist,
          threads: kiterunnerForm.threads,
          timeout: kiterunnerForm.timeout
        }
      };

      const response = await api.post('/apiscans/', payload);
      navigate(`/api-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleArjunSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: arjunForm.name,
        scan_type: 'arjun',
        target: arjunForm.target,
        config: {
          arjun_methods: arjunForm.methods,
          arjun_threads: arjunForm.threads
        }
      };

      const response = await api.post('/apiscans/', payload);
      navigate(`/api-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleGraphQLSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: graphqlForm.name,
        scan_type: 'graphql',
        target: graphqlForm.target,
        config: {}
      };

      const response = await api.post('/apiscans/', payload);
      navigate(`/api-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleSwaggerSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: swaggerForm.name,
        scan_type: 'swagger',
        target: swaggerForm.target,
        config: {}
      };

      const response = await api.post('/apiscans/', payload);
      navigate(`/api-scans/${response.data.id}`);
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
        scan_type: 'full',
        target: fullForm.target,
        config: {
          kiterunner_wordlist: fullForm.kiterunnerWordlist,
          arjun_methods: fullForm.arjunMethods,
          threads: fullForm.threads
        }
      };

      const response = await api.post('/apiscans/', payload);
      navigate(`/api-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const toggleArjunMethod = (method) => {
    const methods = arjunForm.methods.includes(method)
      ? arjunForm.methods.filter(m => m !== method)
      : [...arjunForm.methods, method];
    setArjunForm({ ...arjunForm, methods });
  };

  const toggleFullMethod = (method) => {
    const methods = fullForm.arjunMethods.includes(method)
      ? fullForm.arjunMethods.filter(m => m !== method)
      : [...fullForm.arjunMethods, method];
    setFullForm({ ...fullForm, arjunMethods: methods });
  };

  return (
    <div className="new-api-scan">
      <h1>Create API Discovery Scan</h1>

      {error && <div className="error-message">{error}</div>}

      <div className="scan-type-tabs">
        <button
          className={`scan-type-tab ${activeScanType === 'kiterunner' ? 'active' : ''}`}
          onClick={() => setActiveScanType('kiterunner')}
        >
          Kiterunner
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'arjun' ? 'active' : ''}`}
          onClick={() => setActiveScanType('arjun')}
        >
          Arjun
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'graphql' ? 'active' : ''}`}
          onClick={() => setActiveScanType('graphql')}
        >
          GraphQL
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'swagger' ? 'active' : ''}`}
          onClick={() => setActiveScanType('swagger')}
        >
          Swagger
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'full' ? 'active' : ''}`}
          onClick={() => setActiveScanType('full')}
        >
          Full Scan
        </button>
      </div>

      {/* Kiterunner Form */}
      {activeScanType === 'kiterunner' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>Kiterunner - API Endpoint Discovery</h2>
            <p>Discover API endpoints using context-aware content discovery</p>
          </div>

          <form onSubmit={handleKiterunnerSubmit}>
            <div className="form-group">
              <label htmlFor="kr-name">Scan Name *</label>
              <input
                type="text"
                id="kr-name"
                value={kiterunnerForm.name}
                onChange={(e) => setKiterunnerForm({...kiterunnerForm, name: e.target.value})}
                placeholder="e.g., API Scan - example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="kr-target">Target URL *</label>
              <input
                type="url"
                id="kr-target"
                value={kiterunnerForm.target}
                onChange={(e) => setKiterunnerForm({...kiterunnerForm, target: e.target.value})}
                placeholder="https://api.example.com"
                required
              />
              <small>Enter the base URL of the API to scan</small>
            </div>

            <div className="form-group">
              <label htmlFor="kr-wordlist">Wordlist</label>
              <select
                id="kr-wordlist"
                value={kiterunnerForm.wordlist}
                onChange={(e) => setKiterunnerForm({...kiterunnerForm, wordlist: e.target.value})}
              >
                {kiterunnerWordlists.map(wl => (
                  <option key={wl.value} value={wl.value}>{wl.label}</option>
                ))}
              </select>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="kr-threads">Threads</label>
                <input
                  type="number"
                  id="kr-threads"
                  value={kiterunnerForm.threads}
                  onChange={(e) => setKiterunnerForm({...kiterunnerForm, threads: parseInt(e.target.value) || 10})}
                  min="1"
                  max="50"
                />
              </div>

              <div className="form-group">
                <label htmlFor="kr-timeout">Timeout (sec)</label>
                <input
                  type="number"
                  id="kr-timeout"
                  value={kiterunnerForm.timeout}
                  onChange={(e) => setKiterunnerForm({...kiterunnerForm, timeout: parseInt(e.target.value) || 10})}
                  min="1"
                  max="60"
                />
              </div>
            </div>

            <div className="info-box">
              <h4>What Kiterunner Discovers:</h4>
              <ul>
                <li>Hidden API endpoints</li>
                <li>REST API routes</li>
                <li>Administrative endpoints</li>
                <li>Undocumented APIs</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/api-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Kiterunner Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Arjun Form */}
      {activeScanType === 'arjun' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>Arjun - Parameter Discovery</h2>
            <p>Discover hidden HTTP parameters for API endpoints</p>
          </div>

          <form onSubmit={handleArjunSubmit}>
            <div className="form-group">
              <label htmlFor="arjun-name">Scan Name *</label>
              <input
                type="text"
                id="arjun-name"
                value={arjunForm.name}
                onChange={(e) => setArjunForm({...arjunForm, name: e.target.value})}
                placeholder="e.g., Parameter Discovery - api.example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="arjun-target">Target URLs * (one per line or comma-separated)</label>
              <textarea
                id="arjun-target"
                value={arjunForm.target}
                onChange={(e) => setArjunForm({...arjunForm, target: e.target.value})}
                placeholder="https://api.example.com/users&#10;https://api.example.com/products"
                rows="4"
                required
              />
              <small>Enter API endpoint URLs to test for hidden parameters</small>
            </div>

            <div className="form-group">
              <label>HTTP Methods to Test</label>
              <div className="checkbox-grid">
                {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map(method => (
                  <label key={method} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={arjunForm.methods.includes(method)}
                      onChange={() => toggleArjunMethod(method)}
                    />
                    {method}
                  </label>
                ))}
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="arjun-threads">Threads</label>
              <input
                type="number"
                id="arjun-threads"
                value={arjunForm.threads}
                onChange={(e) => setArjunForm({...arjunForm, threads: parseInt(e.target.value) || 10})}
                min="1"
                max="50"
              />
            </div>

            <div className="info-box">
              <h4>What Arjun Discovers:</h4>
              <ul>
                <li>Hidden query parameters</li>
                <li>POST body parameters</li>
                <li>Debug parameters</li>
                <li>Authentication bypasses</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/api-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading || arjunForm.methods.length === 0}>
                {loading ? 'Creating...' : 'Start Arjun Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* GraphQL Form */}
      {activeScanType === 'graphql' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>GraphQL Introspection</h2>
            <p>Extract and analyze GraphQL schema via introspection</p>
          </div>

          <form onSubmit={handleGraphQLSubmit}>
            <div className="form-group">
              <label htmlFor="gql-name">Scan Name *</label>
              <input
                type="text"
                id="gql-name"
                value={graphqlForm.name}
                onChange={(e) => setGraphqlForm({...graphqlForm, name: e.target.value})}
                placeholder="e.g., GraphQL Schema - api.example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="gql-target">GraphQL Endpoint URL *</label>
              <input
                type="url"
                id="gql-target"
                value={graphqlForm.target}
                onChange={(e) => setGraphqlForm({...graphqlForm, target: e.target.value})}
                placeholder="https://api.example.com/graphql"
                required
              />
              <small>Enter the GraphQL endpoint (usually /graphql or /gql)</small>
            </div>

            <div className="info-box">
              <h4>What GraphQL Introspection Discovers:</h4>
              <ul>
                <li>All available queries</li>
                <li>Mutations and subscriptions</li>
                <li>Types and fields</li>
                <li>Input types and arguments</li>
                <li>Enums and directives</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/api-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start GraphQL Introspection'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Swagger Form */}
      {activeScanType === 'swagger' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>Swagger/OpenAPI Discovery</h2>
            <p>Find and parse OpenAPI/Swagger specifications</p>
          </div>

          <form onSubmit={handleSwaggerSubmit}>
            <div className="form-group">
              <label htmlFor="swagger-name">Scan Name *</label>
              <input
                type="text"
                id="swagger-name"
                value={swaggerForm.name}
                onChange={(e) => setSwaggerForm({...swaggerForm, name: e.target.value})}
                placeholder="e.g., Swagger Discovery - api.example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="swagger-target">Target URL *</label>
              <input
                type="url"
                id="swagger-target"
                value={swaggerForm.target}
                onChange={(e) => setSwaggerForm({...swaggerForm, target: e.target.value})}
                placeholder="https://api.example.com"
                required
              />
              <small>Enter the base URL - common paths like /swagger.json will be checked</small>
            </div>

            <div className="info-box">
              <h4>Paths Checked:</h4>
              <ul>
                <li>/swagger.json, /swagger/v1/swagger.json</li>
                <li>/openapi.json, /api-docs</li>
                <li>/v1/swagger.json, /v2/swagger.json</li>
                <li>/docs/swagger.json, /api/swagger.json</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/api-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Swagger Discovery'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Full Scan Form */}
      {activeScanType === 'full' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>Full API Discovery Scan</h2>
            <p>Comprehensive scan combining all discovery methods</p>
          </div>

          <form onSubmit={handleFullSubmit}>
            <div className="form-group">
              <label htmlFor="full-name">Scan Name *</label>
              <input
                type="text"
                id="full-name"
                value={fullForm.name}
                onChange={(e) => setFullForm({...fullForm, name: e.target.value})}
                placeholder="e.g., Full API Discovery - example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="full-target">Target URL *</label>
              <input
                type="url"
                id="full-target"
                value={fullForm.target}
                onChange={(e) => setFullForm({...fullForm, target: e.target.value})}
                placeholder="https://api.example.com"
                required
              />
              <small>Enter the base URL of the target API</small>
            </div>

            <div className="form-group">
              <label htmlFor="full-wordlist">Kiterunner Wordlist</label>
              <select
                id="full-wordlist"
                value={fullForm.kiterunnerWordlist}
                onChange={(e) => setFullForm({...fullForm, kiterunnerWordlist: e.target.value})}
              >
                {kiterunnerWordlists.map(wl => (
                  <option key={wl.value} value={wl.value}>{wl.label}</option>
                ))}
              </select>
            </div>

            <div className="form-group">
              <label>Arjun HTTP Methods</label>
              <div className="checkbox-grid">
                {['GET', 'POST', 'PUT', 'PATCH'].map(method => (
                  <label key={method} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={fullForm.arjunMethods.includes(method)}
                      onChange={() => toggleFullMethod(method)}
                    />
                    {method}
                  </label>
                ))}
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="full-threads">Threads</label>
              <input
                type="number"
                id="full-threads"
                value={fullForm.threads}
                onChange={(e) => setFullForm({...fullForm, threads: parseInt(e.target.value) || 10})}
                min="1"
                max="50"
              />
            </div>

            <div className="info-box info-box-highlight">
              <h4>Full Scan Includes:</h4>
              <ol>
                <li><strong>Swagger/OpenAPI Discovery</strong> - Find API documentation</li>
                <li><strong>GraphQL Introspection</strong> - Extract GraphQL schema</li>
                <li><strong>Kiterunner</strong> - Discover hidden endpoints</li>
                <li><strong>Arjun</strong> - Find hidden parameters</li>
              </ol>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/api-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Full API Scan'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

export default NewAPIScan;
