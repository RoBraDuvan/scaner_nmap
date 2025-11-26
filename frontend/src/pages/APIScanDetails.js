import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { format } from 'date-fns';
import api from '../services/api';
import './APIScanDetails.css';

function APIScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState(null);
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState('results');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScanData();
    const interval = setInterval(loadScanData, 3000);
    return () => clearInterval(interval);
  }, [id]);

  const loadScanData = async () => {
    try {
      const [scanRes, resultsRes, logsRes] = await Promise.all([
        api.get(`/apiscans/${id}`),
        api.get(`/apiscans/${id}/results`),
        api.get(`/apiscans/${id}/logs`)
      ]);

      setScan(scanRes.data);
      setResults(resultsRes.data);
      setLogs(logsRes.data || []);
    } catch (error) {
      console.error('Error loading scan data:', error);
    } finally {
      setLoading(false);
    }
  };

  const cancelScan = async () => {
    if (!scan) return;

    try {
      await api.post(`/apiscans/${id}/cancel`);
      loadScanData();
    } catch (error) {
      console.error('Error cancelling scan:', error);
      alert('Failed to cancel scan');
    }
  };

  const deleteScan = async () => {
    if (!window.confirm('Are you sure you want to delete this scan?')) return;

    try {
      await api.delete(`/apiscans/${id}`);
      navigate('/api-scans');
    } catch (error) {
      console.error('Error deleting scan:', error);
      alert('Failed to delete scan');
    }
  };

  const getScanTypeLabel = (scanType) => {
    const labels = {
      kiterunner: 'Kiterunner',
      arjun: 'Arjun',
      graphql: 'GraphQL',
      swagger: 'Swagger',
      full: 'Full Scan'
    };
    return labels[scanType] || scanType;
  };

  const getScanTypeIcon = (scanType) => {
    const icons = {
      kiterunner: 'K',
      arjun: 'A',
      graphql: 'G',
      swagger: 'S',
      full: 'F'
    };
    return icons[scanType] || '?';
  };

  if (loading) {
    return <div className="loading">Loading scan details...</div>;
  }

  if (!scan) {
    return <div className="error-message">Scan not found</div>;
  }

  const renderEndpointsResults = () => {
    const endpoints = results?.endpoints || [];
    if (endpoints.length === 0) {
      return <div className="empty-state">No endpoints discovered</div>;
    }

    return (
      <div className="results-section">
        <div className="results-header">
          <h3>Discovered Endpoints ({endpoints.length})</h3>
        </div>
        <div className="endpoints-table card">
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>Status</th>
                <th>Content Type</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((endpoint, index) => (
                <tr key={index}>
                  <td>
                    <span className={`method-badge method-${endpoint.method?.toLowerCase()}`}>
                      {endpoint.method}
                    </span>
                  </td>
                  <td className="endpoint-path">{endpoint.path || endpoint.url}</td>
                  <td>
                    {endpoint.status_code && (
                      <span className={`status-code status-${Math.floor(endpoint.status_code / 100)}xx`}>
                        {endpoint.status_code}
                      </span>
                    )}
                  </td>
                  <td className="content-type">{endpoint.content_type || '-'}</td>
                  <td>
                    <span className="source-badge">{endpoint.source || 'kiterunner'}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderParametersResults = () => {
    const parameters = results?.parameters || [];
    if (parameters.length === 0) {
      return <div className="empty-state">No parameters discovered</div>;
    }

    // Group by URL
    const paramsByUrl = parameters.reduce((acc, param) => {
      const url = param.url || 'Unknown';
      if (!acc[url]) acc[url] = [];
      acc[url].push(param);
      return acc;
    }, {});

    return (
      <div className="results-section">
        <div className="results-header">
          <h3>Discovered Parameters ({parameters.length})</h3>
        </div>
        {Object.entries(paramsByUrl).map(([url, params]) => (
          <div key={url} className="params-group card">
            <h4 className="params-url">{url}</h4>
            <div className="params-list">
              {params.map((param, index) => (
                <div key={index} className="param-item">
                  <span className="param-name">{param.name}</span>
                  <span className={`param-type type-${param.param_type}`}>{param.param_type}</span>
                  <span className={`method-badge method-${param.method?.toLowerCase()}`}>{param.method}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderGraphQLResults = () => {
    const schemas = results?.graphql_schemas || [];
    if (schemas.length === 0) {
      return <div className="empty-state">No GraphQL schema discovered</div>;
    }

    return (
      <div className="results-section">
        <div className="results-header">
          <h3>GraphQL Schemas ({schemas.length})</h3>
        </div>
        {schemas.map((schema, index) => (
          <div key={index} className="graphql-schema card">
            <div className="schema-header">
              <h4>{schema.url}</h4>
              {schema.introspection_enabled && (
                <span className="badge badge-success">Introspection Enabled</span>
              )}
            </div>

            {schema.query_type && (
              <div className="schema-section">
                <h5>Query Type</h5>
                <span className="type-name">{schema.query_type}</span>
              </div>
            )}

            {schema.mutation_type && (
              <div className="schema-section">
                <h5>Mutation Type</h5>
                <span className="type-name">{schema.mutation_type}</span>
              </div>
            )}

            {schema.subscription_type && (
              <div className="schema-section">
                <h5>Subscription Type</h5>
                <span className="type-name">{schema.subscription_type}</span>
              </div>
            )}

            {schema.types && schema.types.length > 0 && (
              <div className="schema-section">
                <h5>Types ({schema.types.length})</h5>
                <div className="types-grid">
                  {schema.types.filter(t => !t.name?.startsWith('__')).slice(0, 50).map((type, i) => (
                    <div key={i} className="type-item">
                      <span className={`type-kind kind-${type.kind?.toLowerCase()}`}>{type.kind}</span>
                      <span className="type-name">{type.name}</span>
                    </div>
                  ))}
                  {schema.types.filter(t => !t.name?.startsWith('__')).length > 50 && (
                    <div className="type-item more">+{schema.types.filter(t => !t.name?.startsWith('__')).length - 50} more</div>
                  )}
                </div>
              </div>
            )}

            {schema.queries && schema.queries.length > 0 && (
              <div className="schema-section">
                <h5>Queries ({schema.queries.length})</h5>
                <div className="operations-list">
                  {schema.queries.map((q, i) => (
                    <div key={i} className="operation-item">
                      <span className="operation-name">{q.name}</span>
                      {q.description && <span className="operation-desc">{q.description}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {schema.mutations && schema.mutations.length > 0 && (
              <div className="schema-section">
                <h5>Mutations ({schema.mutations.length})</h5>
                <div className="operations-list">
                  {schema.mutations.map((m, i) => (
                    <div key={i} className="operation-item">
                      <span className="operation-name">{m.name}</span>
                      {m.description && <span className="operation-desc">{m.description}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {schema.raw_schema && (
              <details className="raw-schema-details">
                <summary>View Raw Schema</summary>
                <pre className="raw-schema">{JSON.stringify(JSON.parse(schema.raw_schema), null, 2)}</pre>
              </details>
            )}
          </div>
        ))}
      </div>
    );
  };

  const renderSwaggerResults = () => {
    const specs = results?.swagger_specs || [];
    if (specs.length === 0) {
      return <div className="empty-state">No OpenAPI/Swagger specifications discovered</div>;
    }

    return (
      <div className="results-section">
        <div className="results-header">
          <h3>OpenAPI/Swagger Specifications ({specs.length})</h3>
        </div>
        {specs.map((spec, index) => (
          <div key={index} className="swagger-spec card">
            <div className="spec-header">
              <div className="spec-info">
                <h4>{spec.title || 'API Specification'}</h4>
                {spec.version && <span className="spec-version">v{spec.version}</span>}
              </div>
              <span className={`spec-type spec-${spec.spec_type?.toLowerCase()}`}>
                {spec.spec_type || 'OpenAPI'}
              </span>
            </div>

            <div className="spec-url">
              <strong>URL:</strong> <a href={spec.url} target="_blank" rel="noopener noreferrer">{spec.url}</a>
            </div>

            {spec.description && (
              <div className="spec-description">{spec.description}</div>
            )}

            {spec.servers && spec.servers.length > 0 && (
              <div className="spec-section">
                <h5>Servers</h5>
                <ul className="servers-list">
                  {spec.servers.map((server, i) => (
                    <li key={i}>{typeof server === 'string' ? server : server.url}</li>
                  ))}
                </ul>
              </div>
            )}

            {spec.paths && Object.keys(spec.paths).length > 0 && (
              <div className="spec-section">
                <h5>Paths ({Object.keys(spec.paths).length})</h5>
                <div className="paths-list">
                  {Object.entries(spec.paths).slice(0, 30).map(([path, methods], i) => (
                    <div key={i} className="path-item">
                      <span className="path-name">{path}</span>
                      <div className="path-methods">
                        {Object.keys(methods).filter(m => ['get', 'post', 'put', 'patch', 'delete'].includes(m.toLowerCase())).map(method => (
                          <span key={method} className={`method-badge method-${method.toLowerCase()}`}>
                            {method.toUpperCase()}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                  {Object.keys(spec.paths).length > 30 && (
                    <div className="path-item more">+{Object.keys(spec.paths).length - 30} more paths</div>
                  )}
                </div>
              </div>
            )}

            {spec.security_definitions && Object.keys(spec.security_definitions).length > 0 && (
              <div className="spec-section">
                <h5>Security Schemes</h5>
                <div className="security-list">
                  {Object.entries(spec.security_definitions).map(([name, def]) => (
                    <div key={name} className="security-item">
                      <span className="security-name">{name}</span>
                      <span className="security-type">{def.type}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {spec.raw_spec && (
              <details className="raw-spec-details">
                <summary>View Raw Specification</summary>
                <pre className="raw-spec">{spec.raw_spec}</pre>
              </details>
            )}
          </div>
        ))}
      </div>
    );
  };

  const renderResults = () => {
    if (!results) {
      return <div className="empty-state">No results yet</div>;
    }

    const hasEndpoints = results.endpoints && results.endpoints.length > 0;
    const hasParameters = results.parameters && results.parameters.length > 0;
    const hasGraphQL = results.graphql_schemas && results.graphql_schemas.length > 0;
    const hasSwagger = results.swagger_specs && results.swagger_specs.length > 0;

    if (!hasEndpoints && !hasParameters && !hasGraphQL && !hasSwagger) {
      return <div className="empty-state">No results yet</div>;
    }

    return (
      <div className="all-results">
        {hasEndpoints && renderEndpointsResults()}
        {hasParameters && renderParametersResults()}
        {hasGraphQL && renderGraphQLResults()}
        {hasSwagger && renderSwaggerResults()}
      </div>
    );
  };

  const getResultsCount = () => {
    if (!results) return 0;
    return (results.endpoints?.length || 0) +
           (results.parameters?.length || 0) +
           (results.graphql_schemas?.length || 0) +
           (results.swagger_specs?.length || 0);
  };

  return (
    <div className="api-scan-details">
      <div className="page-header">
        <div className="header-left">
          <Link to="/api-scans" className="back-link">← Back to API Scans</Link>
          <h1>{scan.name}</h1>
          <div className="scan-meta">
            <span className={`type-badge type-${scan.scan_type}`}>
              {getScanTypeLabel(scan.scan_type)}
            </span>
            <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
            <span className="target">{scan.target}</span>
          </div>
        </div>
        <div className="header-actions">
          {(scan.status === 'pending' || scan.status === 'running') && (
            <button className="btn btn-warning" onClick={cancelScan}>
              Cancel Scan
            </button>
          )}
          {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
            <button className="btn btn-danger" onClick={deleteScan}>
              Delete
            </button>
          )}
        </div>
      </div>

      {/* Progress */}
      {(scan.status === 'running' || scan.status === 'pending') && (
        <div className="progress-section card">
          <div className="progress-bar-large">
            <div className="progress-fill" style={{ width: `${scan.progress || 0}%` }}></div>
            <span className="progress-text">{scan.progress || 0}%</span>
          </div>
          <p className="progress-status">
            {scan.status === 'pending' ? 'Waiting to start...' : 'Scanning in progress...'}
          </p>
        </div>
      )}

      {/* Stats Summary */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{results?.endpoints?.length || 0}</div>
          <div className="stat-label">Endpoints</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{results?.parameters?.length || 0}</div>
          <div className="stat-label">Parameters</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{results?.graphql_schemas?.length || 0}</div>
          <div className="stat-label">GraphQL Schemas</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{results?.swagger_specs?.length || 0}</div>
          <div className="stat-label">Swagger Specs</div>
        </div>
      </div>

      {scan.error_message && (
        <div className="error-message">{scan.error_message}</div>
      )}

      <div className="tabs">
        <button
          className={`tab ${activeTab === 'results' ? 'active' : ''}`}
          onClick={() => setActiveTab('results')}
        >
          Results
        </button>
        <button
          className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          Logs ({logs.length})
        </button>
        {scan.config && (
          <button
            className={`tab ${activeTab === 'config' ? 'active' : ''}`}
            onClick={() => setActiveTab('config')}
          >
            Configuration
          </button>
        )}
      </div>

      {activeTab === 'results' && renderResults()}

      {activeTab === 'logs' && (
        <div className="logs-section">
          {logs.length === 0 ? (
            <div className="empty-state">No logs yet</div>
          ) : (
            <div className="logs-list card">
              {logs.map(log => (
                <div key={log.id} className={`log-entry log-${log.level}`}>
                  <span className="log-time">
                    {format(new Date(log.created_at), 'HH:mm:ss')}
                  </span>
                  <span className="log-level">{log.level}</span>
                  <span className="log-message">{log.message}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'config' && scan.config && (
        <div className="config-section card">
          <h3>Scan Configuration</h3>
          <pre className="config-json">
            {JSON.stringify(scan.config, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default APIScanDetails;
