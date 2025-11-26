import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import './NewWebScan.css';

function NewWebScan() {
  const navigate = useNavigate();
  const [activeTool, setActiveTool] = useState('ffuf');
  const [templates, setTemplates] = useState([]);
  const [wordlists, setWordlists] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // ffuf form data
  const [ffufForm, setFfufForm] = useState({
    name: '',
    url: '',
    wordlist: 'common',
    method: 'GET',
    threads: 40,
    timeout: 10,
    extensions: '',
    filterCodes: '404',
    recursion: false
  });

  // gowitness form data
  const [gowitnessForm, setGowitnessForm] = useState({
    name: '',
    urls: '',
    timeout: 30,
    resolution: '1920x1080',
    fullPage: false
  });

  // testssl form data
  const [testsslForm, setTestsslForm] = useState({
    name: '',
    target: '',
    full: false,
    fast: true,
    protocols: true,
    ciphers: false,
    vulnerabilities: true,
    headers: false
  });

  useEffect(() => {
    loadTemplatesAndWordlists();
  }, []);

  const loadTemplatesAndWordlists = async () => {
    try {
      const [templatesRes, wordlistsRes] = await Promise.all([
        api.get('/webscans/templates'),
        api.get('/webscans/wordlists')
      ]);
      setTemplates(templatesRes.data || []);
      setWordlists(wordlistsRes.data || []);
    } catch (error) {
      console.error('Error loading data:', error);
    }
  };

  const handleFfufSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: ffufForm.name,
        url: ffufForm.url.includes('FUZZ') ? ffufForm.url : ffufForm.url + '/FUZZ',
        wordlist: ffufForm.wordlist,
        method: ffufForm.method,
        threads: parseInt(ffufForm.threads),
        timeout: parseInt(ffufForm.timeout),
        filter_codes: ffufForm.filterCodes ? ffufForm.filterCodes.split(',').map(c => parseInt(c.trim())) : [],
        extensions: ffufForm.extensions ? ffufForm.extensions.split(',').map(e => e.trim()) : [],
        recursion: ffufForm.recursion
      };

      const response = await api.post('/webscans/ffuf', payload);
      navigate(`/webscan/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleGowitnessSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const urls = gowitnessForm.urls.split('\n').map(u => u.trim()).filter(u => u);
      const payload = {
        name: gowitnessForm.name,
        urls: urls,
        timeout: parseInt(gowitnessForm.timeout),
        resolution: gowitnessForm.resolution,
        full_page: gowitnessForm.fullPage
      };

      const response = await api.post('/webscans/gowitness', payload);
      navigate(`/webscan/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleTestsslSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: testsslForm.name,
        target: testsslForm.target,
        full: testsslForm.full,
        fast: testsslForm.fast,
        protocols: testsslForm.protocols,
        ciphers: testsslForm.ciphers,
        vulnerabilities: testsslForm.vulnerabilities,
        headers: testsslForm.headers
      };

      const response = await api.post('/webscans/testssl', payload);
      navigate(`/webscan/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const applyTemplate = (template) => {
    if (template.tool === 'ffuf') {
      setFfufForm(prev => ({
        ...prev,
        wordlist: template.config.wordlist || prev.wordlist,
        threads: template.config.threads || prev.threads,
        extensions: template.config.extensions ? template.config.extensions.join(',') : ''
      }));
    } else if (template.tool === 'gowitness') {
      setGowitnessForm(prev => ({
        ...prev,
        timeout: template.config.timeout || prev.timeout,
        fullPage: template.config.full_page || prev.fullPage
      }));
    } else if (template.tool === 'testssl') {
      setTestsslForm(prev => ({
        ...prev,
        ...template.config
      }));
    }
  };

  const getToolTemplates = (tool) => templates.filter(t => t.tool === tool);

  return (
    <div className="new-webscan">
      <h1>Create Web Scan</h1>

      {error && <div className="error-message">{error}</div>}

      <div className="tool-tabs">
        <button
          className={`tool-tab ${activeTool === 'ffuf' ? 'active' : ''}`}
          onClick={() => setActiveTool('ffuf')}
        >
          🔍 ffuf - Directory Fuzzer
        </button>
        <button
          className={`tool-tab ${activeTool === 'gowitness' ? 'active' : ''}`}
          onClick={() => setActiveTool('gowitness')}
        >
          📸 Gowitness - Screenshots
        </button>
        <button
          className={`tool-tab ${activeTool === 'testssl' ? 'active' : ''}`}
          onClick={() => setActiveTool('testssl')}
        >
          🔒 testssl.sh - SSL/TLS Analyzer
        </button>
      </div>

      {/* ffuf Form */}
      {activeTool === 'ffuf' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>🔍 ffuf - Web Fuzzer</h2>
            <p>Discover hidden directories, files, and endpoints</p>
          </div>

          <div className="templates-section">
            <h3>Quick Templates</h3>
            <div className="template-buttons">
              {getToolTemplates('ffuf').map(t => (
                <button
                  key={t.id}
                  type="button"
                  className="template-btn"
                  onClick={() => applyTemplate(t)}
                >
                  {t.name}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleFfufSubmit}>
            <div className="form-group">
              <label htmlFor="ffuf-name">Scan Name *</label>
              <input
                type="text"
                id="ffuf-name"
                value={ffufForm.name}
                onChange={(e) => setFfufForm({...ffufForm, name: e.target.value})}
                placeholder="e.g., Example.com Directory Scan"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="ffuf-url">Target URL *</label>
              <input
                type="text"
                id="ffuf-url"
                value={ffufForm.url}
                onChange={(e) => setFfufForm({...ffufForm, url: e.target.value})}
                placeholder="e.g., https://example.com/FUZZ or https://example.com/"
                required
              />
              <small>Use FUZZ keyword where you want to inject wordlist. If not present, /FUZZ will be appended.</small>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="ffuf-wordlist">Wordlist</label>
                <select
                  id="ffuf-wordlist"
                  value={ffufForm.wordlist}
                  onChange={(e) => setFfufForm({...ffufForm, wordlist: e.target.value})}
                >
                  {wordlists.map(w => (
                    <option key={w.name} value={w.name}>{w.name} - {w.description}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="ffuf-method">HTTP Method</label>
                <select
                  id="ffuf-method"
                  value={ffufForm.method}
                  onChange={(e) => setFfufForm({...ffufForm, method: e.target.value})}
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="ffuf-threads">Threads</label>
                <input
                  type="number"
                  id="ffuf-threads"
                  value={ffufForm.threads}
                  onChange={(e) => setFfufForm({...ffufForm, threads: e.target.value})}
                  min="1"
                  max="200"
                />
              </div>

              <div className="form-group">
                <label htmlFor="ffuf-timeout">Timeout (seconds)</label>
                <input
                  type="number"
                  id="ffuf-timeout"
                  value={ffufForm.timeout}
                  onChange={(e) => setFfufForm({...ffufForm, timeout: e.target.value})}
                  min="1"
                  max="60"
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="ffuf-extensions">Extensions (comma-separated)</label>
                <input
                  type="text"
                  id="ffuf-extensions"
                  value={ffufForm.extensions}
                  onChange={(e) => setFfufForm({...ffufForm, extensions: e.target.value})}
                  placeholder="e.g., .php,.html,.txt,.bak"
                />
              </div>

              <div className="form-group">
                <label htmlFor="ffuf-filter">Filter Status Codes</label>
                <input
                  type="text"
                  id="ffuf-filter"
                  value={ffufForm.filterCodes}
                  onChange={(e) => setFfufForm({...ffufForm, filterCodes: e.target.value})}
                  placeholder="e.g., 404,403"
                />
              </div>
            </div>

            <div className="form-group checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={ffufForm.recursion}
                  onChange={(e) => setFfufForm({...ffufForm, recursion: e.target.checked})}
                />
                Enable Recursion (scan found directories)
              </label>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/webscans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start ffuf Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Gowitness Form */}
      {activeTool === 'gowitness' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>📸 Gowitness - Web Screenshots</h2>
            <p>Capture screenshots of web pages for visual reconnaissance</p>
          </div>

          <div className="templates-section">
            <h3>Quick Templates</h3>
            <div className="template-buttons">
              {getToolTemplates('gowitness').map(t => (
                <button
                  key={t.id}
                  type="button"
                  className="template-btn"
                  onClick={() => applyTemplate(t)}
                >
                  {t.name}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleGowitnessSubmit}>
            <div className="form-group">
              <label htmlFor="gowitness-name">Scan Name *</label>
              <input
                type="text"
                id="gowitness-name"
                value={gowitnessForm.name}
                onChange={(e) => setGowitnessForm({...gowitnessForm, name: e.target.value})}
                placeholder="e.g., Website Screenshots"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="gowitness-urls">URLs (one per line) *</label>
              <textarea
                id="gowitness-urls"
                value={gowitnessForm.urls}
                onChange={(e) => setGowitnessForm({...gowitnessForm, urls: e.target.value})}
                placeholder="https://example.com&#10;https://example.org&#10;https://test.com"
                rows="6"
                required
              />
              <small>Enter one URL per line</small>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="gowitness-timeout">Timeout (seconds)</label>
                <input
                  type="number"
                  id="gowitness-timeout"
                  value={gowitnessForm.timeout}
                  onChange={(e) => setGowitnessForm({...gowitnessForm, timeout: e.target.value})}
                  min="5"
                  max="120"
                />
              </div>

              <div className="form-group">
                <label htmlFor="gowitness-resolution">Resolution</label>
                <select
                  id="gowitness-resolution"
                  value={gowitnessForm.resolution}
                  onChange={(e) => setGowitnessForm({...gowitnessForm, resolution: e.target.value})}
                >
                  <option value="1920x1080">1920x1080 (Full HD)</option>
                  <option value="1366x768">1366x768 (HD)</option>
                  <option value="1280x720">1280x720 (720p)</option>
                  <option value="800x600">800x600</option>
                  <option value="375x812">375x812 (Mobile)</option>
                </select>
              </div>
            </div>

            <div className="form-group checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={gowitnessForm.fullPage}
                  onChange={(e) => setGowitnessForm({...gowitnessForm, fullPage: e.target.checked})}
                />
                Capture Full Page (scroll entire page)
              </label>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/webscans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Screenshot Capture'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* testssl.sh Form */}
      {activeTool === 'testssl' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>🔒 testssl.sh - SSL/TLS Analyzer</h2>
            <p>Comprehensive analysis of SSL/TLS configuration and vulnerabilities</p>
          </div>

          <div className="templates-section">
            <h3>Quick Templates</h3>
            <div className="template-buttons">
              {getToolTemplates('testssl').map(t => (
                <button
                  key={t.id}
                  type="button"
                  className="template-btn"
                  onClick={() => applyTemplate(t)}
                >
                  {t.name}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleTestsslSubmit}>
            <div className="form-group">
              <label htmlFor="testssl-name">Scan Name *</label>
              <input
                type="text"
                id="testssl-name"
                value={testsslForm.name}
                onChange={(e) => setTestsslForm({...testsslForm, name: e.target.value})}
                placeholder="e.g., Example.com SSL Audit"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="testssl-target">Target *</label>
              <input
                type="text"
                id="testssl-target"
                value={testsslForm.target}
                onChange={(e) => setTestsslForm({...testsslForm, target: e.target.value})}
                placeholder="e.g., example.com:443 or example.com"
                required
              />
              <small>Enter hostname:port or just hostname (default port 443)</small>
            </div>

            <div className="form-group">
              <label>Scan Options</label>
              <div className="checkbox-grid">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={testsslForm.full}
                    onChange={(e) => setTestsslForm({...testsslForm, full: e.target.checked, fast: !e.target.checked})}
                  />
                  Full Scan (all tests)
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={testsslForm.fast}
                    onChange={(e) => setTestsslForm({...testsslForm, fast: e.target.checked})}
                    disabled={testsslForm.full}
                  />
                  Fast Mode
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={testsslForm.protocols}
                    onChange={(e) => setTestsslForm({...testsslForm, protocols: e.target.checked})}
                    disabled={testsslForm.full}
                  />
                  Check Protocols
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={testsslForm.ciphers}
                    onChange={(e) => setTestsslForm({...testsslForm, ciphers: e.target.checked})}
                    disabled={testsslForm.full}
                  />
                  Check Ciphers
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={testsslForm.vulnerabilities}
                    onChange={(e) => setTestsslForm({...testsslForm, vulnerabilities: e.target.checked})}
                    disabled={testsslForm.full}
                  />
                  Check Vulnerabilities
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={testsslForm.headers}
                    onChange={(e) => setTestsslForm({...testsslForm, headers: e.target.checked})}
                    disabled={testsslForm.full}
                  />
                  Check HTTP Headers
                </label>
              </div>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/webscans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start SSL Analysis'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

export default NewWebScan;
