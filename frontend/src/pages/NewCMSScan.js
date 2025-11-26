import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import './NewCMSScan.css';

function NewCMSScan() {
  const navigate = useNavigate();
  const [activeScanType, setActiveScanType] = useState('whatweb');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // WhatWeb form data
  const [whatwebForm, setWhatwebForm] = useState({
    name: '',
    target: '',
    aggression: 1
  });

  // CMSeeK form data
  const [cmseekForm, setCmseekForm] = useState({
    name: '',
    target: '',
    followRedirect: true,
    randomAgent: true
  });

  // WPScan form data
  const [wpscanForm, setWpscanForm] = useState({
    name: '',
    target: '',
    apiToken: '',
    enumerate: ['vp', 'vt', 'u'],
    detectionMode: 'mixed'
  });

  // Full scan form data
  const [fullForm, setFullForm] = useState({
    name: '',
    target: '',
    whatwebAggression: 1,
    wpscanApiToken: ''
  });

  const handleWhatWebSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: whatwebForm.name,
        scan_type: 'whatweb',
        target: whatwebForm.target,
        config: {
          whatweb_aggression: whatwebForm.aggression
        }
      };

      const response = await api.post('/cmsscans/', payload);
      navigate(`/cms-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleCMSeeKSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: cmseekForm.name,
        scan_type: 'cmseek',
        target: cmseekForm.target,
        config: {
          cmseek_follow_redirect: cmseekForm.followRedirect,
          cmseek_random_agent: cmseekForm.randomAgent
        }
      };

      const response = await api.post('/cmsscans/', payload);
      navigate(`/cms-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const handleWPScanSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload = {
        name: wpscanForm.name,
        scan_type: 'wpscan',
        target: wpscanForm.target,
        config: {
          wpscan_api_token: wpscanForm.apiToken,
          wpscan_enumerate: wpscanForm.enumerate,
          wpscan_detection_mode: wpscanForm.detectionMode
        }
      };

      const response = await api.post('/cmsscans/', payload);
      navigate(`/cms-scans/${response.data.id}`);
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
          whatweb_aggression: fullForm.whatwebAggression,
          wpscan_api_token: fullForm.wpscanApiToken
        }
      };

      const response = await api.post('/cmsscans/', payload);
      navigate(`/cms-scans/${response.data.id}`);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  };

  const toggleWPScanEnum = (option) => {
    const enums = wpscanForm.enumerate.includes(option)
      ? wpscanForm.enumerate.filter(e => e !== option)
      : [...wpscanForm.enumerate, option];
    setWpscanForm({ ...wpscanForm, enumerate: enums });
  };

  return (
    <div className="new-cms-scan">
      <h1>Create CMS Detection Scan</h1>

      {error && <div className="error-message">{error}</div>}

      <div className="scan-type-tabs">
        <button
          className={`scan-type-tab ${activeScanType === 'whatweb' ? 'active' : ''}`}
          onClick={() => setActiveScanType('whatweb')}
        >
          WhatWeb
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'cmseek' ? 'active' : ''}`}
          onClick={() => setActiveScanType('cmseek')}
        >
          CMSeeK
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'wpscan' ? 'active' : ''}`}
          onClick={() => setActiveScanType('wpscan')}
        >
          WPScan
        </button>
        <button
          className={`scan-type-tab ${activeScanType === 'full' ? 'active' : ''}`}
          onClick={() => setActiveScanType('full')}
        >
          Full Scan
        </button>
      </div>

      {/* WhatWeb Form */}
      {activeScanType === 'whatweb' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>WhatWeb - Technology Detection</h2>
            <p>Identify web technologies, CMS platforms, frameworks, and servers</p>
          </div>

          <form onSubmit={handleWhatWebSubmit}>
            <div className="form-group">
              <label htmlFor="ww-name">Scan Name *</label>
              <input
                type="text"
                id="ww-name"
                value={whatwebForm.name}
                onChange={(e) => setWhatwebForm({...whatwebForm, name: e.target.value})}
                placeholder="e.g., Tech Detection - example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="ww-target">Target URL *</label>
              <input
                type="url"
                id="ww-target"
                value={whatwebForm.target}
                onChange={(e) => setWhatwebForm({...whatwebForm, target: e.target.value})}
                placeholder="https://example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="ww-aggression">Aggression Level</label>
              <select
                id="ww-aggression"
                value={whatwebForm.aggression}
                onChange={(e) => setWhatwebForm({...whatwebForm, aggression: parseInt(e.target.value)})}
              >
                <option value={1}>1 - Stealthy (passive)</option>
                <option value={2}>2 - Polite (minimal requests)</option>
                <option value={3}>3 - Aggressive (more plugins)</option>
                <option value={4}>4 - Heavy (all plugins)</option>
              </select>
              <small>Higher levels make more requests but detect more technologies</small>
            </div>

            <div className="info-box">
              <h4>WhatWeb Detects:</h4>
              <ul>
                <li>CMS platforms (WordPress, Drupal, Joomla, etc.)</li>
                <li>Web frameworks (Laravel, Django, Rails, etc.)</li>
                <li>Web servers (Apache, nginx, IIS)</li>
                <li>Programming languages (PHP, Python, Ruby)</li>
                <li>JavaScript libraries and CDNs</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/cms-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start WhatWeb Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* CMSeeK Form */}
      {activeScanType === 'cmseek' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>CMSeeK - CMS Detection</h2>
            <p>Detect and enumerate CMS platforms with detailed information</p>
          </div>

          <form onSubmit={handleCMSeeKSubmit}>
            <div className="form-group">
              <label htmlFor="cms-name">Scan Name *</label>
              <input
                type="text"
                id="cms-name"
                value={cmseekForm.name}
                onChange={(e) => setCmseekForm({...cmseekForm, name: e.target.value})}
                placeholder="e.g., CMS Detection - example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="cms-target">Target URL *</label>
              <input
                type="url"
                id="cms-target"
                value={cmseekForm.target}
                onChange={(e) => setCmseekForm({...cmseekForm, target: e.target.value})}
                placeholder="https://example.com"
                required
              />
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={cmseekForm.followRedirect}
                  onChange={(e) => setCmseekForm({...cmseekForm, followRedirect: e.target.checked})}
                />
                Follow Redirects
              </label>
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={cmseekForm.randomAgent}
                  onChange={(e) => setCmseekForm({...cmseekForm, randomAgent: e.target.checked})}
                />
                Use Random User-Agent
              </label>
            </div>

            <div className="info-box">
              <h4>CMSeeK Detects 180+ CMS:</h4>
              <ul>
                <li>WordPress, Drupal, Joomla, Magento</li>
                <li>Shopify, PrestaShop, OpenCart</li>
                <li>Ghost, TYPO3, MediaWiki</li>
                <li>Custom CMS and frameworks</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/cms-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start CMSeeK Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* WPScan Form */}
      {activeScanType === 'wpscan' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>WPScan - WordPress Security Scanner</h2>
            <p>Deep WordPress vulnerability and security assessment</p>
          </div>

          <form onSubmit={handleWPScanSubmit}>
            <div className="form-group">
              <label htmlFor="wp-name">Scan Name *</label>
              <input
                type="text"
                id="wp-name"
                value={wpscanForm.name}
                onChange={(e) => setWpscanForm({...wpscanForm, name: e.target.value})}
                placeholder="e.g., WordPress Audit - example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="wp-target">WordPress Site URL *</label>
              <input
                type="url"
                id="wp-target"
                value={wpscanForm.target}
                onChange={(e) => setWpscanForm({...wpscanForm, target: e.target.value})}
                placeholder="https://wordpress-site.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="wp-token">WPScan API Token (optional)</label>
              <input
                type="password"
                id="wp-token"
                value={wpscanForm.apiToken}
                onChange={(e) => setWpscanForm({...wpscanForm, apiToken: e.target.value})}
                placeholder="Get free token from wpscan.com"
              />
              <small>API token enables vulnerability detection. Free at wpscan.com</small>
            </div>

            <div className="form-group">
              <label>Enumeration Options</label>
              <div className="checkbox-grid">
                {[
                  { value: 'vp', label: 'Vulnerable Plugins' },
                  { value: 'ap', label: 'All Plugins' },
                  { value: 'vt', label: 'Vulnerable Themes' },
                  { value: 'at', label: 'All Themes' },
                  { value: 'u', label: 'Users' },
                  { value: 'cb', label: 'Config Backups' }
                ].map(opt => (
                  <label key={opt.value} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={wpscanForm.enumerate.includes(opt.value)}
                      onChange={() => toggleWPScanEnum(opt.value)}
                    />
                    {opt.label}
                  </label>
                ))}
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="wp-mode">Detection Mode</label>
              <select
                id="wp-mode"
                value={wpscanForm.detectionMode}
                onChange={(e) => setWpscanForm({...wpscanForm, detectionMode: e.target.value})}
              >
                <option value="mixed">Mixed (balanced)</option>
                <option value="passive">Passive (stealth)</option>
                <option value="aggressive">Aggressive (thorough)</option>
              </select>
            </div>

            <div className="info-box info-box-warning">
              <h4>WPScan Discovers:</h4>
              <ul>
                <li>WordPress version vulnerabilities</li>
                <li>Vulnerable plugins and themes</li>
                <li>User enumeration</li>
                <li>Configuration issues</li>
                <li>Known CVEs and exploits</li>
              </ul>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/cms-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start WPScan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Full Scan Form */}
      {activeScanType === 'full' && (
        <div className="scan-form card">
          <div className="form-header">
            <h2>Full CMS Detection Scan</h2>
            <p>Comprehensive scan combining all detection methods</p>
          </div>

          <form onSubmit={handleFullSubmit}>
            <div className="form-group">
              <label htmlFor="full-name">Scan Name *</label>
              <input
                type="text"
                id="full-name"
                value={fullForm.name}
                onChange={(e) => setFullForm({...fullForm, name: e.target.value})}
                placeholder="e.g., Full CMS Audit - example.com"
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
                placeholder="https://example.com"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="full-aggression">WhatWeb Aggression</label>
              <select
                id="full-aggression"
                value={fullForm.whatwebAggression}
                onChange={(e) => setFullForm({...fullForm, whatwebAggression: parseInt(e.target.value)})}
              >
                <option value={1}>1 - Stealthy</option>
                <option value={2}>2 - Polite</option>
                <option value={3}>3 - Aggressive</option>
              </select>
            </div>

            <div className="form-group">
              <label htmlFor="full-token">WPScan API Token (optional)</label>
              <input
                type="password"
                id="full-token"
                value={fullForm.wpscanApiToken}
                onChange={(e) => setFullForm({...fullForm, wpscanApiToken: e.target.value})}
                placeholder="For WordPress vulnerability detection"
              />
            </div>

            <div className="info-box info-box-highlight">
              <h4>Full Scan Includes:</h4>
              <ol>
                <li><strong>WhatWeb</strong> - General technology detection</li>
                <li><strong>CMSeeK</strong> - CMS-specific identification</li>
                <li><strong>WPScan</strong> - WordPress security audit (if WordPress detected)</li>
              </ol>
            </div>

            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate('/cms-scans')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? 'Creating...' : 'Start Full CMS Scan'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

export default NewCMSScan;
