import React, { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Header.css';

function Header() {
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [scansDropdownOpen, setScansDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('darkMode');
    return saved ? JSON.parse(saved) : false;
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : 'light');
    localStorage.setItem('darkMode', JSON.stringify(darkMode));
  }, [darkMode]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setScansDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  const closeMenu = () => {
    setMenuOpen(false);
    setScansDropdownOpen(false);
  };

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  const toggleScansDropdown = () => {
    setScansDropdownOpen(!scansDropdownOpen);
  };

  // Check if any scan page is active
  const isScansActive =
    location.pathname === '/network-scans' ||
    location.pathname === '/new-scan' ||
    location.pathname.startsWith('/scan/') ||
    location.pathname.startsWith('/vulnerabilities') ||
    location.pathname.startsWith('/vuln-scan') ||
    location.pathname === '/new-vuln-scan' ||
    location.pathname === '/webscans' ||
    location.pathname === '/new-webscan' ||
    location.pathname.startsWith('/webscan/') ||
    location.pathname === '/recon' ||
    location.pathname === '/new-recon' ||
    location.pathname.startsWith('/recon/') ||
    location.pathname === '/api-scans' ||
    location.pathname === '/new-api-scan' ||
    location.pathname.startsWith('/api-scans/') ||
    location.pathname === '/cms-scans' ||
    location.pathname === '/new-cms-scan' ||
    location.pathname.startsWith('/cms-scans/') ||
    location.pathname === '/cloud-scans' ||
    location.pathname === '/new-cloud-scan' ||
    location.pathname.startsWith('/cloud-scans/');

  return (
    <header className="header">
      <div className="header-container">
        <Link to="/" className="logo" onClick={closeMenu}>
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">Security Scanner</span>
        </Link>

        <div className="header-actions">
          <button
            className="theme-toggle"
            onClick={toggleDarkMode}
            aria-label="Toggle dark mode"
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? '☀️' : '🌙'}
          </button>

          <button className={`menu-toggle ${menuOpen ? 'open' : ''}`} onClick={toggleMenu} aria-label="Toggle menu">
            <div className="menu-icon">
              <span></span>
              <span></span>
              <span></span>
            </div>
          </button>
        </div>

        <nav className={`nav ${menuOpen ? 'open' : ''}`}>
          <Link
            to="/"
            className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
            onClick={closeMenu}
          >
            Dashboard
          </Link>

          {/* Desktop dropdown */}
          <div className="nav-dropdown" ref={dropdownRef}>
            <button
              className={`nav-link dropdown-toggle ${isScansActive ? 'active' : ''}`}
              onClick={toggleScansDropdown}
            >
              Scans
              <span className={`dropdown-arrow ${scansDropdownOpen ? 'open' : ''}`}>▾</span>
            </button>
            <div className={`dropdown-menu ${scansDropdownOpen ? 'open' : ''}`}>
              <Link
                to="/network-scans"
                className={`dropdown-item ${location.pathname === '/network-scans' || location.pathname === '/new-scan' || location.pathname.startsWith('/scan/') ? 'active' : ''}`}
                onClick={closeMenu}
              >
                <span className="dropdown-icon">🌐</span>
                Network
              </Link>
              <Link
                to="/vulnerabilities"
                className={`dropdown-item ${location.pathname.startsWith('/vulnerabilities') || location.pathname.startsWith('/vuln-scan') || location.pathname === '/new-vuln-scan' ? 'active' : ''}`}
                onClick={closeMenu}
              >
                <span className="dropdown-icon">🔓</span>
                Vulnerabilities
              </Link>
              <Link
                to="/webscans"
                className={`dropdown-item ${location.pathname === '/webscans' || location.pathname === '/new-webscan' || location.pathname.startsWith('/webscan/') ? 'active' : ''}`}
                onClick={closeMenu}
              >
                <span className="dropdown-icon">🕸️</span>
                Web
              </Link>
              <Link
                to="/recon"
                className={`dropdown-item ${location.pathname === '/recon' || location.pathname === '/new-recon' || location.pathname.startsWith('/recon/') ? 'active' : ''}`}
                onClick={closeMenu}
              >
                <span className="dropdown-icon">🔍</span>
                Recon
              </Link>
              <Link
                to="/api-scans"
                className={`dropdown-item ${location.pathname === '/api-scans' || location.pathname === '/new-api-scan' || location.pathname.startsWith('/api-scans/') ? 'active' : ''}`}
                onClick={closeMenu}
              >
                <span className="dropdown-icon">🔌</span>
                API Discovery
              </Link>
              <Link
                to="/cms-scans"
                className={`dropdown-item ${location.pathname === '/cms-scans' || location.pathname === '/new-cms-scan' || location.pathname.startsWith('/cms-scans/') ? 'active' : ''}`}
                onClick={closeMenu}
              >
                <span className="dropdown-icon">📝</span>
                CMS Detection
              </Link>
              <Link
                to="/cloud-scans"
                className={`dropdown-item ${location.pathname === '/cloud-scans' || location.pathname === '/new-cloud-scan' || location.pathname.startsWith('/cloud-scans/') ? 'active' : ''}`}
                onClick={closeMenu}
              >
                <span className="dropdown-icon">☁️</span>
                Cloud Security
              </Link>
              <div className="dropdown-divider"></div>
              <Link
                to="/cloud-credentials"
                className={`dropdown-item ${location.pathname === '/cloud-credentials' ? 'active' : ''}`}
                onClick={closeMenu}
              >
                <span className="dropdown-icon">🔑</span>
                Cloud Credentials
              </Link>
            </div>
          </div>

          <Link
            to="/templates"
            className={`nav-link ${location.pathname === '/templates' ? 'active' : ''}`}
            onClick={closeMenu}
          >
            Templates
          </Link>

          {/* Mobile: Show all links directly */}
          <div className="mobile-nav-items">
            <Link
              to="/network-scans"
              className={`nav-link ${location.pathname === '/network-scans' || location.pathname === '/new-scan' || location.pathname.startsWith('/scan/') ? 'active' : ''}`}
              onClick={closeMenu}
            >
              🌐 Network Scans
            </Link>
            <Link
              to="/vulnerabilities"
              className={`nav-link ${location.pathname.startsWith('/vulnerabilities') || location.pathname.startsWith('/vuln-scan') || location.pathname === '/new-vuln-scan' ? 'active' : ''}`}
              onClick={closeMenu}
            >
              🔓 Vulnerabilities
            </Link>
            <Link
              to="/webscans"
              className={`nav-link ${location.pathname === '/webscans' || location.pathname === '/new-webscan' || location.pathname.startsWith('/webscan/') ? 'active' : ''}`}
              onClick={closeMenu}
            >
              🕸️ Web Scans
            </Link>
            <Link
              to="/recon"
              className={`nav-link ${location.pathname === '/recon' || location.pathname === '/new-recon' || location.pathname.startsWith('/recon/') ? 'active' : ''}`}
              onClick={closeMenu}
            >
              🔍 Recon
            </Link>
            <Link
              to="/api-scans"
              className={`nav-link ${location.pathname === '/api-scans' || location.pathname === '/new-api-scan' || location.pathname.startsWith('/api-scans/') ? 'active' : ''}`}
              onClick={closeMenu}
            >
              🔌 API Discovery
            </Link>
            <Link
              to="/cms-scans"
              className={`nav-link ${location.pathname === '/cms-scans' || location.pathname === '/new-cms-scan' || location.pathname.startsWith('/cms-scans/') ? 'active' : ''}`}
              onClick={closeMenu}
            >
              📝 CMS Detection
            </Link>
            <Link
              to="/cloud-scans"
              className={`nav-link ${location.pathname === '/cloud-scans' || location.pathname === '/new-cloud-scan' || location.pathname.startsWith('/cloud-scans/') ? 'active' : ''}`}
              onClick={closeMenu}
            >
              ☁️ Cloud Security
            </Link>
          </div>
        </nav>
      </div>
    </header>
  );
}

export default Header;
