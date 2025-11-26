import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Header.css';

function Header() {
  const location = useLocation();

  return (
    <header className="header">
      <div className="header-container">
        <Link to="/" className="logo">
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">Security Scanner</span>
        </Link>

        <nav className="nav">
          <Link
            to="/"
            className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
          >
            Dashboard
          </Link>
          <Link
            to="/network-scans"
            className={`nav-link ${location.pathname === '/network-scans' || location.pathname === '/new-scan' || location.pathname.startsWith('/scan/') ? 'active' : ''}`}
          >
            Network Scans
          </Link>
          <Link
            to="/vulnerabilities"
            className={`nav-link ${location.pathname.startsWith('/vulnerabilities') || location.pathname.startsWith('/vuln-scan') || location.pathname === '/new-vuln-scan' ? 'active' : ''}`}
          >
            Vulnerabilities
          </Link>
          <Link
            to="/webscans"
            className={`nav-link ${location.pathname === '/webscans' || location.pathname === '/new-webscan' || location.pathname.startsWith('/webscan/') ? 'active' : ''}`}
          >
            Web Scans
          </Link>
          <Link
            to="/templates"
            className={`nav-link ${location.pathname === '/templates' ? 'active' : ''}`}
          >
            Templates
          </Link>
        </nav>
      </div>
    </header>
  );
}

export default Header;
