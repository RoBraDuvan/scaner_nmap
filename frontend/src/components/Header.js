import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Header.css';

function Header() {
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  const closeMenu = () => {
    setMenuOpen(false);
  };

  return (
    <header className="header">
      <div className="header-container">
        <Link to="/" className="logo" onClick={closeMenu}>
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">Security Scanner</span>
        </Link>

        <button className={`menu-toggle ${menuOpen ? 'open' : ''}`} onClick={toggleMenu} aria-label="Toggle menu">
          <div className="menu-icon">
            <span></span>
            <span></span>
            <span></span>
          </div>
        </button>

        <nav className={`nav ${menuOpen ? 'open' : ''}`}>
          <Link
            to="/"
            className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
            onClick={closeMenu}
          >
            Dashboard
          </Link>
          <Link
            to="/network-scans"
            className={`nav-link ${location.pathname === '/network-scans' || location.pathname === '/new-scan' || location.pathname.startsWith('/scan/') ? 'active' : ''}`}
            onClick={closeMenu}
          >
            Network Scans
          </Link>
          <Link
            to="/vulnerabilities"
            className={`nav-link ${location.pathname.startsWith('/vulnerabilities') || location.pathname.startsWith('/vuln-scan') || location.pathname === '/new-vuln-scan' ? 'active' : ''}`}
            onClick={closeMenu}
          >
            Vulnerabilities
          </Link>
          <Link
            to="/webscans"
            className={`nav-link ${location.pathname === '/webscans' || location.pathname === '/new-webscan' || location.pathname.startsWith('/webscan/') ? 'active' : ''}`}
            onClick={closeMenu}
          >
            Web Scans
          </Link>
          <Link
            to="/recon"
            className={`nav-link ${location.pathname === '/recon' || location.pathname === '/new-recon' || location.pathname.startsWith('/recon/') ? 'active' : ''}`}
            onClick={closeMenu}
          >
            Recon
          </Link>
          <Link
            to="/api-scans"
            className={`nav-link ${location.pathname === '/api-scans' || location.pathname === '/new-api-scan' || location.pathname.startsWith('/api-scans/') ? 'active' : ''}`}
            onClick={closeMenu}
          >
            API Discovery
          </Link>
          <Link
            to="/cms-scans"
            className={`nav-link ${location.pathname === '/cms-scans' || location.pathname === '/new-cms-scan' || location.pathname.startsWith('/cms-scans/') ? 'active' : ''}`}
            onClick={closeMenu}
          >
            CMS Detection
          </Link>
          <Link
            to="/templates"
            className={`nav-link ${location.pathname === '/templates' ? 'active' : ''}`}
            onClick={closeMenu}
          >
            Templates
          </Link>
        </nav>
      </div>
    </header>
  );
}

export default Header;
