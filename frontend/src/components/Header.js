import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Header.css';

function Header() {
  const location = useLocation();

  return (
    <header className="header">
      <div className="header-container">
        <Link to="/" className="logo">
          <span className="logo-icon">🔍</span>
          <span className="logo-text">Nmap Scanner</span>
        </Link>

        <nav className="nav">
          <Link
            to="/"
            className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
          >
            Dashboard
          </Link>
          <Link
            to="/new-scan"
            className={`nav-link ${location.pathname === '/new-scan' ? 'active' : ''}`}
          >
            New Scan
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
