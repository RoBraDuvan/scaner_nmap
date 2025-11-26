import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import NetworkScans from './pages/NetworkScans';
import NewScan from './pages/NewScan';
import ScanDetails from './pages/ScanDetails';
import Templates from './pages/Templates';
import Vulnerabilities from './pages/Vulnerabilities';
import NewVulnScan from './pages/NewVulnScan';
import VulnScanDetails from './pages/VulnScanDetails';
import WebScans from './pages/WebScans';
import NewWebScan from './pages/NewWebScan';
import WebScanDetails from './pages/WebScanDetails';
import './App.css';

function App() {
  return (
    <Router>
      <div className="App">
        <Header />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/network-scans" element={<NetworkScans />} />
            <Route path="/new-scan" element={<NewScan />} />
            <Route path="/scan/:id" element={<ScanDetails />} />
            <Route path="/templates" element={<Templates />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/new-vuln-scan" element={<NewVulnScan />} />
            <Route path="/vuln-scan/:id" element={<VulnScanDetails />} />
            <Route path="/webscans" element={<WebScans />} />
            <Route path="/new-webscan" element={<NewWebScan />} />
            <Route path="/webscan/:id" element={<WebScanDetails />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
