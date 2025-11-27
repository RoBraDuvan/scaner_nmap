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
import ReconScans from './pages/ReconScans';
import NewReconScan from './pages/NewReconScan';
import ReconScanDetails from './pages/ReconScanDetails';
import APIScans from './pages/APIScans';
import NewAPIScan from './pages/NewAPIScan';
import APIScanDetails from './pages/APIScanDetails';
import CMSScans from './pages/CMSScans';
import NewCMSScan from './pages/NewCMSScan';
import CMSScanDetails from './pages/CMSScanDetails';
import CloudScans from './pages/CloudScans';
import NewCloudScan from './pages/NewCloudScan';
import CloudScanDetails from './pages/CloudScanDetails';
import CloudCredentials from './pages/CloudCredentials';
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
            <Route path="/recon" element={<ReconScans />} />
            <Route path="/new-recon" element={<NewReconScan />} />
            <Route path="/recon/:id" element={<ReconScanDetails />} />
            <Route path="/api-scans" element={<APIScans />} />
            <Route path="/new-api-scan" element={<NewAPIScan />} />
            <Route path="/api-scans/:id" element={<APIScanDetails />} />
            <Route path="/cms-scans" element={<CMSScans />} />
            <Route path="/new-cms-scan" element={<NewCMSScan />} />
            <Route path="/cms-scans/:id" element={<CMSScanDetails />} />
            <Route path="/cloud-scans" element={<CloudScans />} />
            <Route path="/new-cloud-scan" element={<NewCloudScan />} />
            <Route path="/cloud-scans/:id" element={<CloudScanDetails />} />
            <Route path="/cloud-credentials" element={<CloudCredentials />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
