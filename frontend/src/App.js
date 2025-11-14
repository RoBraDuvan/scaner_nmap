import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanDetails from './pages/ScanDetails';
import Templates from './pages/Templates';
import './App.css';

function App() {
  return (
    <Router>
      <div className="App">
        <Header />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/new-scan" element={<NewScan />} />
            <Route path="/scan/:id" element={<ScanDetails />} />
            <Route path="/templates" element={<Templates />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
