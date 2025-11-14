-- Initialize database schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    configuration JSONB,
    CONSTRAINT valid_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
);

-- Scan results table
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    host VARCHAR(255) NOT NULL,
    hostname VARCHAR(255),
    state VARCHAR(50),
    ports JSONB,
    os_detection JSONB,
    services JSONB,
    vulnerabilities JSONB,
    raw_output TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan templates table
CREATE TABLE IF NOT EXISTS scan_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    scan_type VARCHAR(50) NOT NULL,
    nmap_arguments VARCHAR(500),
    configuration JSONB,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan history/logs table
CREATE TABLE IF NOT EXISTS scan_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for better performance
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX idx_scan_results_host ON scan_results(host);
CREATE INDEX idx_scan_logs_scan_id ON scan_logs(scan_id);

-- Insert default scan templates
INSERT INTO scan_templates (name, description, scan_type, nmap_arguments, configuration, is_default) VALUES
('Quick Scan', 'Fast scan of the most common 100 ports', 'quick', '-F -T4', '{"timeout": 300, "max_hosts": 256}', true),
('Full Port Scan', 'Comprehensive scan of all 65535 ports', 'full', '-p- -T4', '{"timeout": 3600, "max_hosts": 10}', true),
('Service Version Detection', 'Detect service versions and OS', 'service', '-sV -O -T4', '{"timeout": 1800, "max_hosts": 50}', true),
('Stealth Scan', 'SYN stealth scan with minimal footprint', 'stealth', '-sS -T2 -f', '{"timeout": 2400, "max_hosts": 20}', false),
('Vulnerability Scan', 'Scan with NSE vulnerability scripts', 'vulnerability', '-sV --script vuln -T4', '{"timeout": 3600, "max_hosts": 10}', true),
('Ping Sweep', 'Discover live hosts only', 'ping', '-sn -T4', '{"timeout": 300, "max_hosts": 1024}', false),
('UDP Scan', 'Scan common UDP ports', 'udp', '-sU --top-ports 100 -T4', '{"timeout": 1800, "max_hosts": 50}', false),
('Aggressive Scan', 'Aggressive scan with OS detection, version, scripts and traceroute', 'aggressive', '-A -T4', '{"timeout": 2400, "max_hosts": 20}', true);
