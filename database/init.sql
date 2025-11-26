-- Initialize database schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    scanner VARCHAR(50) NOT NULL DEFAULT 'nmap',
    status VARCHAR(50) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    configuration JSONB,
    nmap_arguments VARCHAR(500),
    CONSTRAINT valid_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_scan_scanner CHECK (scanner IN ('nmap', 'masscan', 'dns'))
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
    mac_address VARCHAR(17),
    mac_vendor TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan templates table
CREATE TABLE IF NOT EXISTS scan_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    scan_type VARCHAR(50) NOT NULL,
    scanner VARCHAR(50) NOT NULL DEFAULT 'nmap',
    nmap_arguments VARCHAR(500),
    ports VARCHAR(500),
    rate INTEGER,
    configuration JSONB,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_scanner CHECK (scanner IN ('nmap', 'masscan', 'dns'))
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
CREATE INDEX idx_scans_scanner ON scans(scanner);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX idx_scan_results_host ON scan_results(host);
CREATE INDEX idx_scan_logs_scan_id ON scan_logs(scan_id);
CREATE INDEX idx_scan_templates_scanner ON scan_templates(scanner);

-- Insert default scan templates
INSERT INTO scan_templates (name, description, scan_type, scanner, nmap_arguments, ports, rate, configuration, is_default) VALUES
-- =====================================================
-- NMAP TEMPLATES
-- =====================================================
-- Basic Port Scans
('Quick Scan', 'Fast scan of the most common 100 ports', 'quick', 'nmap', '-F -T4', NULL, NULL, '{"timeout": 300, "max_hosts": 256}', true),
('Full Port Scan', 'Comprehensive scan of all 65535 ports', 'full', 'nmap', '-p- -T4', NULL, NULL, '{"timeout": 3600, "max_hosts": 10}', true),
('UDP Scan', 'Scan common UDP ports', 'udp', 'nmap', '-sU --top-ports 100 -T4', NULL, NULL, '{"timeout": 1800, "max_hosts": 50}', true),

-- Network Discovery Scans
('Host Discovery', 'Discover active hosts in network (ping sweep)', 'discovery', 'nmap', '-sn -PE -PP -PM --dns-servers 8.8.8.8,1.1.1.1 -T4', NULL, NULL, '{"timeout": 300, "max_hosts": 1024}', true),
('Local Network Scan', 'Complete local network scan with MAC vendor identification', 'local_network', 'nmap', '-sn -PR --dns-servers 8.8.8.8,1.1.1.1 -T4', NULL, NULL, '{"timeout": 600, "max_hosts": 256}', true),

-- Server-Specific Scans
('Web Server Scan', 'Scan web servers (HTTP/HTTPS) with service detection', 'web_server', 'nmap', '-p 80,443,8080,8443,3000,5000,8000 -sV --script http-title,http-methods,http-headers -T4', NULL, NULL, '{"timeout": 900, "max_hosts": 50}', true),
('Database Server Scan', 'Scan common database ports with version detection', 'db_server', 'nmap', '-p 3306,5432,1433,1521,27017,6379,5984,9200,11211 -sV -T4', NULL, NULL, '{"timeout": 900, "max_hosts": 50}', true),
('Mail Server Scan', 'Scan mail servers (SMTP, POP3, IMAP)', 'mail_server', 'nmap', '-p 25,110,143,465,587,993,995 -sV --script smtp-commands,pop3-capabilities,imap-capabilities -T4', NULL, NULL, '{"timeout": 900, "max_hosts": 50}', true),
('FTP/SSH Server Scan', 'Scan file transfer and remote access services', 'ftp_ssh_server', 'nmap', '-p 20,21,22,23,990,2121,2222 -sV --script ftp-anon,ssh-auth-methods -T4', NULL, NULL, '{"timeout": 900, "max_hosts": 50}', true),
('DNS Server Scan (Nmap)', 'Scan DNS servers and detect configuration', 'dns_server', 'nmap', '-p 53 -sU -sV --script dns-nsid,dns-recursion -T4', NULL, NULL, '{"timeout": 900, "max_hosts": 50}', true),

-- Advanced Scans
('Service Version Detection', 'Detect service versions and OS', 'service', 'nmap', '-sV -O -T4', NULL, NULL, '{"timeout": 1800, "max_hosts": 50}', true),
('Vulnerability Scan', 'Scan with NSE vulnerability scripts', 'vulnerability', 'nmap', '-sV --script vuln -T4', NULL, NULL, '{"timeout": 3600, "max_hosts": 10}', true),
('Security Audit', 'Complete security audit with SSL/TLS checks', 'security_audit', 'nmap', '-p- -sV --script ssl-cert,ssl-enum-ciphers,ssh-auth-methods -T4', NULL, NULL, '{"timeout": 3600, "max_hosts": 20}', true),
('Stealth Scan', 'SYN stealth scan with minimal footprint', 'stealth', 'nmap', '-sS -T2 -f', NULL, NULL, '{"timeout": 2400, "max_hosts": 20}', true),
('Aggressive Scan', 'Aggressive scan with OS detection, version, scripts and traceroute', 'aggressive', 'nmap', '-A -T4', NULL, NULL, '{"timeout": 2400, "max_hosts": 20}', true),

-- =====================================================
-- MASSCAN TEMPLATES
-- =====================================================
('Masscan Quick Scan', 'Fast scan of common ports at high speed', 'masscan_quick', 'masscan', NULL, '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080', 10000, '{"timeout": 300}', true),
('Masscan Full Port Scan', 'Scan all 65535 ports at high speed', 'masscan_full', 'masscan', NULL, '1-65535', 100000, '{"timeout": 600}', true),
('Masscan Web Ports', 'Scan common web server ports', 'masscan_web', 'masscan', NULL, '80,443,8080,8443,8000,8888,9000,9090,3000,5000', 10000, '{"timeout": 180}', true),
('Masscan Database Ports', 'Scan common database ports', 'masscan_database', 'masscan', NULL, '1433,1521,3306,5432,6379,27017,9200,5984', 10000, '{"timeout": 180}', true),

-- =====================================================
-- DNS SCANNER TEMPLATES
-- =====================================================
('DNS Records Scan', 'Query all DNS record types (A, AAAA, MX, NS, TXT)', 'dns_records', 'dns', NULL, NULL, NULL, '{"timeout": 60}', true),
('Full DNS Scan', 'Complete DNS reconnaissance including subdomain enumeration', 'dns_full', 'dns', NULL, NULL, NULL, '{"timeout": 300, "enumerate_subdomains": true}', true),
('Subdomain Enumeration', 'Discover subdomains using common wordlist', 'dns_subdomain', 'dns', NULL, NULL, NULL, '{"timeout": 600, "wordlist": "common"}', true);

-- =====================================================
-- VULNERABILITY SCANNING TABLES (Nuclei Integration)
-- =====================================================

-- Vulnerability scans table
CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    target TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    templates TEXT[],
    severity TEXT[],
    tags TEXT[],
    configuration JSONB,
    CONSTRAINT valid_vuln_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
);

-- Vulnerability findings table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
    template_id VARCHAR(255) NOT NULL,
    template_name VARCHAR(500) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    host TEXT NOT NULL,
    matched_at TEXT,
    extracted_results TEXT[],
    curl_command TEXT,
    request TEXT,
    response TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability scan logs table
CREATE TABLE IF NOT EXISTS vulnerability_scan_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
    level VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability scan templates table (Nuclei presets)
CREATE TABLE IF NOT EXISTS vulnerability_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    nuclei_tags TEXT[],
    nuclei_templates TEXT[],
    severity_filter TEXT[],
    configuration JSONB,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for vulnerability tables
CREATE INDEX idx_vuln_scans_status ON vulnerability_scans(status);
CREATE INDEX idx_vuln_scans_created_at ON vulnerability_scans(created_at DESC);
CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_created_at ON vulnerabilities(created_at DESC);
CREATE INDEX idx_vuln_scan_logs_scan_id ON vulnerability_scan_logs(scan_id);
CREATE INDEX idx_vuln_templates_category ON vulnerability_templates(category);

-- Insert default vulnerability scan templates (Nuclei presets)
INSERT INTO vulnerability_templates (name, description, category, nuclei_tags, nuclei_templates, severity_filter, configuration, is_default) VALUES
-- Web Application Scans
('Web Technologies', 'Detect web technologies, frameworks and CMS', 'discovery',
 ARRAY['tech', 'detect'], NULL, ARRAY['info'],
 '{"timeout": 300, "rate_limit": 150}', true),

('CVE Detection', 'Scan for known CVE vulnerabilities', 'vulnerability',
 ARRAY['cve'], NULL, ARRAY['low', 'medium', 'high', 'critical'],
 '{"timeout": 1800, "rate_limit": 100}', true),

('OWASP Top 10', 'Check for OWASP Top 10 vulnerabilities', 'vulnerability',
 ARRAY['owasp'], NULL, ARRAY['medium', 'high', 'critical'],
 '{"timeout": 1800, "rate_limit": 100}', true),

('XSS Detection', 'Cross-Site Scripting vulnerability detection', 'vulnerability',
 ARRAY['xss'], NULL, ARRAY['low', 'medium', 'high'],
 '{"timeout": 900, "rate_limit": 50}', true),

('SQL Injection', 'SQL Injection vulnerability detection', 'vulnerability',
 ARRAY['sqli'], NULL, ARRAY['medium', 'high', 'critical'],
 '{"timeout": 900, "rate_limit": 50}', true),

('Default Credentials', 'Check for default login credentials', 'misconfiguration',
 ARRAY['default-login'], NULL, ARRAY['medium', 'high', 'critical'],
 '{"timeout": 600, "rate_limit": 30}', true),

('Exposed Panels', 'Detect exposed admin panels and dashboards', 'exposure',
 ARRAY['panel', 'admin'], NULL, ARRAY['info', 'low', 'medium'],
 '{"timeout": 600, "rate_limit": 100}', true),

('Sensitive Files', 'Find exposed sensitive files and directories', 'exposure',
 ARRAY['exposure', 'config'], NULL, ARRAY['low', 'medium', 'high'],
 '{"timeout": 600, "rate_limit": 100}', true),

-- Network Service Scans
('SSL/TLS Issues', 'Check for SSL/TLS misconfigurations', 'misconfiguration',
 ARRAY['ssl', 'tls'], NULL, ARRAY['info', 'low', 'medium', 'high'],
 '{"timeout": 300, "rate_limit": 50}', true),

('Network Services', 'Scan network services for vulnerabilities', 'network',
 ARRAY['network'], NULL, ARRAY['medium', 'high', 'critical'],
 '{"timeout": 900, "rate_limit": 50}', true),

-- CMS Specific
('WordPress Scan', 'WordPress specific vulnerability scan', 'cms',
 ARRAY['wordpress', 'wp-plugin'], NULL, ARRAY['low', 'medium', 'high', 'critical'],
 '{"timeout": 1200, "rate_limit": 50}', true),

('Joomla Scan', 'Joomla specific vulnerability scan', 'cms',
 ARRAY['joomla'], NULL, ARRAY['low', 'medium', 'high', 'critical'],
 '{"timeout": 900, "rate_limit": 50}', true),

('Drupal Scan', 'Drupal specific vulnerability scan', 'cms',
 ARRAY['drupal'], NULL, ARRAY['low', 'medium', 'high', 'critical'],
 '{"timeout": 900, "rate_limit": 50}', true),

-- Cloud & DevOps
('Cloud Misconfiguration', 'Check for cloud service misconfigurations', 'cloud',
 ARRAY['cloud', 'aws', 'azure', 'gcp'], NULL, ARRAY['low', 'medium', 'high', 'critical'],
 '{"timeout": 600, "rate_limit": 50}', true),

('CI/CD Exposure', 'Detect exposed CI/CD configurations', 'devops',
 ARRAY['cicd', 'git'], NULL, ARRAY['medium', 'high', 'critical'],
 '{"timeout": 300, "rate_limit": 50}', true),

('API Security', 'API endpoint security checks', 'api',
 ARRAY['api'], NULL, ARRAY['low', 'medium', 'high', 'critical'],
 '{"timeout": 900, "rate_limit": 50}', true),

-- Comprehensive Scans
('Quick Vulnerability Scan', 'Fast scan with common vulnerability checks', 'comprehensive',
 ARRAY['cve', 'tech'], NULL, ARRAY['medium', 'high', 'critical'],
 '{"timeout": 600, "rate_limit": 150}', true),

('Full Security Audit', 'Comprehensive security audit with all checks', 'comprehensive',
 NULL, NULL, ARRAY['info', 'low', 'medium', 'high', 'critical'],
 '{"timeout": 7200, "rate_limit": 50}', true);

-- Comments
COMMENT ON TABLE vulnerability_scans IS 'Stores Nuclei vulnerability scan jobs';
COMMENT ON TABLE vulnerabilities IS 'Stores vulnerability findings from Nuclei';
COMMENT ON TABLE vulnerability_scan_logs IS 'Stores execution logs for vulnerability scans';
COMMENT ON TABLE vulnerability_templates IS 'Stores preset configurations for Nuclei scans';

-- =====================================================
-- WEB SCANNING TABLES (ffuf, Gowitness, testssl.sh)
-- =====================================================

-- Web scans table
CREATE TABLE IF NOT EXISTS web_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    target TEXT NOT NULL,
    tool VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    configuration JSONB,
    CONSTRAINT valid_web_scan_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_web_scan_tool CHECK (tool IN ('ffuf', 'gowitness', 'testssl'))
);

-- Web scan results table (unified for all web scanning tools)
CREATE TABLE IF NOT EXISTS web_scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES web_scans(id) ON DELETE CASCADE,
    tool VARCHAR(50) NOT NULL,
    url TEXT,
    -- ffuf specific fields
    status_code INTEGER,
    content_length INTEGER,
    words INTEGER,
    lines INTEGER,
    content_type VARCHAR(255),
    redirect_url TEXT,
    -- gowitness specific fields
    title VARCHAR(500),
    screenshot_path TEXT,
    screenshot_b64 TEXT,
    -- testssl specific fields
    finding_id VARCHAR(100),
    severity VARCHAR(50),
    finding_text TEXT,
    cve VARCHAR(50),
    cwe VARCHAR(50),
    -- common fields
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Web scan logs table
CREATE TABLE IF NOT EXISTS web_scan_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES web_scans(id) ON DELETE CASCADE,
    level VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for web scanning tables
CREATE INDEX idx_web_scans_status ON web_scans(status);
CREATE INDEX idx_web_scans_tool ON web_scans(tool);
CREATE INDEX idx_web_scans_created_at ON web_scans(created_at DESC);
CREATE INDEX idx_web_scan_results_scan_id ON web_scan_results(scan_id);
CREATE INDEX idx_web_scan_results_tool ON web_scan_results(tool);
CREATE INDEX idx_web_scan_results_severity ON web_scan_results(severity);
CREATE INDEX idx_web_scan_logs_scan_id ON web_scan_logs(scan_id);

-- Comments for web scanning tables
COMMENT ON TABLE web_scans IS 'Stores web scanning jobs (ffuf, gowitness, testssl.sh)';
COMMENT ON TABLE web_scan_results IS 'Stores results from web scanning tools';
COMMENT ON TABLE web_scan_logs IS 'Stores execution logs for web scans';

-- =====================================================
-- RECON SCANNING TABLES (Subdomain, WHOIS, DNS, Tech)
-- =====================================================

-- Recon scans table
CREATE TABLE IF NOT EXISTS recon_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    target TEXT NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    configuration JSONB,
    CONSTRAINT valid_recon_scan_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_recon_scan_type CHECK (scan_type IN ('subdomain', 'whois', 'dns', 'tech'))
);

-- Subdomain results table
CREATE TABLE IF NOT EXISTS subdomain_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
    subdomain VARCHAR(500) NOT NULL,
    source VARCHAR(100),
    ip_addresses TEXT[],
    is_alive BOOLEAN DEFAULT false,
    http_status INTEGER,
    https_status INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, subdomain)
);

-- WHOIS results table
CREATE TABLE IF NOT EXISTS whois_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    registrar TEXT,
    registrar_url TEXT,
    creation_date TIMESTAMP,
    expiration_date TIMESTAMP,
    updated_date TIMESTAMP,
    name_servers TEXT[],
    status TEXT[],
    registrant JSONB,
    admin_contact JSONB,
    tech_contact JSONB,
    raw_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, domain)
);

-- DNS results table
CREATE TABLE IF NOT EXISTS dns_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    a_records TEXT[],
    aaaa_records TEXT[],
    cname_records TEXT[],
    mx_records JSONB,
    ns_records TEXT[],
    txt_records TEXT[],
    soa_record JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, domain)
);

-- Tech detection results table
CREATE TABLE IF NOT EXISTS tech_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    server TEXT,
    content_type TEXT,
    technologies JSONB,
    headers JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, url)
);

-- Recon scan logs table
CREATE TABLE IF NOT EXISTS recon_scan_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
    level VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for recon tables
CREATE INDEX idx_recon_scans_status ON recon_scans(status);
CREATE INDEX idx_recon_scans_type ON recon_scans(scan_type);
CREATE INDEX idx_recon_scans_created_at ON recon_scans(created_at DESC);
CREATE INDEX idx_subdomain_results_scan_id ON subdomain_results(scan_id);
CREATE INDEX idx_whois_results_scan_id ON whois_results(scan_id);
CREATE INDEX idx_dns_results_scan_id ON dns_results(scan_id);
CREATE INDEX idx_tech_results_scan_id ON tech_results(scan_id);
CREATE INDEX idx_recon_scan_logs_scan_id ON recon_scan_logs(scan_id);

-- Comments for recon tables
COMMENT ON TABLE recon_scans IS 'Stores recon scanning jobs (subdomain, whois, dns, tech)';
COMMENT ON TABLE subdomain_results IS 'Stores subdomain enumeration results';
COMMENT ON TABLE whois_results IS 'Stores WHOIS lookup results';
COMMENT ON TABLE dns_results IS 'Stores DNS record query results';
COMMENT ON TABLE tech_results IS 'Stores technology detection results';
COMMENT ON TABLE recon_scan_logs IS 'Stores execution logs for recon scans';

-- =====================================================
-- API DISCOVERY TABLES (Kiterunner, Arjun, GraphQL, Swagger)
-- =====================================================

-- API scans table
CREATE TABLE IF NOT EXISTS api_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    target TEXT NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    config JSONB,
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    CONSTRAINT valid_api_scan_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_api_scan_type CHECK (scan_type IN ('kiterunner', 'arjun', 'graphql', 'swagger', 'full'))
);

-- API endpoints table
CREATE TABLE IF NOT EXISTS api_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES api_scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    method VARCHAR(20) NOT NULL,
    status_code INTEGER,
    content_type TEXT,
    length INTEGER DEFAULT 0,
    source VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, url, method)
);

-- API parameters table
CREATE TABLE IF NOT EXISTS api_parameters (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES api_scans(id) ON DELETE CASCADE,
    endpoint_id UUID REFERENCES api_endpoints(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    name VARCHAR(255) NOT NULL,
    param_type VARCHAR(50) NOT NULL,
    method VARCHAR(20) NOT NULL,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, url, name, param_type)
);

-- GraphQL schemas table
CREATE TABLE IF NOT EXISTS graphql_schemas (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES api_scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    introspection_enabled BOOLEAN DEFAULT false,
    types JSONB,
    queries JSONB,
    mutations JSONB,
    subscriptions JSONB,
    raw_schema TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, url)
);

-- Swagger/OpenAPI specs table
CREATE TABLE IF NOT EXISTS swagger_specs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES api_scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    version VARCHAR(50),
    title TEXT,
    description TEXT,
    base_path TEXT,
    paths JSONB,
    raw_spec TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, url)
);

-- API scan logs table
CREATE TABLE IF NOT EXISTS api_scan_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES api_scans(id) ON DELETE CASCADE,
    level VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for API discovery tables
CREATE INDEX idx_api_scans_status ON api_scans(status);
CREATE INDEX idx_api_scans_type ON api_scans(scan_type);
CREATE INDEX idx_api_scans_created_at ON api_scans(created_at DESC);
CREATE INDEX idx_api_endpoints_scan_id ON api_endpoints(scan_id);
CREATE INDEX idx_api_endpoints_method ON api_endpoints(method);
CREATE INDEX idx_api_parameters_scan_id ON api_parameters(scan_id);
CREATE INDEX idx_api_parameters_type ON api_parameters(param_type);
CREATE INDEX idx_graphql_schemas_scan_id ON graphql_schemas(scan_id);
CREATE INDEX idx_swagger_specs_scan_id ON swagger_specs(scan_id);
CREATE INDEX idx_api_scan_logs_scan_id ON api_scan_logs(scan_id);

-- Comments for API discovery tables
COMMENT ON TABLE api_scans IS 'Stores API discovery scan jobs (Kiterunner, Arjun, GraphQL, Swagger)';
COMMENT ON TABLE api_endpoints IS 'Stores discovered API endpoints';
COMMENT ON TABLE api_parameters IS 'Stores discovered API parameters';
COMMENT ON TABLE graphql_schemas IS 'Stores GraphQL introspection results';
COMMENT ON TABLE swagger_specs IS 'Stores discovered OpenAPI/Swagger specifications';
COMMENT ON TABLE api_scan_logs IS 'Stores execution logs for API scans';
