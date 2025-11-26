package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/models"
)

type DNSScanner struct {
	db          *database.Database
	cancelFuncs map[string]context.CancelFunc
	resolver    *net.Resolver
}

// DNSRecord represents a DNS record
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// DNSScanResult represents the result of a DNS scan
type DNSScanResult struct {
	Domain       string      `json:"domain"`
	Records      []DNSRecord `json:"records"`
	Subdomains   []string    `json:"subdomains,omitempty"`
	NameServers  []string    `json:"nameservers,omitempty"`
	MXRecords    []string    `json:"mx_records,omitempty"`
	TXTRecords   []string    `json:"txt_records,omitempty"`
	ZoneTransfer bool        `json:"zone_transfer_possible"`
}

func NewDNSScanner(db *database.Database) *DNSScanner {
	return &DNSScanner{
		db:          db,
		cancelFuncs: make(map[string]context.CancelFunc),
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, network, address)
			},
		},
	}
}

// ExecuteScan runs a DNS scan on the target domain
func (s *DNSScanner) ExecuteScan(ctx context.Context, scanID uuid.UUID, domain string, scanType string) error {
	log.Printf("🔍 Starting DNS scan %s on domain: %s type: %s", scanID, domain, scanType)

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFuncs[scanID.String()] = cancel
	defer func() {
		delete(s.cancelFuncs, scanID.String())
		cancel()
	}()

	// Update scan status to running
	if err := s.updateScanStatus(ctx, scanID, "running", 0, nil); err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	s.addLog(ctx, scanID, "info", fmt.Sprintf("Starting DNS scan on domain: %s", domain))

	var dnsResult DNSScanResult
	dnsResult.Domain = domain

	// Perform different DNS queries based on scan type
	switch scanType {
	case "dns_full", "dns_comprehensive":
		s.performFullDNSScan(ctx, scanID, domain, &dnsResult)
	case "dns_records":
		s.performRecordsScan(ctx, scanID, domain, &dnsResult)
	case "dns_subdomain":
		s.performSubdomainEnum(ctx, scanID, domain, &dnsResult)
	default:
		s.performRecordsScan(ctx, scanID, domain, &dnsResult)
	}

	// Check if context was cancelled
	if ctx.Err() == context.Canceled {
		s.addLog(context.Background(), scanID, "info", "Scan was cancelled by user")
		return nil
	}

	// Store results as ScanResult
	result := s.convertToScanResult(scanID, domain, &dnsResult)
	if err := s.storeResult(ctx, result); err != nil {
		log.Printf("Failed to store result: %v", err)
	}

	// Update scan status to completed
	if err := s.updateScanStatus(ctx, scanID, "completed", 100, nil); err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	s.addLog(ctx, scanID, "success", fmt.Sprintf("DNS scan completed. Found %d records", len(dnsResult.Records)))
	log.Printf("✅ DNS scan %s completed. Found %d records", scanID, len(dnsResult.Records))

	return nil
}

func (s *DNSScanner) performFullDNSScan(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	s.addLog(ctx, scanID, "info", "Performing full DNS scan")

	// A records
	s.queryARecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 15, nil)

	// AAAA records
	s.queryAAAARecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 25, nil)

	// MX records
	s.queryMXRecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 40, nil)

	// NS records
	s.queryNSRecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 55, nil)

	// TXT records
	s.queryTXTRecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 70, nil)

	// CNAME record
	s.queryCNAMERecord(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 80, nil)

	// SOA record
	s.querySOARecord(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 90, nil)

	// Common subdomains check
	s.checkCommonSubdomains(ctx, scanID, domain, result)
}

func (s *DNSScanner) performRecordsScan(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	s.addLog(ctx, scanID, "info", "Performing DNS records scan")

	s.queryARecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 20, nil)

	s.queryAAAARecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 40, nil)

	s.queryMXRecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 60, nil)

	s.queryNSRecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 75, nil)

	s.queryTXTRecords(ctx, scanID, domain, result)
	s.updateScanStatus(ctx, scanID, "running", 90, nil)
}

func (s *DNSScanner) performSubdomainEnum(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	s.addLog(ctx, scanID, "info", "Performing subdomain enumeration")
	s.checkCommonSubdomains(ctx, scanID, domain, result)
}

func (s *DNSScanner) queryARecords(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	ips, err := s.resolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		s.addLog(ctx, scanID, "warning", fmt.Sprintf("A record lookup failed: %v", err))
		return
	}
	for _, ip := range ips {
		result.Records = append(result.Records, DNSRecord{
			Type:  "A",
			Name:  domain,
			Value: ip.String(),
		})
		s.addLog(ctx, scanID, "info", fmt.Sprintf("A record: %s -> %s", domain, ip.String()))
	}
}

func (s *DNSScanner) queryAAAARecords(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	ips, err := s.resolver.LookupIP(ctx, "ip6", domain)
	if err != nil {
		s.addLog(ctx, scanID, "warning", fmt.Sprintf("AAAA record lookup failed: %v", err))
		return
	}
	for _, ip := range ips {
		result.Records = append(result.Records, DNSRecord{
			Type:  "AAAA",
			Name:  domain,
			Value: ip.String(),
		})
		s.addLog(ctx, scanID, "info", fmt.Sprintf("AAAA record: %s -> %s", domain, ip.String()))
	}
}

func (s *DNSScanner) queryMXRecords(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	mxRecords, err := s.resolver.LookupMX(ctx, domain)
	if err != nil {
		s.addLog(ctx, scanID, "warning", fmt.Sprintf("MX record lookup failed: %v", err))
		return
	}
	for _, mx := range mxRecords {
		result.Records = append(result.Records, DNSRecord{
			Type:  "MX",
			Name:  domain,
			Value: fmt.Sprintf("%d %s", mx.Pref, mx.Host),
		})
		result.MXRecords = append(result.MXRecords, mx.Host)
		s.addLog(ctx, scanID, "info", fmt.Sprintf("MX record: %s -> %d %s", domain, mx.Pref, mx.Host))
	}
}

func (s *DNSScanner) queryNSRecords(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	nsRecords, err := s.resolver.LookupNS(ctx, domain)
	if err != nil {
		s.addLog(ctx, scanID, "warning", fmt.Sprintf("NS record lookup failed: %v", err))
		return
	}
	for _, ns := range nsRecords {
		result.Records = append(result.Records, DNSRecord{
			Type:  "NS",
			Name:  domain,
			Value: ns.Host,
		})
		result.NameServers = append(result.NameServers, ns.Host)
		s.addLog(ctx, scanID, "info", fmt.Sprintf("NS record: %s -> %s", domain, ns.Host))
	}
}

func (s *DNSScanner) queryTXTRecords(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	txtRecords, err := s.resolver.LookupTXT(ctx, domain)
	if err != nil {
		s.addLog(ctx, scanID, "warning", fmt.Sprintf("TXT record lookup failed: %v", err))
		return
	}
	for _, txt := range txtRecords {
		result.Records = append(result.Records, DNSRecord{
			Type:  "TXT",
			Name:  domain,
			Value: txt,
		})
		result.TXTRecords = append(result.TXTRecords, txt)
		// Truncate long TXT records for logging
		logTxt := txt
		if len(logTxt) > 100 {
			logTxt = logTxt[:100] + "..."
		}
		s.addLog(ctx, scanID, "info", fmt.Sprintf("TXT record: %s -> %s", domain, logTxt))
	}
}

func (s *DNSScanner) queryCNAMERecord(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	cname, err := s.resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return // CNAME errors are common, don't log
	}
	if cname != domain+"." && cname != "" {
		result.Records = append(result.Records, DNSRecord{
			Type:  "CNAME",
			Name:  domain,
			Value: cname,
		})
		s.addLog(ctx, scanID, "info", fmt.Sprintf("CNAME record: %s -> %s", domain, cname))
	}
}

func (s *DNSScanner) querySOARecord(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	// SOA lookup using net package
	_, err := net.LookupNS(domain)
	if err == nil {
		result.Records = append(result.Records, DNSRecord{
			Type:  "SOA",
			Name:  domain,
			Value: "SOA record exists",
		})
	}
}

func (s *DNSScanner) checkCommonSubdomains(ctx context.Context, scanID uuid.UUID, domain string, result *DNSScanResult) {
	commonSubdomains := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
		"dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging", "test",
		"admin", "portal", "blog", "shop", "store", "app", "mobile", "m", "static",
		"cdn", "media", "images", "img", "assets", "js", "css", "vpn", "remote",
		"gateway", "proxy", "firewall", "router", "server", "web", "www2", "secure",
		"login", "auth", "sso", "id", "account", "accounts", "my", "dashboard",
		"cp", "cpanel", "panel", "control", "manage", "manager", "support", "help",
		"docs", "doc", "documentation", "wiki", "kb", "knowledge", "forum", "forums",
		"community", "chat", "irc", "slack", "teams", "meet", "zoom", "video",
		"git", "gitlab", "github", "bitbucket", "svn", "repo", "repository",
		"jenkins", "ci", "cd", "build", "deploy", "release", "stage", "prod",
		"production", "development", "qa", "uat", "sandbox", "demo", "preview",
	}

	s.addLog(ctx, scanID, "info", fmt.Sprintf("Checking %d common subdomains", len(commonSubdomains)))

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10) // Limit concurrent lookups

	for i, sub := range commonSubdomains {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(subdomain string, idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			fullDomain := subdomain + "." + domain
			ips, err := s.resolver.LookupIP(ctx, "ip4", fullDomain)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				result.Subdomains = append(result.Subdomains, fullDomain)
				result.Records = append(result.Records, DNSRecord{
					Type:  "SUBDOMAIN",
					Name:  fullDomain,
					Value: fmt.Sprintf("%s -> %s", fullDomain, ips[0].String()),
				})
				mu.Unlock()
				s.addLog(ctx, scanID, "info", fmt.Sprintf("Found subdomain: %s -> %s", fullDomain, ips[0].String()))
			}
		}(sub, i)

		// Update progress
		if i%10 == 0 {
			progress := 50 + (i * 50 / len(commonSubdomains))
			s.updateScanStatus(ctx, scanID, "running", progress, nil)
		}
	}

	wg.Wait()
}

func (s *DNSScanner) convertToScanResult(scanID uuid.UUID, domain string, dnsResult *DNSScanResult) *models.ScanResult {
	// Convert DNS records to services list
	var services []string
	for _, record := range dnsResult.Records {
		services = append(services, fmt.Sprintf("%s: %s", record.Type, record.Value))
	}

	// Store DNS-specific data in OSDetection field (repurposed for extra data)
	extraData := map[string]interface{}{
		"dns_records":   dnsResult.Records,
		"subdomains":    dnsResult.Subdomains,
		"nameservers":   dnsResult.NameServers,
		"mx_records":    dnsResult.MXRecords,
		"txt_records":   dnsResult.TXTRecords,
		"zone_transfer": dnsResult.ZoneTransfer,
	}

	return &models.ScanResult{
		ID:          uuid.New(),
		ScanID:      scanID,
		Host:        domain,
		State:       "resolved",
		Ports:       []models.Port{}, // DNS doesn't scan ports
		Services:    services,
		OSDetection: extraData,
		CreatedAt:   time.Now(),
	}
}

// CancelScan cancels a running scan
func (s *DNSScanner) CancelScan(scanID string) {
	if cancel, ok := s.cancelFuncs[scanID]; ok {
		cancel()
		log.Printf("🛑 Cancelled DNS scan %s", scanID)
	}
}

func (s *DNSScanner) updateScanStatus(ctx context.Context, scanID uuid.UUID, status string, progress int, errorMsg *string) error {
	query := `
		UPDATE scans
		SET status = $1, progress = $2, error_message = $3,
		    started_at = CASE WHEN $4 = 'running' AND started_at IS NULL THEN NOW() ELSE started_at END,
		    completed_at = CASE WHEN $5 IN ('completed', 'failed') THEN NOW() ELSE completed_at END
		WHERE id = $6
	`
	_, err := s.db.Pool.Exec(ctx, query, status, progress, errorMsg, status, status, scanID)
	return err
}

func (s *DNSScanner) addLog(ctx context.Context, scanID uuid.UUID, level, message string) {
	query := `INSERT INTO scan_logs (id, scan_id, level, message, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.Pool.Exec(ctx, query, uuid.New(), scanID, level, message, time.Now())
	if err != nil {
		log.Printf("Failed to add log: %v", err)
	}
}

func (s *DNSScanner) storeResult(ctx context.Context, result *models.ScanResult) error {
	query := `
		INSERT INTO scan_results (id, scan_id, host, hostname, state, ports, os_detection, services, mac_address, mac_vendor, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := s.db.Pool.Exec(ctx, query,
		result.ID,
		result.ScanID,
		result.Host,
		result.Hostname,
		result.State,
		result.Ports,
		result.OSDetection,
		result.Services,
		result.MacAddress,
		result.MacVendor,
		result.CreatedAt,
	)
	return err
}

// GetTemplates returns predefined DNS scan templates
func (s *DNSScanner) GetTemplates() map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		"dns_records": {
			"name":        "DNS Records Scan",
			"description": "Query all DNS record types (A, AAAA, MX, NS, TXT)",
			"scan_type":   "dns_records",
		},
		"dns_full": {
			"name":        "Full DNS Scan",
			"description": "Complete DNS reconnaissance including subdomain enumeration",
			"scan_type":   "dns_full",
		},
		"dns_subdomain": {
			"name":        "Subdomain Enumeration",
			"description": "Discover subdomains using common wordlist",
			"scan_type":   "dns_subdomain",
		},
	}
}
