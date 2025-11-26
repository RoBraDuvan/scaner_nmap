package scanner

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/google/uuid"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/models"
)

type Scanner struct {
	db            *database.Database
	useSystemNmap bool
	nmapPath      string
	cancelFuncs   map[string]context.CancelFunc
}

func NewScanner(db *database.Database, useSystemNmap bool, nmapPath string) *Scanner {
	return &Scanner{
		db:            db,
		useSystemNmap: useSystemNmap,
		nmapPath:      nmapPath,
		cancelFuncs:   make(map[string]context.CancelFunc),
	}
}

// ExecuteScan runs an nmap scan and stores results
func (s *Scanner) ExecuteScan(ctx context.Context, scanID uuid.UUID, target string, arguments string) error {
	log.Printf("🔍 Starting scan %s on target: %s with args: %s", scanID, target, arguments)

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

	// Add log entry
	s.addLog(ctx, scanID, "info", fmt.Sprintf("Starting scan on target: %s", target))

	var results []models.ScanResult
	var scanErr error

	if s.useSystemNmap {
		results, scanErr = s.runSystemNmap(ctx, scanID, target, arguments)
	} else {
		results, scanErr = s.runGonmap(ctx, scanID, target, arguments)
	}

	// Check if context was cancelled
	if ctx.Err() == context.Canceled {
		s.addLog(context.Background(), scanID, "info", "Scan was cancelled by user")
		return nil
	}

	if scanErr != nil {
		errMsg := scanErr.Error()
		s.updateScanStatus(ctx, scanID, "failed", 0, &errMsg)
		s.addLog(ctx, scanID, "error", fmt.Sprintf("Scan failed: %s", errMsg))
		return scanErr
	}

	// Store results in database
	if err := s.storeResults(ctx, scanID, results); err != nil {
		log.Printf("Failed to store results: %v", err)
	}

	// Update scan status to completed
	if err := s.updateScanStatus(ctx, scanID, "completed", 100, nil); err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	s.addLog(ctx, scanID, "success", "Scan completed successfully")
	log.Printf("✅ Scan %s completed successfully. Found %d hosts", scanID, len(results))

	return nil
}

// CancelScan cancels a running scan by its ID
func (s *Scanner) CancelScan(scanID string) {
	if cancel, ok := s.cancelFuncs[scanID]; ok {
		cancel()
		log.Printf("🛑 Cancelled scan %s", scanID)
	}
}

// runGonmap executes scan using gonmap library
func (s *Scanner) runGonmap(ctx context.Context, scanID uuid.UUID, target string, arguments string) ([]models.ScanResult, error) {
	log.Println("Using gonmap library for scan")

	// Parse arguments
	args := strings.Fields(arguments)
	args = append(args, target)

	// Create scanner
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithCustomArguments(args...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create nmap scanner: %w", err)
	}

	// Run scan
	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("nmap scan failed: %w", err)
	}

	if warnings != nil {
		log.Printf("⚠️  Nmap warnings: %v", warnings)
	}

	// Parse results
	return s.parseGonmapResults(result), nil
}

// runSystemNmap executes system nmap command
func (s *Scanner) runSystemNmap(ctx context.Context, scanID uuid.UUID, target string, arguments string) ([]models.ScanResult, error) {
	log.Printf("Using system nmap at: %s", s.nmapPath)

	// Build command
	args := strings.Fields(arguments)
	args = append(args, "-oX", "-") // Output XML to stdout
	args = append(args, target)

	cmd := exec.CommandContext(ctx, s.nmapPath, args...)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("system nmap failed: %w", err)
	}

	// Parse XML output using gonmap
	var result nmap.Run
	if err := nmap.Parse(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse nmap output: %w", err)
	}

	return s.parseGonmapResults(&result), nil
}

// parseGonmapResults converts gonmap results to our models
func (s *Scanner) parseGonmapResults(result *nmap.Run) []models.ScanResult {
	var results []models.ScanResult

	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}

		scanResult := models.ScanResult{
			ID:        uuid.New(),
			Host:      host.Addresses[0].Addr,
			State:     string(host.Status.State),
			Ports:     []models.Port{},
			Services:  []string{},
			CreatedAt: time.Now(),
		}

		// Hostname
		if len(host.Hostnames) > 0 {
			scanResult.Hostname = &host.Hostnames[0].Name
		}

		// MAC address and vendor
		for _, addr := range host.Addresses {
			if addr.AddrType == "mac" {
				scanResult.MacAddress = &addr.Addr
				if addr.Vendor != "" {
					scanResult.MacVendor = &addr.Vendor
				}
			}
		}

		// Ports
		for _, port := range host.Ports {
			portInfo := models.Port{
				Port:     int(port.ID),
				Protocol: port.Protocol,
				State:    string(port.State.State),
				Service:  port.Service.Name,
			}

			if port.Service.Product != "" {
				portInfo.Product = port.Service.Product
			}
			if port.Service.Version != "" {
				portInfo.Version = port.Service.Version
			}
			if port.Service.ExtraInfo != "" {
				portInfo.ExtraInfo = port.Service.ExtraInfo
			}

			scanResult.Ports = append(scanResult.Ports, portInfo)
			scanResult.Services = append(scanResult.Services,
				fmt.Sprintf("%d/%s - %s", port.ID, port.Protocol, port.Service.Name))
		}

		results = append(results, scanResult)
	}

	return results
}

// updateScanStatus updates scan status in database
func (s *Scanner) updateScanStatus(ctx context.Context, scanID uuid.UUID, status string, progress int, errorMsg *string) error {
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

// addLog adds a log entry for the scan
func (s *Scanner) addLog(ctx context.Context, scanID uuid.UUID, level, message string) {
	query := `INSERT INTO scan_logs (id, scan_id, level, message, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.Pool.Exec(ctx, query, uuid.New(), scanID, level, message, time.Now())
	if err != nil {
		log.Printf("Failed to add log: %v", err)
	}
}

// storeResults stores scan results in database
func (s *Scanner) storeResults(ctx context.Context, scanID uuid.UUID, results []models.ScanResult) error {
	for _, result := range results {
		result.ScanID = scanID
		result.ID = uuid.New()
		result.CreatedAt = time.Now()

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

		if err != nil {
			return fmt.Errorf("failed to insert scan result: %w", err)
		}
	}

	return nil
}

// GetScanTemplates returns predefined scan templates
func (s *Scanner) GetScanTemplates() map[string]map[string]string {
	return map[string]map[string]string{
		"quick": {
			"name":        "Quick Scan",
			"arguments":   "-F -T4",
			"description": "Fast scan of the most common 100 ports",
		},
		"full": {
			"name":        "Full Port Scan",
			"arguments":   "-p- -T4",
			"description": "Comprehensive scan of all 65535 ports",
		},
		"service": {
			"name":        "Service Version Detection",
			"arguments":   "-sV -O -T4",
			"description": "Detect service versions and OS",
		},
		"web_server": {
			"name":        "Web Server Scan",
			"arguments":   "-p 80,443,8080,8443,3000,5000,8000 -sV -T4",
			"description": "Scan web servers with service detection",
		},
	}
}
