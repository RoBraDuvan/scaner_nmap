package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nmap-scanner/backend-go/internal/database"
	"github.com/nmap-scanner/backend-go/internal/models"
)

type MasscanScanner struct {
	db          *database.Database
	masscanPath string
	cancelFuncs map[string]context.CancelFunc
}

// MasscanResult represents the JSON output from masscan
type MasscanResult struct {
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
	Ports     []struct {
		Port     int    `json:"port"`
		Protocol string `json:"proto"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
		TTL      int    `json:"ttl"`
	} `json:"ports"`
}

func NewMasscanScanner(db *database.Database, masscanPath string) *MasscanScanner {
	if masscanPath == "" {
		masscanPath = "masscan"
	}
	return &MasscanScanner{
		db:          db,
		masscanPath: masscanPath,
		cancelFuncs: make(map[string]context.CancelFunc),
	}
}

// ExecuteScan runs a masscan scan and stores results
func (s *MasscanScanner) ExecuteScan(ctx context.Context, scanID uuid.UUID, target string, ports string, rate int) error {
	log.Printf("🚀 Starting Masscan scan %s on target: %s ports: %s rate: %d", scanID, target, ports, rate)

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
	s.addLog(ctx, scanID, "info", fmt.Sprintf("Starting Masscan on target: %s", target))

	// Default values
	if ports == "" {
		ports = "1-65535"
	}
	if rate == 0 {
		rate = 10000 // Default rate: 10k packets/sec
	}

	// Build command arguments
	args := []string{
		target,
		"-p", ports,
		"--rate", strconv.Itoa(rate),
		"-oJ", "-", // JSON output to stdout
		"--open",   // Only show open ports
	}

	log.Printf("Running: %s %s", s.masscanPath, strings.Join(args, " "))
	s.addLog(ctx, scanID, "info", fmt.Sprintf("Command: masscan %s", strings.Join(args, " ")))

	cmd := exec.CommandContext(ctx, s.masscanPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		errMsg := err.Error()
		s.updateScanStatus(ctx, scanID, "failed", 0, &errMsg)
		s.addLog(ctx, scanID, "error", fmt.Sprintf("Failed to start masscan: %s", errMsg))
		return fmt.Errorf("failed to start masscan: %w", err)
	}

	// Read stderr for progress/errors
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "rate:") || strings.Contains(line, "Scanning") {
				s.addLog(ctx, scanID, "info", line)
			}
		}
	}()

	// Parse JSON output
	results := make(map[string]*models.ScanResult)
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line == "[" || line == "]" {
			continue
		}

		// Remove trailing comma if present
		line = strings.TrimSuffix(strings.TrimSpace(line), ",")
		if line == "" {
			continue
		}

		var masscanResult MasscanResult
		if err := json.Unmarshal([]byte(line), &masscanResult); err != nil {
			log.Printf("Failed to parse masscan output: %v - line: %s", err, line)
			continue
		}

		// Group ports by IP
		if _, exists := results[masscanResult.IP]; !exists {
			results[masscanResult.IP] = &models.ScanResult{
				ID:        uuid.New(),
				ScanID:    scanID,
				Host:      masscanResult.IP,
				State:     "up",
				Ports:     []models.Port{},
				Services:  []string{},
				CreatedAt: time.Now(),
			}
		}

		for _, port := range masscanResult.Ports {
			results[masscanResult.IP].Ports = append(results[masscanResult.IP].Ports, models.Port{
				Port:     port.Port,
				Protocol: port.Protocol,
				State:    port.Status,
				Service:  "unknown", // Masscan doesn't do service detection
			})
			results[masscanResult.IP].Services = append(results[masscanResult.IP].Services,
				fmt.Sprintf("%d/%s", port.Port, port.Protocol))
		}
	}

	// Check if context was cancelled
	if ctx.Err() == context.Canceled {
		s.addLog(context.Background(), scanID, "info", "Scan was cancelled by user")
		return nil
	}

	if err := cmd.Wait(); err != nil {
		// Check if it was cancelled
		if ctx.Err() == context.Canceled {
			s.addLog(context.Background(), scanID, "info", "Scan was cancelled by user")
			return nil
		}
		errMsg := err.Error()
		s.updateScanStatus(ctx, scanID, "failed", 0, &errMsg)
		s.addLog(ctx, scanID, "error", fmt.Sprintf("Masscan failed: %s", errMsg))
		return fmt.Errorf("masscan failed: %w", err)
	}

	// Store results
	for _, result := range results {
		if err := s.storeResult(ctx, result); err != nil {
			log.Printf("Failed to store result: %v", err)
		}
	}

	// Update scan status to completed
	if err := s.updateScanStatus(ctx, scanID, "completed", 100, nil); err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	s.addLog(ctx, scanID, "success", fmt.Sprintf("Masscan completed. Found %d hosts with open ports", len(results)))
	log.Printf("✅ Masscan %s completed. Found %d hosts", scanID, len(results))

	return nil
}

// CancelScan cancels a running scan
func (s *MasscanScanner) CancelScan(scanID string) {
	if cancel, ok := s.cancelFuncs[scanID]; ok {
		cancel()
		log.Printf("🛑 Cancelled Masscan scan %s", scanID)
	}
}

func (s *MasscanScanner) updateScanStatus(ctx context.Context, scanID uuid.UUID, status string, progress int, errorMsg *string) error {
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

func (s *MasscanScanner) addLog(ctx context.Context, scanID uuid.UUID, level, message string) {
	query := `INSERT INTO scan_logs (id, scan_id, level, message, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.Pool.Exec(ctx, query, uuid.New(), scanID, level, message, time.Now())
	if err != nil {
		log.Printf("Failed to add log: %v", err)
	}
}

func (s *MasscanScanner) storeResult(ctx context.Context, result *models.ScanResult) error {
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

// GetTemplates returns predefined masscan templates
func (s *MasscanScanner) GetTemplates() map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		"masscan_quick": {
			"name":        "Masscan Quick Scan",
			"description": "Fast scan of common ports (top 100)",
			"ports":       "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
			"rate":        10000,
		},
		"masscan_full": {
			"name":        "Masscan Full Port Scan",
			"description": "Scan all 65535 ports at high speed",
			"ports":       "1-65535",
			"rate":        100000,
		},
		"masscan_web": {
			"name":        "Masscan Web Ports",
			"description": "Scan common web server ports",
			"ports":       "80,443,8080,8443,8000,8888,9000,9090,3000,5000",
			"rate":        10000,
		},
		"masscan_database": {
			"name":        "Masscan Database Ports",
			"description": "Scan common database ports",
			"ports":       "1433,1521,3306,5432,6379,27017,9200,5984",
			"rate":        10000,
		},
	}
}
