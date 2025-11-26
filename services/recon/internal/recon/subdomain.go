package recon

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/recon-service/internal/database"
	"github.com/security-scanner/recon-service/internal/models"
)

type SubdomainScanner struct {
	db            *database.Database
	subfinderPath string
	amassPath     string
}

func NewSubdomainScanner(db *database.Database, subfinderPath, amassPath string) *SubdomainScanner {
	return &SubdomainScanner{
		db:            db,
		subfinderPath: subfinderPath,
		amassPath:     amassPath,
	}
}

func (s *SubdomainScanner) Scan(ctx context.Context, scan *models.ReconScan) error {
	s.db.UpdateScanStatus(scan.ID, "running", 0, nil)
	s.db.AddLog(scan.ID, "info", "Starting subdomain enumeration for "+scan.Target)

	subdomains := make(map[string]string) // subdomain -> source

	// Run Subfinder
	s.db.AddLog(scan.ID, "info", "Running Subfinder...")
	s.db.UpdateScanStatus(scan.ID, "running", 20, nil)
	subfinderResults, err := s.runSubfinder(ctx, scan.Target)
	if err != nil {
		s.db.AddLog(scan.ID, "warning", "Subfinder error: "+err.Error())
	} else {
		for _, sub := range subfinderResults {
			if _, exists := subdomains[sub]; !exists {
				subdomains[sub] = "subfinder"
			}
		}
		s.db.AddLog(scan.ID, "info", fmt.Sprintf("Subfinder found %d subdomains", len(subfinderResults)))
	}

	// Run Amass (passive mode for speed) with timeout
	s.db.AddLog(scan.ID, "info", "Running Amass (passive mode, 2min timeout)...")
	s.db.UpdateScanStatus(scan.ID, "running", 50, nil)
	amassCtx, amassCancel := context.WithTimeout(ctx, 2*time.Minute)
	amassResults, err := s.runAmass(amassCtx, scan.Target)
	amassCancel()
	if err != nil {
		s.db.AddLog(scan.ID, "warning", "Amass error: "+err.Error())
	} else {
		for _, sub := range amassResults {
			if _, exists := subdomains[sub]; !exists {
				subdomains[sub] = "amass"
			}
		}
		s.db.AddLog(scan.ID, "info", fmt.Sprintf("Amass found %d additional subdomains", len(amassResults)))
	}

	// Resolve IPs and save results
	s.db.AddLog(scan.ID, "info", "Resolving IP addresses...")
	s.db.UpdateScanStatus(scan.ID, "running", 70, nil)

	count := 0
	total := len(subdomains)
	for subdomain, source := range subdomains {
		// Resolve IP addresses
		var ipAddresses []string
		ips, err := net.LookupIP(subdomain)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				ipAddresses = append(ipAddresses, ip.String())
			}
		}

		result := &models.SubdomainResult{
			ID:          uuid.New(),
			ScanID:      scan.ID,
			Subdomain:   subdomain,
			IPAddresses: ipAddresses,
			Source:      source,
			IsAlive:     len(ipAddresses) > 0,
			CreatedAt:   time.Now(),
		}
		if err := s.db.SaveSubdomainResult(result); err != nil {
			log.Printf("Error saving subdomain %s: %v", subdomain, err)
		}
		count++

		// Update progress
		progress := 70 + (count * 30 / total)
		s.db.UpdateScanStatus(scan.ID, "running", progress, nil)
	}

	s.db.AddLog(scan.ID, "info", fmt.Sprintf("Found %d unique subdomains", count))
	s.db.UpdateScanStatus(scan.ID, "completed", 100, nil)
	s.db.AddLog(scan.ID, "info", "Subdomain enumeration completed")

	return nil
}

func (s *SubdomainScanner) runSubfinder(ctx context.Context, domain string) ([]string, error) {
	cmd := exec.CommandContext(ctx, s.subfinderPath, "-d", domain, "-silent", "-all")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var subdomains []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.Contains(line, domain) {
			subdomains = append(subdomains, line)
		}
	}
	return subdomains, nil
}

func (s *SubdomainScanner) runAmass(ctx context.Context, domain string) ([]string, error) {
	// Use passive mode for faster results
	cmd := exec.CommandContext(ctx, s.amassPath, "enum", "-passive", "-d", domain)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var subdomains []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.Contains(line, domain) {
			subdomains = append(subdomains, line)
		}
	}
	return subdomains, nil
}

