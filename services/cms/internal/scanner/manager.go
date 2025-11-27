package scanner

import (
	"context"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/security-scanner/cms-service/internal/database"
	"github.com/security-scanner/cms-service/internal/models"
)

// ScanManager coordinates CMS scanning operations
type ScanManager struct {
	db             *database.Database
	whatweb        *WhatWebScanner
	cmseek         *CMSeeKScanner
	wpscan         *WPScanScanner
	joomscan       *JoomScanScanner
	droopescan     *DroopescanScanner
	activeScans    map[uuid.UUID]context.CancelFunc
	activeScansMux sync.Mutex
}

// NewScanManager creates a new scan manager
func NewScanManager(db *database.Database, whatwebPath, cmseekPath, wpscanPath, joomscanPath, droopescanPath string) *ScanManager {
	return &ScanManager{
		db:          db,
		whatweb:     NewWhatWebScanner(db, whatwebPath),
		cmseek:      NewCMSeeKScanner(db, cmseekPath),
		wpscan:      NewWPScanScanner(db, wpscanPath),
		joomscan:    NewJoomScanScanner(db, joomscanPath),
		droopescan:  NewDroopescanScanner(db, droopescanPath),
		activeScans: make(map[uuid.UUID]context.CancelFunc),
	}
}

// StartScan initiates a new CMS scan
func (m *ScanManager) StartScan(scan *models.CMSScan) {
	ctx, cancel := context.WithCancel(context.Background())

	m.activeScansMux.Lock()
	m.activeScans[scan.ID] = cancel
	m.activeScansMux.Unlock()

	go m.runScan(ctx, scan)
}

func (m *ScanManager) runScan(ctx context.Context, scan *models.CMSScan) {
	defer func() {
		m.activeScansMux.Lock()
		delete(m.activeScans, scan.ID)
		m.activeScansMux.Unlock()
	}()

	var err error

	switch scan.ScanType {
	case "whatweb":
		err = m.whatweb.Scan(ctx, scan, scan.Config)
	case "cmseek":
		err = m.cmseek.Scan(ctx, scan, scan.Config)
	case "wpscan":
		err = m.wpscan.Scan(ctx, scan, scan.Config)
	case "joomscan":
		err = m.joomscan.Scan(ctx, scan, scan.Config)
	case "droopescan":
		err = m.droopescan.Scan(ctx, scan, scan.Config)
	case "drupal":
		// Shortcut for Drupal-specific scan
		if scan.Config == nil {
			scan.Config = &models.CMSScanConfig{}
		}
		scan.Config.DroopescanCMS = "drupal"
		err = m.droopescan.Scan(ctx, scan, scan.Config)
	case "joomla":
		// Use JoomScan for Joomla-specific scans
		err = m.joomscan.Scan(ctx, scan, scan.Config)
	case "full":
		err = m.runFullScan(ctx, scan)
	default:
		m.db.AddLog(scan.ID, "error", "Unknown scan type: "+scan.ScanType)
		m.db.UpdateScanStatus(scan.ID, "failed", 0, nil)
		return
	}

	// Check if cancelled
	select {
	case <-ctx.Done():
		m.db.AddLog(scan.ID, "info", "Scan cancelled")
		m.db.UpdateScanStatus(scan.ID, "cancelled", scan.Progress, nil)
		return
	default:
	}

	if err != nil {
		m.db.AddLog(scan.ID, "error", "Scan failed: "+err.Error())
		m.db.UpdateScanStatus(scan.ID, "failed", 100, nil)
		return
	}

	m.db.AddLog(scan.ID, "info", "Scan completed successfully")
	m.db.UpdateScanStatus(scan.ID, "completed", 100, nil)
}

func (m *ScanManager) runFullScan(ctx context.Context, scan *models.CMSScan) error {
	m.db.AddLog(scan.ID, "info", "Starting comprehensive CMS scan")

	// Phase 1: WhatWeb for general technology detection (0-20%)
	m.db.AddLog(scan.ID, "info", "Phase 1: Running WhatWeb for technology detection...")
	m.db.UpdateScanStatus(scan.ID, "running", 5, nil)

	whatwebErr := m.whatweb.Scan(ctx, scan, scan.Config)
	if whatwebErr != nil {
		m.db.AddLog(scan.ID, "warning", "WhatWeb phase completed with issues: "+whatwebErr.Error())
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.db.UpdateScanStatus(scan.ID, "running", 20, nil)

	// Phase 2: CMSeeK for CMS-specific detection (20-40%)
	m.db.AddLog(scan.ID, "info", "Phase 2: Running CMSeeK for CMS detection...")
	m.db.UpdateScanStatus(scan.ID, "running", 25, nil)

	cmseekErr := m.cmseek.Scan(ctx, scan, scan.Config)
	if cmseekErr != nil {
		m.db.AddLog(scan.ID, "warning", "CMSeeK phase completed with issues: "+cmseekErr.Error())
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.db.UpdateScanStatus(scan.ID, "running", 40, nil)

	// Phase 3: Droopescan for Drupal/Moodle/SilverStripe (40-55%)
	m.db.AddLog(scan.ID, "info", "Phase 3: Running Droopescan for multi-CMS detection...")
	m.db.UpdateScanStatus(scan.ID, "running", 45, nil)

	droopescanErr := m.droopescan.Scan(ctx, scan, scan.Config)
	if droopescanErr != nil {
		m.db.AddLog(scan.ID, "warning", "Droopescan phase completed with issues: "+droopescanErr.Error())
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.db.UpdateScanStatus(scan.ID, "running", 55, nil)

	// Get detected CMS to determine which specialized scanners to run
	results, _ := m.db.GetCMSResults(scan.ID)

	detectedCMS := make(map[string]bool)
	for _, result := range results {
		cmsLower := strings.ToLower(result.CMSName)
		detectedCMS[cmsLower] = true
	}

	// Phase 4: WordPress-specific scan (55-70%)
	if detectedCMS["wordpress"] {
		m.db.AddLog(scan.ID, "info", "Phase 4: WordPress detected, running WPScan...")
		m.db.UpdateScanStatus(scan.ID, "running", 60, nil)

		wpscanErr := m.wpscan.Scan(ctx, scan, scan.Config)
		if wpscanErr != nil {
			m.db.AddLog(scan.ID, "warning", "WPScan phase completed with issues: "+wpscanErr.Error())
		}
	} else {
		m.db.AddLog(scan.ID, "info", "Phase 4: WordPress not detected, skipping WPScan")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.db.UpdateScanStatus(scan.ID, "running", 70, nil)

	// Phase 5: Joomla-specific scan (70-85%)
	if detectedCMS["joomla"] {
		m.db.AddLog(scan.ID, "info", "Phase 5: Joomla detected, running JoomScan...")
		m.db.UpdateScanStatus(scan.ID, "running", 75, nil)

		joomscanErr := m.joomscan.Scan(ctx, scan, scan.Config)
		if joomscanErr != nil {
			m.db.AddLog(scan.ID, "warning", "JoomScan phase completed with issues: "+joomscanErr.Error())
		}
	} else {
		m.db.AddLog(scan.ID, "info", "Phase 5: Joomla not detected, skipping JoomScan")
	}

	m.db.UpdateScanStatus(scan.ID, "running", 85, nil)

	// Generate summary
	m.generateSummary(scan.ID)

	m.db.UpdateScanStatus(scan.ID, "running", 95, nil)

	return nil
}

func (m *ScanManager) generateSummary(scanID uuid.UUID) {
	// Get all results
	cmsResults, _ := m.db.GetCMSResults(scanID)
	techs, _ := m.db.GetTechnologies(scanID)
	wpResults, _ := m.db.GetWPScanResults(scanID)

	// Count unique CMS
	cmsSet := make(map[string]bool)
	for _, cms := range cmsResults {
		cmsSet[cms.CMSName] = true
	}

	// Count vulnerabilities
	vulnCount := 0
	for _, wp := range wpResults {
		vulnCount += len(wp.Vulnerabilities)
	}

	// Categorize technologies
	techCategories := make(map[string]int)
	for _, tech := range techs {
		techCategories[tech.Category]++
	}

	// Log summary
	m.db.AddLog(scanID, "info", "")
	m.db.AddLog(scanID, "info", "╔════════════════════════════════════════╗")
	m.db.AddLog(scanID, "info", "║           SCAN SUMMARY                 ║")
	m.db.AddLog(scanID, "info", "╠════════════════════════════════════════╣")
	m.db.AddLog(scanID, "info", "║ CMS Detected: "+joinKeys(cmsSet))
	m.db.AddLog(scanID, "info", "║ Total Technologies: "+string(rune('0'+len(techs))))

	for cat, count := range techCategories {
		m.db.AddLog(scanID, "info", "║   - "+cat+": "+string(rune('0'+count)))
	}

	if vulnCount > 0 {
		m.db.AddLog(scanID, "warning", "║ Vulnerabilities Found: "+string(rune('0'+vulnCount)))
	}
	m.db.AddLog(scanID, "info", "╚════════════════════════════════════════╝")
}

func joinKeys(m map[string]bool) string {
	if len(m) == 0 {
		return "None"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	result := ""
	for i, k := range keys {
		if i > 0 {
			result += ", "
		}
		result += k
	}
	return result
}

// CancelScan cancels a running scan
func (m *ScanManager) CancelScan(scanID uuid.UUID) bool {
	m.activeScansMux.Lock()
	defer m.activeScansMux.Unlock()

	if cancel, ok := m.activeScans[scanID]; ok {
		cancel()
		return true
	}
	return false
}

// IsScanRunning checks if a scan is currently running
func (m *ScanManager) IsScanRunning(scanID uuid.UUID) bool {
	m.activeScansMux.Lock()
	defer m.activeScansMux.Unlock()

	_, ok := m.activeScans[scanID]
	return ok
}

// GetAvailableTools returns a list of available scanning tools
func (m *ScanManager) GetAvailableTools() map[string]bool {
	return map[string]bool{
		"whatweb":    m.whatweb.IsAvailable(),
		"cmseek":     m.cmseek.IsAvailable(),
		"wpscan":     m.wpscan.IsAvailable(),
		"joomscan":   m.joomscan.IsAvailable(),
		"droopescan": m.droopescan.IsAvailable(),
	}
}
