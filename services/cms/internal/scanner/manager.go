package scanner

import (
	"context"
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
	activeScans    map[uuid.UUID]context.CancelFunc
	activeScansMux sync.Mutex
}

// NewScanManager creates a new scan manager
func NewScanManager(db *database.Database, whatwebPath, cmseekPath, wpscanPath string) *ScanManager {
	return &ScanManager{
		db:          db,
		whatweb:     NewWhatWebScanner(db, whatwebPath),
		cmseek:      NewCMSeeKScanner(db, cmseekPath),
		wpscan:      NewWPScanScanner(db, wpscanPath),
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
	m.db.AddLog(scan.ID, "info", "Starting full CMS scan")

	// Phase 1: WhatWeb for general technology detection (0-30%)
	m.db.AddLog(scan.ID, "info", "Phase 1: Running WhatWeb...")
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

	m.db.UpdateScanStatus(scan.ID, "running", 30, nil)

	// Phase 2: CMSeeK for CMS-specific detection (30-60%)
	m.db.AddLog(scan.ID, "info", "Phase 2: Running CMSeeK...")
	m.db.UpdateScanStatus(scan.ID, "running", 35, nil)

	cmseekErr := m.cmseek.Scan(ctx, scan, scan.Config)
	if cmseekErr != nil {
		m.db.AddLog(scan.ID, "warning", "CMSeeK phase completed with issues: "+cmseekErr.Error())
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.db.UpdateScanStatus(scan.ID, "running", 60, nil)

	// Phase 3: WPScan if WordPress detected (60-90%)
	// Check if WordPress was detected
	results, _ := m.db.GetCMSResults(scan.ID)
	isWordPress := false
	for _, result := range results {
		if result.CMSName == "WordPress" || result.CMSName == "wordpress" {
			isWordPress = true
			break
		}
	}

	if isWordPress {
		m.db.AddLog(scan.ID, "info", "Phase 3: WordPress detected, running WPScan...")
		m.db.UpdateScanStatus(scan.ID, "running", 65, nil)

		wpscanErr := m.wpscan.Scan(ctx, scan, scan.Config)
		if wpscanErr != nil {
			m.db.AddLog(scan.ID, "warning", "WPScan phase completed with issues: "+wpscanErr.Error())
		}
	} else {
		m.db.AddLog(scan.ID, "info", "Phase 3: WordPress not detected, skipping WPScan")
	}

	m.db.UpdateScanStatus(scan.ID, "running", 90, nil)

	// Generate summary
	m.generateSummary(scan.ID)

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

	// Log summary
	m.db.AddLog(scanID, "info", "=== SCAN SUMMARY ===")
	m.db.AddLog(scanID, "info", "CMS Detected: "+joinKeys(cmsSet))
	m.db.AddLog(scanID, "info", "Technologies found: "+string(rune(len(techs))))
	m.db.AddLog(scanID, "info", "Vulnerabilities: "+string(rune(vulnCount)))
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
