package scanner

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"github.com/security-scanner/cloud-service/internal/database"
	"github.com/security-scanner/cloud-service/internal/models"
)

// ScanManager coordinates cloud security scanning operations
type ScanManager struct {
	db             *database.Database
	trivy          *TrivyScanner
	prowler        *ProwlerScanner
	scoutsuite     *ScoutSuiteScanner
	activeScans    map[uuid.UUID]context.CancelFunc
	activeScansMux sync.Mutex
}

// NewScanManager creates a new scan manager
func NewScanManager(db *database.Database, trivyPath, prowlerPath, scoutsuitePath string) *ScanManager {
	return &ScanManager{
		db:          db,
		trivy:       NewTrivyScanner(db, trivyPath),
		prowler:     NewProwlerScanner(db, prowlerPath),
		scoutsuite:  NewScoutSuiteScanner(db, scoutsuitePath),
		activeScans: make(map[uuid.UUID]context.CancelFunc),
	}
}

// StartScan initiates a new cloud security scan
func (m *ScanManager) StartScan(scan *models.CloudScan) {
	ctx, cancel := context.WithCancel(context.Background())

	m.activeScansMux.Lock()
	m.activeScans[scan.ID] = cancel
	m.activeScansMux.Unlock()

	go m.runScan(ctx, scan)
}

func (m *ScanManager) runScan(ctx context.Context, scan *models.CloudScan) {
	defer func() {
		m.activeScansMux.Lock()
		delete(m.activeScans, scan.ID)
		m.activeScansMux.Unlock()
	}()

	var err error

	switch scan.ScanType {
	case "trivy":
		err = m.trivy.Scan(ctx, scan, scan.Config)
	case "prowler":
		err = m.prowler.Scan(ctx, scan, scan.Config)
	case "scoutsuite":
		err = m.scoutsuite.Scan(ctx, scan, scan.Config)
	case "image":
		// Shortcut for container image scanning
		err = m.trivy.ScanImage(ctx, scan, scan.Target)
	case "config":
		// Shortcut for IaC scanning
		err = m.trivy.ScanConfig(ctx, scan, scan.Target)
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

	// Calculate summary
	summary := m.db.CalculateSummary(scan.ID)

	m.db.AddLog(scan.ID, "info", "Scan completed successfully")
	m.db.UpdateScanStatus(scan.ID, "completed", 100, summary)
}

func (m *ScanManager) runFullScan(ctx context.Context, scan *models.CloudScan) error {
	m.db.AddLog(scan.ID, "info", "Starting comprehensive cloud security scan")

	// Phase 1: ScoutSuite for configuration audit (0-40%)
	if m.scoutsuite.IsAvailable() && (scan.Provider == "aws" || scan.Provider == "azure" || scan.Provider == "gcp") {
		m.db.AddLog(scan.ID, "info", "Phase 1: Running ScoutSuite configuration audit...")
		m.db.UpdateScanStatus(scan.ID, "running", 5, nil)

		scoutErr := m.scoutsuite.Scan(ctx, scan, scan.Config)
		if scoutErr != nil {
			m.db.AddLog(scan.ID, "warning", "ScoutSuite phase completed with issues: "+scoutErr.Error())
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	} else {
		m.db.AddLog(scan.ID, "info", "Phase 1: Skipping ScoutSuite (not available or unsupported provider)")
	}

	m.db.UpdateScanStatus(scan.ID, "running", 40, nil)

	// Phase 2: Prowler for compliance checks (40-70%)
	if m.prowler.IsAvailable() && (scan.Provider == "aws" || scan.Provider == "azure" || scan.Provider == "gcp") {
		m.db.AddLog(scan.ID, "info", "Phase 2: Running Prowler compliance checks...")
		m.db.UpdateScanStatus(scan.ID, "running", 45, nil)

		prowlerErr := m.prowler.Scan(ctx, scan, scan.Config)
		if prowlerErr != nil {
			m.db.AddLog(scan.ID, "warning", "Prowler phase completed with issues: "+prowlerErr.Error())
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	} else {
		m.db.AddLog(scan.ID, "info", "Phase 2: Skipping Prowler (not available or unsupported provider)")
	}

	m.db.UpdateScanStatus(scan.ID, "running", 70, nil)

	// Phase 3: Trivy for vulnerability scanning (70-95%)
	if m.trivy.IsAvailable() && scan.Target != "" {
		m.db.AddLog(scan.ID, "info", "Phase 3: Running Trivy vulnerability scan...")
		m.db.UpdateScanStatus(scan.ID, "running", 75, nil)

		trivyErr := m.trivy.Scan(ctx, scan, scan.Config)
		if trivyErr != nil {
			m.db.AddLog(scan.ID, "warning", "Trivy phase completed with issues: "+trivyErr.Error())
		}
	} else {
		m.db.AddLog(scan.ID, "info", "Phase 3: Skipping Trivy (no target specified or not available)")
	}

	m.db.UpdateScanStatus(scan.ID, "running", 95, nil)

	// Generate summary
	m.generateSummary(scan.ID)

	return nil
}

func (m *ScanManager) generateSummary(scanID uuid.UUID) {
	summary := m.db.CalculateSummary(scanID)

	m.db.AddLog(scanID, "info", "")
	m.db.AddLog(scanID, "info", "╔════════════════════════════════════════╗")
	m.db.AddLog(scanID, "info", "║       CLOUD SECURITY SUMMARY           ║")
	m.db.AddLog(scanID, "info", "╠════════════════════════════════════════╣")
	m.db.AddLog(scanID, "info", "║ Total Findings: "+itoa(summary.TotalFindings))
	m.db.AddLog(scanID, "info", "║ ├─ Critical: "+itoa(summary.Critical))
	m.db.AddLog(scanID, "info", "║ ├─ High: "+itoa(summary.High))
	m.db.AddLog(scanID, "info", "║ ├─ Medium: "+itoa(summary.Medium))
	m.db.AddLog(scanID, "info", "║ ├─ Low: "+itoa(summary.Low))
	m.db.AddLog(scanID, "info", "║ └─ Info: "+itoa(summary.Info))
	m.db.AddLog(scanID, "info", "║ Passed Checks: "+itoa(summary.Passed))
	m.db.AddLog(scanID, "info", "╚════════════════════════════════════════╝")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
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
		"trivy":      m.trivy.IsAvailable(),
		"prowler":    m.prowler.IsAvailable(),
		"scoutsuite": m.scoutsuite.IsAvailable(),
	}
}
