package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/security-scanner/api-service/internal/database"
	"github.com/security-scanner/api-service/internal/models"
)

// Manager handles all API scanning operations
type Manager struct {
	db          *database.Database
	kiterunner  *KiterunnerScanner
	arjun       *ArjunScanner
	graphql     *GraphQLScanner
	swagger     *SwaggerScanner
	activeScans map[string]context.CancelFunc
	mu          sync.Mutex
}

// NewManager creates a new scanner manager
func NewManager(db *database.Database, kiterunnerPath, arjunPath, wordlistsPath string) *Manager {
	return &Manager{
		db:          db,
		kiterunner:  NewKiterunnerScanner(db, kiterunnerPath, wordlistsPath),
		arjun:       NewArjunScanner(db, arjunPath, wordlistsPath),
		graphql:     NewGraphQLScanner(db),
		swagger:     NewSwaggerScanner(db),
		activeScans: make(map[string]context.CancelFunc),
	}
}

// StartScan starts an API scan asynchronously
func (m *Manager) StartScan(scan *models.APIScan) error {
	ctx, cancel := context.WithCancel(context.Background())

	m.mu.Lock()
	m.activeScans[scan.ID.String()] = cancel
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.activeScans, scan.ID.String())
			m.mu.Unlock()
		}()

		// Parse config
		var config models.APIScanConfig
		if len(scan.Config) > 0 {
			json.Unmarshal(scan.Config, &config)
		}

		var err error
		switch scan.ScanType {
		case "kiterunner":
			err = m.runKiterunnerScan(ctx, scan, &config)
		case "arjun":
			err = m.runArjunScan(ctx, scan, &config)
		case "graphql":
			err = m.runGraphQLScan(ctx, scan, &config)
		case "swagger":
			err = m.runSwaggerScan(ctx, scan, &config)
		case "full":
			err = m.runFullScan(ctx, scan, &config)
		default:
			errMsg := fmt.Sprintf("Unknown scan type: %s", scan.ScanType)
			m.db.UpdateAPIScanStatus(scan.ID, "failed", 0, &errMsg)
			return
		}

		if err != nil {
			if ctx.Err() == context.Canceled {
				m.db.UpdateAPIScanStatus(scan.ID, "cancelled", 0, nil)
			} else {
				errMsg := err.Error()
				m.db.UpdateAPIScanStatus(scan.ID, "failed", 0, &errMsg)
			}
			return
		}

		m.db.UpdateAPIScanStatus(scan.ID, "completed", 100, nil)
	}()

	return nil
}

// CancelScan cancels a running scan
func (m *Manager) CancelScan(scanID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cancel, ok := m.activeScans[scanID]; ok {
		cancel()
		delete(m.activeScans, scanID)
		return true
	}
	return false
}

// runKiterunnerScan runs Kiterunner API endpoint discovery
func (m *Manager) runKiterunnerScan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	m.db.AddLog(scan.ID, "info", "Starting Kiterunner scan")

	if err := m.kiterunner.Scan(ctx, scan, config); err != nil {
		return err
	}

	return nil
}

// runArjunScan runs Arjun parameter discovery
func (m *Manager) runArjunScan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	m.db.AddLog(scan.ID, "info", "Starting Arjun parameter discovery")

	if err := m.arjun.Scan(ctx, scan, config); err != nil {
		return err
	}

	return nil
}

// runGraphQLScan runs GraphQL introspection scan
func (m *Manager) runGraphQLScan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	m.db.AddLog(scan.ID, "info", "Starting GraphQL introspection scan")

	if err := m.graphql.Scan(ctx, scan, config); err != nil {
		return err
	}

	return nil
}

// runSwaggerScan runs OpenAPI/Swagger discovery
func (m *Manager) runSwaggerScan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	m.db.AddLog(scan.ID, "info", "Starting OpenAPI/Swagger discovery")

	if err := m.swagger.Scan(ctx, scan, config); err != nil {
		return err
	}

	return nil
}

// runFullScan runs all scan types
func (m *Manager) runFullScan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	m.db.AddLog(scan.ID, "info", "Starting full API discovery scan")
	m.db.UpdateAPIScanStatus(scan.ID, "running", 0, nil)

	// Step 1: Swagger/OpenAPI discovery (20%)
	m.db.AddLog(scan.ID, "info", "Phase 1: OpenAPI/Swagger discovery")
	if err := m.swagger.Scan(ctx, scan, config); err != nil {
		m.db.AddLog(scan.ID, "warning", "Swagger scan error: "+err.Error())
	}
	m.db.UpdateAPIScanStatus(scan.ID, "running", 20, nil)

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Step 2: GraphQL introspection (40%)
	m.db.AddLog(scan.ID, "info", "Phase 2: GraphQL introspection")
	if err := m.graphql.Scan(ctx, scan, config); err != nil {
		m.db.AddLog(scan.ID, "warning", "GraphQL scan error: "+err.Error())
	}
	m.db.UpdateAPIScanStatus(scan.ID, "running", 40, nil)

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Step 3: Kiterunner endpoint discovery (70%)
	m.db.AddLog(scan.ID, "info", "Phase 3: API endpoint discovery with Kiterunner")
	if err := m.kiterunner.Scan(ctx, scan, config); err != nil {
		m.db.AddLog(scan.ID, "warning", "Kiterunner scan error: "+err.Error())
	}
	m.db.UpdateAPIScanStatus(scan.ID, "running", 70, nil)

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Step 4: Arjun parameter discovery on found endpoints (95%)
	m.db.AddLog(scan.ID, "info", "Phase 4: Parameter discovery with Arjun")

	// Get discovered endpoints and scan them for parameters
	endpoints, err := m.db.GetAPIEndpoints(scan.ID)
	if err == nil && len(endpoints) > 0 {
		// Limit to first 20 endpoints to avoid long scans
		if len(endpoints) > 20 {
			endpoints = endpoints[:20]
		}
		if err := m.arjun.ScanEndpoints(ctx, scan, endpoints, config); err != nil {
			m.db.AddLog(scan.ID, "warning", "Arjun scan error: "+err.Error())
		}
	} else {
		// No endpoints found, scan the main target
		if err := m.arjun.Scan(ctx, scan, config); err != nil {
			m.db.AddLog(scan.ID, "warning", "Arjun scan error: "+err.Error())
		}
	}
	m.db.UpdateAPIScanStatus(scan.ID, "running", 95, nil)

	// Get final statistics
	results, _ := m.db.GetAPIScanResults(scan.ID)
	if results != nil {
		m.db.AddLog(scan.ID, "info", fmt.Sprintf("Full scan completed: %d endpoints, %d parameters, %d GraphQL schemas, %d Swagger specs",
			len(results.Endpoints), len(results.Parameters), len(results.GraphQL), len(results.Swagger)))
	}

	return nil
}

// GetScanStatus returns the current status of active scans
func (m *Manager) GetScanStatus() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := make(map[string]bool)
	for id := range m.activeScans {
		status[id] = true
	}
	return status
}
