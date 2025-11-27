package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/security-scanner/recon-service/internal/models"
)

type Database struct {
	db *sql.DB
}

func NewDatabase(connectionString string) (*Database, error) {
	// Add sslmode=disable if not present
	if !strings.Contains(connectionString, "sslmode=") {
		if strings.Contains(connectionString, "?") {
			connectionString = connectionString + "&sslmode=disable"
		} else {
			connectionString = connectionString + "?sslmode=disable"
		}
	}

	// Retry logic with exponential backoff
	maxRetries := 10
	var db *sql.DB
	var err error

	for i := 0; i < maxRetries; i++ {
		db, err = sql.Open("postgres", connectionString)
		if err != nil {
			waitTime := time.Duration(1<<uint(i)) * time.Second
			if waitTime > 30*time.Second {
				waitTime = 30 * time.Second
			}
			fmt.Printf("Failed to open database (attempt %d/%d): %v. Retrying in %v...\n", i+1, maxRetries, err, waitTime)
			time.Sleep(waitTime)
			continue
		}

		err = db.Ping()
		if err == nil {
			break
		}

		db.Close()
		waitTime := time.Duration(1<<uint(i)) * time.Second
		if waitTime > 30*time.Second {
			waitTime = 30 * time.Second
		}
		fmt.Printf("Failed to ping database (attempt %d/%d): %v. Retrying in %v...\n", i+1, maxRetries, err, waitTime)
		time.Sleep(waitTime)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
	}

	database := &Database{db: db}
	if err := database.runMigrations(); err != nil {
		return nil, err
	}

	return database, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) runMigrations() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS recon_scans (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			target VARCHAR(255) NOT NULL,
			scan_type VARCHAR(50) NOT NULL,
			status VARCHAR(20) DEFAULT 'pending',
			progress INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			error_message TEXT,
			configuration JSONB DEFAULT '{}'
		)`,
		`CREATE TABLE IF NOT EXISTS subdomain_results (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
			subdomain VARCHAR(255) NOT NULL,
			ip VARCHAR(45),
			source VARCHAR(50),
			is_alive BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS whois_results (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
			domain VARCHAR(255) NOT NULL,
			registrar VARCHAR(255),
			creation_date VARCHAR(50),
			expiration_date VARCHAR(50),
			updated_date VARCHAR(50),
			name_servers TEXT[],
			status TEXT[],
			registrant JSONB,
			admin JSONB,
			tech JSONB,
			raw_data TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS dns_results (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
			domain VARCHAR(255) NOT NULL,
			a_records TEXT[],
			aaaa_records TEXT[],
			cname_records TEXT[],
			mx_records JSONB,
			ns_records TEXT[],
			txt_records TEXT[],
			soa_record JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS tech_results (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
			url VARCHAR(2048) NOT NULL,
			status_code INTEGER,
			title VARCHAR(512),
			technologies JSONB,
			headers JSONB,
			server VARCHAR(255),
			content_type VARCHAR(255),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS recon_logs (
			id UUID PRIMARY KEY,
			scan_id UUID REFERENCES recon_scans(id) ON DELETE CASCADE,
			level VARCHAR(20),
			message TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_recon_scans_status ON recon_scans(status)`,
		`CREATE INDEX IF NOT EXISTS idx_recon_scans_scan_type ON recon_scans(scan_type)`,
		`CREATE INDEX IF NOT EXISTS idx_subdomain_results_scan_id ON subdomain_results(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_whois_results_scan_id ON whois_results(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_results_scan_id ON dns_results(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tech_results_scan_id ON tech_results(scan_id)`,
	}

	for _, migration := range migrations {
		if _, err := d.db.Exec(migration); err != nil {
			return fmt.Errorf("migration failed: %v", err)
		}
	}

	return nil
}

// Scan operations
func (d *Database) CreateScan(scan *models.ReconScan) error {
	optionsJSON, _ := json.Marshal(scan.Options)
	_, err := d.db.Exec(`
		INSERT INTO recon_scans (id, name, target, scan_type, status, progress, created_at, configuration)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, scan.ID, scan.Name, scan.Target, scan.ScanType, scan.Status, scan.Progress, scan.CreatedAt, optionsJSON)
	return err
}

func (d *Database) GetScan(id uuid.UUID) (*models.ReconScan, error) {
	var scan models.ReconScan
	var optionsJSON []byte
	var startedAt, completedAt sql.NullTime
	var errorMessage sql.NullString

	err := d.db.QueryRow(`
		SELECT id, name, target, scan_type, status, progress, created_at, started_at, completed_at, error_message, configuration
		FROM recon_scans WHERE id = $1
	`, id).Scan(&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status, &scan.Progress,
		&scan.CreatedAt, &startedAt, &completedAt, &errorMessage, &optionsJSON)

	if err != nil {
		return nil, err
	}

	if startedAt.Valid {
		scan.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}
	if errorMessage.Valid {
		scan.ErrorMessage = &errorMessage.String
	}
	json.Unmarshal(optionsJSON, &scan.Options)

	return &scan, nil
}

func (d *Database) ListScans(scanType, status string) ([]models.ReconScan, error) {
	query := `SELECT id, name, target, scan_type, status, progress, created_at, started_at, completed_at, error_message, configuration FROM recon_scans WHERE 1=1`
	args := []interface{}{}
	argIndex := 1

	if scanType != "" {
		query += fmt.Sprintf(" AND scan_type = $%d", argIndex)
		args = append(args, scanType)
		argIndex++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	query += " ORDER BY created_at DESC"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.ReconScan
	for rows.Next() {
		var scan models.ReconScan
		var optionsJSON []byte
		var startedAt, completedAt sql.NullTime
		var errorMessage sql.NullString

		err := rows.Scan(&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status, &scan.Progress,
			&scan.CreatedAt, &startedAt, &completedAt, &errorMessage, &optionsJSON)
		if err != nil {
			continue
		}

		if startedAt.Valid {
			scan.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			scan.CompletedAt = &completedAt.Time
		}
		if errorMessage.Valid {
			scan.ErrorMessage = &errorMessage.String
		}
		json.Unmarshal(optionsJSON, &scan.Options)
		scans = append(scans, scan)
	}

	return scans, nil
}

func (d *Database) UpdateScanStatus(id uuid.UUID, status string, progress int, errorMsg *string) error {
	query := `UPDATE recon_scans SET status = $1, progress = $2`
	args := []interface{}{status, progress}
	argIndex := 3

	if status == "running" {
		query += fmt.Sprintf(", started_at = $%d", argIndex)
		args = append(args, time.Now())
		argIndex++
	}
	if status == "completed" || status == "failed" || status == "cancelled" {
		query += fmt.Sprintf(", completed_at = $%d", argIndex)
		args = append(args, time.Now())
		argIndex++
	}
	if errorMsg != nil {
		query += fmt.Sprintf(", error_message = $%d", argIndex)
		args = append(args, *errorMsg)
		argIndex++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argIndex)
	args = append(args, id)

	_, err := d.db.Exec(query, args...)
	return err
}

func (d *Database) DeleteScan(id uuid.UUID) error {
	_, err := d.db.Exec(`DELETE FROM recon_scans WHERE id = $1`, id)
	return err
}

// Subdomain operations
func (d *Database) SaveSubdomainResult(result *models.SubdomainResult) error {
	_, err := d.db.Exec(`
		INSERT INTO subdomain_results (id, scan_id, subdomain, ip_addresses, source, is_alive, http_status, https_status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (scan_id, subdomain) DO NOTHING
	`, result.ID, result.ScanID, result.Subdomain, pq.Array(result.IPAddresses), result.Source, result.IsAlive, result.HTTPStatus, result.HTTPSStatus, result.CreatedAt)
	return err
}

func (d *Database) GetSubdomainResults(scanID uuid.UUID) ([]models.SubdomainResult, error) {
	rows, err := d.db.Query(`
		SELECT id, scan_id, subdomain, ip_addresses, source, is_alive, http_status, https_status, created_at
		FROM subdomain_results WHERE scan_id = $1 ORDER BY subdomain
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.SubdomainResult
	for rows.Next() {
		var r models.SubdomainResult
		var httpStatus, httpsStatus sql.NullInt32
		err := rows.Scan(&r.ID, &r.ScanID, &r.Subdomain, pq.Array(&r.IPAddresses), &r.Source, &r.IsAlive, &httpStatus, &httpsStatus, &r.CreatedAt)
		if err != nil {
			continue
		}
		if httpStatus.Valid {
			status := int(httpStatus.Int32)
			r.HTTPStatus = &status
		}
		if httpsStatus.Valid {
			status := int(httpsStatus.Int32)
			r.HTTPSStatus = &status
		}
		results = append(results, r)
	}
	return results, nil
}

// WHOIS operations
func (d *Database) SaveWhoisResult(result *models.WhoisResult) error {
	registrantJSON, _ := json.Marshal(result.Registrant)
	adminJSON, _ := json.Marshal(result.Admin)
	techJSON, _ := json.Marshal(result.Tech)

	_, err := d.db.Exec(`
		INSERT INTO whois_results (id, scan_id, domain, registrar, creation_date, expiration_date, updated_date,
			name_servers, status, registrant, admin, tech, raw_data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`, result.ID, result.ScanID, result.Domain, result.Registrar, result.CreationDate, result.ExpirationDate,
		result.UpdatedDate, pq.Array(result.NameServers), pq.Array(result.Status), registrantJSON, adminJSON, techJSON,
		result.RawData, result.CreatedAt)
	return err
}

func (d *Database) GetWhoisResult(scanID uuid.UUID) (*models.WhoisResult, error) {
	var r models.WhoisResult
	var registrar, creationDate, expirationDate, updatedDate sql.NullString
	var registrantJSON, adminJSON, techJSON []byte

	err := d.db.QueryRow(`
		SELECT id, scan_id, domain, registrar, creation_date, expiration_date, updated_date,
			name_servers, status, registrant, admin, tech, raw_data, created_at
		FROM whois_results WHERE scan_id = $1
	`, scanID).Scan(&r.ID, &r.ScanID, &r.Domain, &registrar, &creationDate, &expirationDate,
		&updatedDate, pq.Array(&r.NameServers), pq.Array(&r.Status), &registrantJSON, &adminJSON, &techJSON, &r.RawData, &r.CreatedAt)

	if err != nil {
		return nil, err
	}

	if registrar.Valid {
		r.Registrar = &registrar.String
	}
	if creationDate.Valid {
		r.CreationDate = &creationDate.String
	}
	if expirationDate.Valid {
		r.ExpirationDate = &expirationDate.String
	}
	if updatedDate.Valid {
		r.UpdatedDate = &updatedDate.String
	}

	json.Unmarshal(registrantJSON, &r.Registrant)
	json.Unmarshal(adminJSON, &r.Admin)
	json.Unmarshal(techJSON, &r.Tech)

	return &r, nil
}

// DNS operations
func (d *Database) SaveDNSResult(result *models.DNSResult) error {
	mxJSON, _ := json.Marshal(result.MX)
	soaJSON, _ := json.Marshal(result.SOA)

	_, err := d.db.Exec(`
		INSERT INTO dns_results (id, scan_id, domain, a_records, aaaa_records, cname_records,
			mx_records, ns_records, txt_records, soa_record, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, result.ID, result.ScanID, result.Domain, pq.Array(result.A), pq.Array(result.AAAA), pq.Array(result.CNAME),
		mxJSON, pq.Array(result.NS), pq.Array(result.TXT), soaJSON, result.CreatedAt)
	return err
}

func (d *Database) GetDNSResult(scanID uuid.UUID) (*models.DNSResult, error) {
	var r models.DNSResult
	var mxJSON, soaJSON []byte

	err := d.db.QueryRow(`
		SELECT id, scan_id, domain, a_records, aaaa_records, cname_records,
			mx_records, ns_records, txt_records, soa_record, created_at
		FROM dns_results WHERE scan_id = $1
	`, scanID).Scan(&r.ID, &r.ScanID, &r.Domain, pq.Array(&r.A), pq.Array(&r.AAAA), pq.Array(&r.CNAME), &mxJSON, pq.Array(&r.NS), pq.Array(&r.TXT), &soaJSON, &r.CreatedAt)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(mxJSON, &r.MX)
	json.Unmarshal(soaJSON, &r.SOA)

	return &r, nil
}

// Tech detection operations
func (d *Database) SaveTechResult(result *models.TechResult) error {
	techJSON, _ := json.Marshal(result.Technologies)
	headersJSON, _ := json.Marshal(result.Headers)

	_, err := d.db.Exec(`
		INSERT INTO tech_results (id, scan_id, url, status_code, title, technologies, headers, server, content_type, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, result.ID, result.ScanID, result.URL, result.StatusCode, result.Title, techJSON, headersJSON,
		result.Server, result.ContentType, result.CreatedAt)
	return err
}

func (d *Database) GetTechResults(scanID uuid.UUID) ([]models.TechResult, error) {
	rows, err := d.db.Query(`
		SELECT id, scan_id, url, status_code, title, technologies, headers, server, content_type, created_at
		FROM tech_results WHERE scan_id = $1
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.TechResult
	for rows.Next() {
		var r models.TechResult
		var title, server, contentType sql.NullString
		var techJSON, headersJSON []byte

		err := rows.Scan(&r.ID, &r.ScanID, &r.URL, &r.StatusCode, &title, &techJSON, &headersJSON, &server, &contentType, &r.CreatedAt)
		if err != nil {
			continue
		}

		if title.Valid {
			r.Title = &title.String
		}
		if server.Valid {
			r.Server = &server.String
		}
		if contentType.Valid {
			r.ContentType = &contentType.String
		}
		json.Unmarshal(techJSON, &r.Technologies)
		json.Unmarshal(headersJSON, &r.Headers)
		results = append(results, r)
	}
	return results, nil
}

// Log operations
func (d *Database) AddLog(scanID uuid.UUID, level, message string) error {
	_, err := d.db.Exec(`
		INSERT INTO recon_logs (id, scan_id, level, message, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, uuid.New(), scanID, level, message, time.Now())
	return err
}

func (d *Database) GetLogs(scanID uuid.UUID) ([]models.ReconLog, error) {
	rows, err := d.db.Query(`
		SELECT id, scan_id, level, message, created_at
		FROM recon_logs WHERE scan_id = $1 ORDER BY created_at
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.ReconLog
	for rows.Next() {
		var log models.ReconLog
		err := rows.Scan(&log.ID, &log.ScanID, &log.Level, &log.Message, &log.CreatedAt)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}
	return logs, nil
}
