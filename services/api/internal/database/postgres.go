package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/security-scanner/api-service/internal/models"
)

type Database struct {
	db *sql.DB
}

func New(connectionString string) (*Database, error) {
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

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &Database{db: db}, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

// ==================== API Scans ====================

func (d *Database) CreateAPIScan(scan *models.APIScan) error {
	query := `
		INSERT INTO api_scans (id, name, target, scan_type, status, progress, config, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := d.db.Exec(query,
		scan.ID, scan.Name, scan.Target, scan.ScanType, scan.Status,
		scan.Progress, scan.Config, scan.CreatedAt,
	)
	return err
}

func (d *Database) GetAPIScan(id uuid.UUID) (*models.APIScan, error) {
	query := `
		SELECT id, name, target, scan_type, status, progress, config, error,
		       created_at, started_at, completed_at
		FROM api_scans WHERE id = $1
	`
	var scan models.APIScan
	err := d.db.QueryRow(query, id).Scan(
		&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status,
		&scan.Progress, &scan.Config, &scan.Error,
		&scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &scan, err
}

func (d *Database) ListAPIScans(scanType string, status string, limit int) ([]models.APIScan, error) {
	query := `
		SELECT id, name, target, scan_type, status, progress, config, error,
		       created_at, started_at, completed_at
		FROM api_scans
		WHERE ($1 = '' OR scan_type = $1)
		  AND ($2 = '' OR status = $2)
		ORDER BY created_at DESC
		LIMIT $3
	`
	rows, err := d.db.Query(query, scanType, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.APIScan
	for rows.Next() {
		var scan models.APIScan
		if err := rows.Scan(
			&scan.ID, &scan.Name, &scan.Target, &scan.ScanType, &scan.Status,
			&scan.Progress, &scan.Config, &scan.Error,
			&scan.CreatedAt, &scan.StartedAt, &scan.CompletedAt,
		); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, nil
}

func (d *Database) UpdateAPIScanStatus(id uuid.UUID, status string, progress int, scanError *string) error {
	var query string
	var args []interface{}

	if status == "running" && progress == 0 {
		query = `UPDATE api_scans SET status = $1, progress = $2, started_at = $3 WHERE id = $4`
		args = []interface{}{status, progress, time.Now(), id}
	} else if status == "completed" || status == "failed" || status == "cancelled" {
		query = `UPDATE api_scans SET status = $1, progress = $2, error = $3, completed_at = $4 WHERE id = $5`
		args = []interface{}{status, progress, scanError, time.Now(), id}
	} else {
		query = `UPDATE api_scans SET status = $1, progress = $2 WHERE id = $3`
		args = []interface{}{status, progress, id}
	}

	_, err := d.db.Exec(query, args...)
	return err
}

func (d *Database) DeleteAPIScan(id uuid.UUID) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete related data
	tables := []string{"api_scan_logs", "api_endpoints", "api_parameters", "graphql_schemas", "swagger_specs"}
	for _, table := range tables {
		if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE scan_id = $1", table), id); err != nil {
			return err
		}
	}

	// Delete scan
	if _, err := tx.Exec("DELETE FROM api_scans WHERE id = $1", id); err != nil {
		return err
	}

	return tx.Commit()
}

// ==================== Endpoints ====================

func (d *Database) SaveAPIEndpoint(endpoint *models.APIEndpoint) error {
	query := `
		INSERT INTO api_endpoints (id, scan_id, url, method, status_code, content_type, length, source, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (scan_id, url, method) DO UPDATE SET
			status_code = EXCLUDED.status_code,
			content_type = EXCLUDED.content_type,
			length = EXCLUDED.length
	`
	_, err := d.db.Exec(query,
		endpoint.ID, endpoint.ScanID, endpoint.URL, endpoint.Method,
		endpoint.StatusCode, endpoint.ContentType, endpoint.Length,
		endpoint.Source, endpoint.CreatedAt,
	)
	return err
}

func (d *Database) GetAPIEndpoints(scanID uuid.UUID) ([]models.APIEndpoint, error) {
	query := `
		SELECT id, scan_id, url, method, status_code, content_type, length, source, created_at
		FROM api_endpoints WHERE scan_id = $1
		ORDER BY url, method
	`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []models.APIEndpoint
	for rows.Next() {
		var e models.APIEndpoint
		if err := rows.Scan(
			&e.ID, &e.ScanID, &e.URL, &e.Method, &e.StatusCode,
			&e.ContentType, &e.Length, &e.Source, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		endpoints = append(endpoints, e)
	}
	return endpoints, nil
}

// ==================== Parameters ====================

func (d *Database) SaveAPIParameter(param *models.APIParameter) error {
	query := `
		INSERT INTO api_parameters (id, scan_id, endpoint_id, url, name, param_type, method, reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (scan_id, url, name, param_type) DO NOTHING
	`
	_, err := d.db.Exec(query,
		param.ID, param.ScanID, param.EndpointID, param.URL,
		param.Name, param.ParamType, param.Method, param.Reason, param.CreatedAt,
	)
	return err
}

func (d *Database) GetAPIParameters(scanID uuid.UUID) ([]models.APIParameter, error) {
	query := `
		SELECT id, scan_id, endpoint_id, url, name, param_type, method, reason, created_at
		FROM api_parameters WHERE scan_id = $1
		ORDER BY url, name
	`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var params []models.APIParameter
	for rows.Next() {
		var p models.APIParameter
		if err := rows.Scan(
			&p.ID, &p.ScanID, &p.EndpointID, &p.URL,
			&p.Name, &p.ParamType, &p.Method, &p.Reason, &p.CreatedAt,
		); err != nil {
			return nil, err
		}
		params = append(params, p)
	}
	return params, nil
}

// ==================== GraphQL ====================

func (d *Database) SaveGraphQLSchema(schema *models.GraphQLSchema) error {
	typesJSON, _ := json.Marshal(schema.Types)
	queriesJSON, _ := json.Marshal(schema.Queries)
	mutationsJSON, _ := json.Marshal(schema.Mutations)
	subscriptionsJSON, _ := json.Marshal(schema.Subscriptions)

	query := `
		INSERT INTO graphql_schemas (id, scan_id, url, introspection_enabled, types, queries, mutations, subscriptions, raw_schema, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (scan_id, url) DO UPDATE SET
			introspection_enabled = EXCLUDED.introspection_enabled,
			types = EXCLUDED.types,
			queries = EXCLUDED.queries,
			mutations = EXCLUDED.mutations,
			subscriptions = EXCLUDED.subscriptions,
			raw_schema = EXCLUDED.raw_schema
	`
	_, err := d.db.Exec(query,
		schema.ID, schema.ScanID, schema.URL, schema.IntrospectionEnabled,
		typesJSON, queriesJSON, mutationsJSON, subscriptionsJSON,
		schema.RawSchema, schema.CreatedAt,
	)
	return err
}

func (d *Database) GetGraphQLSchemas(scanID uuid.UUID) ([]models.GraphQLSchema, error) {
	query := `
		SELECT id, scan_id, url, introspection_enabled, types, queries, mutations, subscriptions, raw_schema, created_at
		FROM graphql_schemas WHERE scan_id = $1
	`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schemas []models.GraphQLSchema
	for rows.Next() {
		var s models.GraphQLSchema
		var typesJSON, queriesJSON, mutationsJSON, subscriptionsJSON []byte
		if err := rows.Scan(
			&s.ID, &s.ScanID, &s.URL, &s.IntrospectionEnabled,
			&typesJSON, &queriesJSON, &mutationsJSON, &subscriptionsJSON,
			&s.RawSchema, &s.CreatedAt,
		); err != nil {
			return nil, err
		}
		json.Unmarshal(typesJSON, &s.Types)
		json.Unmarshal(queriesJSON, &s.Queries)
		json.Unmarshal(mutationsJSON, &s.Mutations)
		json.Unmarshal(subscriptionsJSON, &s.Subscriptions)
		schemas = append(schemas, s)
	}
	return schemas, nil
}

// ==================== Swagger ====================

func (d *Database) SaveSwaggerSpec(spec *models.SwaggerSpec) error {
	pathsJSON, _ := json.Marshal(spec.Paths)

	query := `
		INSERT INTO swagger_specs (id, scan_id, url, version, title, description, base_path, paths, raw_spec, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (scan_id, url) DO UPDATE SET
			version = EXCLUDED.version,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			base_path = EXCLUDED.base_path,
			paths = EXCLUDED.paths,
			raw_spec = EXCLUDED.raw_spec
	`
	_, err := d.db.Exec(query,
		spec.ID, spec.ScanID, spec.URL, spec.Version, spec.Title,
		spec.Description, spec.BasePath, pathsJSON, spec.RawSpec, spec.CreatedAt,
	)
	return err
}

func (d *Database) GetSwaggerSpecs(scanID uuid.UUID) ([]models.SwaggerSpec, error) {
	query := `
		SELECT id, scan_id, url, version, title, description, base_path, paths, raw_spec, created_at
		FROM swagger_specs WHERE scan_id = $1
	`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var specs []models.SwaggerSpec
	for rows.Next() {
		var s models.SwaggerSpec
		var pathsJSON []byte
		if err := rows.Scan(
			&s.ID, &s.ScanID, &s.URL, &s.Version, &s.Title,
			&s.Description, &s.BasePath, &pathsJSON, &s.RawSpec, &s.CreatedAt,
		); err != nil {
			return nil, err
		}
		json.Unmarshal(pathsJSON, &s.Paths)
		specs = append(specs, s)
	}
	return specs, nil
}

// ==================== Logs ====================

func (d *Database) AddLog(scanID uuid.UUID, level, message string) error {
	query := `
		INSERT INTO api_scan_logs (id, scan_id, level, message, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := d.db.Exec(query, uuid.New(), scanID, level, message, time.Now())
	if err != nil {
		log.Printf("Failed to add log: %v", err)
	}
	return err
}

func (d *Database) GetLogs(scanID uuid.UUID) ([]models.ScanLog, error) {
	query := `
		SELECT id, scan_id, level, message, created_at
		FROM api_scan_logs WHERE scan_id = $1
		ORDER BY created_at ASC
	`
	rows, err := d.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.ScanLog
	for rows.Next() {
		var l models.ScanLog
		if err := rows.Scan(&l.ID, &l.ScanID, &l.Level, &l.Message, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// ==================== Results ====================

func (d *Database) GetAPIScanResults(scanID uuid.UUID) (*models.APIScanResults, error) {
	endpoints, err := d.GetAPIEndpoints(scanID)
	if err != nil {
		return nil, err
	}

	params, err := d.GetAPIParameters(scanID)
	if err != nil {
		return nil, err
	}

	graphql, err := d.GetGraphQLSchemas(scanID)
	if err != nil {
		return nil, err
	}

	swagger, err := d.GetSwaggerSpecs(scanID)
	if err != nil {
		return nil, err
	}

	return &models.APIScanResults{
		Endpoints:  endpoints,
		Parameters: params,
		GraphQL:    graphql,
		Swagger:    swagger,
	}, nil
}

// Suppress unused import warning
var _ = pq.Array
