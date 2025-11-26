package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-scanner/api-service/internal/database"
	"github.com/security-scanner/api-service/internal/models"
)

type SwaggerScanner struct {
	db     *database.Database
	client *http.Client
}

func NewSwaggerScanner(db *database.Database) *SwaggerScanner {
	return &SwaggerScanner{
		db: db,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Common OpenAPI/Swagger endpoint paths
var defaultSwaggerEndpoints = []string{
	"/swagger.json",
	"/swagger/v1/swagger.json",
	"/swagger/v2/swagger.json",
	"/api/swagger.json",
	"/api-docs",
	"/api-docs/",
	"/api-docs.json",
	"/v1/api-docs",
	"/v2/api-docs",
	"/v3/api-docs",
	"/openapi.json",
	"/openapi.yaml",
	"/openapi/v1.json",
	"/openapi/v2.json",
	"/openapi/v3.json",
	"/api/openapi.json",
	"/api/v1/openapi.json",
	"/docs/swagger.json",
	"/swagger/docs/v1",
	"/swagger/docs/v2",
	"/.well-known/openapi.json",
	"/spec.json",
	"/api/spec.json",
	"/api.json",
	"/rest/api-docs",
	"/rest/v1/api-docs",
}

// OpenAPI 3.x structure
type OpenAPI3Spec struct {
	OpenAPI string `json:"openapi"`
	Info    struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Version     string `json:"version"`
	} `json:"info"`
	Servers []struct {
		URL         string `json:"url"`
		Description string `json:"description"`
	} `json:"servers"`
	Paths map[string]map[string]OperationObject `json:"paths"`
}

// Swagger 2.0 structure
type Swagger2Spec struct {
	Swagger  string `json:"swagger"`
	Info     struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Version     string `json:"version"`
	} `json:"info"`
	Host     string `json:"host"`
	BasePath string `json:"basePath"`
	Schemes  []string `json:"schemes"`
	Paths    map[string]map[string]OperationObject `json:"paths"`
}

type OperationObject struct {
	Summary     string       `json:"summary"`
	Description string       `json:"description"`
	OperationID string       `json:"operationId"`
	Tags        []string     `json:"tags"`
	Parameters  []Parameter  `json:"parameters"`
	RequestBody *RequestBody `json:"requestBody"`
	Responses   map[string]ResponseObject `json:"responses"`
	Deprecated  bool         `json:"deprecated"`
}

type Parameter struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Schema      *Schema `json:"schema"`
	Type        string `json:"type"` // Swagger 2.0
}

type RequestBody struct {
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Content     map[string]MediaType `json:"content"`
}

type MediaType struct {
	Schema *Schema `json:"schema"`
}

type Schema struct {
	Type       string             `json:"type"`
	Format     string             `json:"format"`
	Items      *Schema            `json:"items"`
	Properties map[string]*Schema `json:"properties"`
	Ref        string             `json:"$ref"`
}

type ResponseObject struct {
	Description string `json:"description"`
}

func (s *SwaggerScanner) Scan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	s.db.UpdateAPIScanStatus(scan.ID, "running", 0, nil)
	s.db.AddLog(scan.ID, "info", "Starting OpenAPI/Swagger discovery for "+scan.Target)

	// Get base URL
	baseURL := strings.TrimSuffix(scan.Target, "/")

	// Determine endpoints to check
	endpoints := defaultSwaggerEndpoints
	if config != nil && len(config.SwaggerEndpoints) > 0 {
		endpoints = config.SwaggerEndpoints
	}

	s.db.AddLog(scan.ID, "info", fmt.Sprintf("Checking %d OpenAPI/Swagger endpoints", len(endpoints)))

	foundSpecs := 0
	totalEndpoints := 0

	for i, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			s.db.UpdateAPIScanStatus(scan.ID, "cancelled", 0, nil)
			return ctx.Err()
		default:
		}

		progress := int(float64(i+1) / float64(len(endpoints)) * 80)
		s.db.UpdateAPIScanStatus(scan.ID, "running", 10+progress, nil)

		url := baseURL + endpoint

		spec, err := s.fetchSpec(ctx, url, config)
		if err != nil {
			continue
		}

		if spec != nil {
			spec.ScanID = scan.ID
			if err := s.db.SaveSwaggerSpec(spec); err != nil {
				s.db.AddLog(scan.ID, "warning", "Failed to save spec: "+err.Error())
			} else {
				foundSpecs++
				totalEndpoints += len(spec.Paths)
				title := "Unknown"
				if spec.Title != nil {
					title = *spec.Title
				}
				s.db.AddLog(scan.ID, "info", fmt.Sprintf("Found OpenAPI spec at %s - %s (v%s) with %d paths",
					url, title, spec.Version, len(spec.Paths)))

				// Also save discovered endpoints
				s.saveEndpointsFromSpec(scan.ID, spec, baseURL)
			}
		}
	}

	s.db.UpdateAPIScanStatus(scan.ID, "running", 95, nil)
	s.db.AddLog(scan.ID, "info", fmt.Sprintf("Swagger scan completed. Found %d specs with %d total endpoints", foundSpecs, totalEndpoints))

	return nil
}

func (s *SwaggerScanner) fetchSpec(ctx context.Context, url string, config *models.APIScanConfig) (*models.SwaggerSpec, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json, application/yaml, */*")

	// Add custom headers
	if config != nil && len(config.Headers) > 0 {
		for key, value := range config.Headers {
			req.Header.Set(key, value)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try parsing as OpenAPI 3.x first
	var openapi3 OpenAPI3Spec
	if err := json.Unmarshal(body, &openapi3); err == nil && openapi3.OpenAPI != "" {
		return s.convertOpenAPI3(url, openapi3, string(body)), nil
	}

	// Try parsing as Swagger 2.0
	var swagger2 Swagger2Spec
	if err := json.Unmarshal(body, &swagger2); err == nil && swagger2.Swagger != "" {
		return s.convertSwagger2(url, swagger2, string(body)), nil
	}

	return nil, fmt.Errorf("not a valid OpenAPI/Swagger spec")
}

func (s *SwaggerScanner) convertOpenAPI3(url string, spec OpenAPI3Spec, raw string) *models.SwaggerSpec {
	result := &models.SwaggerSpec{
		ID:        uuid.New(),
		URL:       url,
		Version:   spec.OpenAPI,
		RawSpec:   &raw,
		CreatedAt: time.Now(),
	}

	if spec.Info.Title != "" {
		result.Title = &spec.Info.Title
	}
	if spec.Info.Description != "" {
		result.Description = &spec.Info.Description
	}

	// Extract base path from first server
	if len(spec.Servers) > 0 {
		result.BasePath = &spec.Servers[0].URL
	}

	// Convert paths
	for path, methods := range spec.Paths {
		for method, op := range methods {
			swaggerPath := models.SwaggerPath{
				Path:   path,
				Method: strings.ToUpper(method),
			}

			if op.Summary != "" {
				swaggerPath.Summary = &op.Summary
			}
			if op.Description != "" {
				swaggerPath.Description = &op.Description
			}

			// Convert parameters
			for _, param := range op.Parameters {
				swaggerPath.Parameters = append(swaggerPath.Parameters, models.SwaggerParam{
					Name:     param.Name,
					In:       param.In,
					Type:     getParamSchemaType(param),
					Required: param.Required,
				})
			}

			// Convert request body to parameters (for OpenAPI 3.x)
			if op.RequestBody != nil {
				swaggerPath.Parameters = append(swaggerPath.Parameters, models.SwaggerParam{
					Name:     "body",
					In:       "body",
					Type:     "object",
					Required: op.RequestBody.Required,
				})
			}

			// Convert responses
			swaggerPath.Responses = make(map[string]string)
			for code, resp := range op.Responses {
				swaggerPath.Responses[code] = resp.Description
			}

			result.Paths = append(result.Paths, swaggerPath)
		}
	}

	return result
}

func (s *SwaggerScanner) convertSwagger2(url string, spec Swagger2Spec, raw string) *models.SwaggerSpec {
	result := &models.SwaggerSpec{
		ID:        uuid.New(),
		URL:       url,
		Version:   spec.Swagger,
		RawSpec:   &raw,
		CreatedAt: time.Now(),
	}

	if spec.Info.Title != "" {
		result.Title = &spec.Info.Title
	}
	if spec.Info.Description != "" {
		result.Description = &spec.Info.Description
	}
	if spec.BasePath != "" {
		result.BasePath = &spec.BasePath
	}

	// Convert paths
	for path, methods := range spec.Paths {
		for method, op := range methods {
			swaggerPath := models.SwaggerPath{
				Path:   path,
				Method: strings.ToUpper(method),
			}

			if op.Summary != "" {
				swaggerPath.Summary = &op.Summary
			}
			if op.Description != "" {
				swaggerPath.Description = &op.Description
			}

			// Convert parameters
			for _, param := range op.Parameters {
				paramType := param.Type
				if paramType == "" && param.Schema != nil {
					paramType = param.Schema.Type
				}
				swaggerPath.Parameters = append(swaggerPath.Parameters, models.SwaggerParam{
					Name:     param.Name,
					In:       param.In,
					Type:     paramType,
					Required: param.Required,
				})
			}

			// Convert responses
			swaggerPath.Responses = make(map[string]string)
			for code, resp := range op.Responses {
				swaggerPath.Responses[code] = resp.Description
			}

			result.Paths = append(result.Paths, swaggerPath)
		}
	}

	return result
}

func getParamSchemaType(param Parameter) string {
	if param.Type != "" {
		return param.Type
	}
	if param.Schema != nil {
		if param.Schema.Type != "" {
			return param.Schema.Type
		}
		if param.Schema.Ref != "" {
			// Extract type from reference
			parts := strings.Split(param.Schema.Ref, "/")
			return parts[len(parts)-1]
		}
	}
	return "string"
}

func (s *SwaggerScanner) saveEndpointsFromSpec(scanID uuid.UUID, spec *models.SwaggerSpec, baseURL string) {
	for _, path := range spec.Paths {
		fullPath := path.Path
		if spec.BasePath != nil && *spec.BasePath != "" && *spec.BasePath != "/" {
			fullPath = *spec.BasePath + path.Path
		}

		endpoint := &models.APIEndpoint{
			ID:        uuid.New(),
			ScanID:    scanID,
			URL:       baseURL + fullPath,
			Method:    path.Method,
			Source:    "swagger",
			CreatedAt: time.Now(),
		}

		s.db.SaveAPIEndpoint(endpoint)

		// Save parameters
		for _, param := range path.Parameters {
			apiParam := &models.APIParameter{
				ID:         uuid.New(),
				ScanID:     scanID,
				EndpointID: &endpoint.ID,
				URL:        endpoint.URL,
				Name:       param.Name,
				ParamType:  param.In,
				Method:     path.Method,
				CreatedAt:  time.Now(),
			}
			s.db.SaveAPIParameter(apiParam)
		}
	}
}
