package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// APIScan represents an API discovery scan
type APIScan struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Target      string          `json:"target"`
	ScanType    string          `json:"scan_type"` // kiterunner, arjun, graphql, swagger, full
	Status      string          `json:"status"`    // pending, running, completed, failed, cancelled
	Progress    int             `json:"progress"`
	Config      json.RawMessage `json:"config,omitempty"`
	Error       *string         `json:"error,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
}

// APIEndpoint represents a discovered API endpoint
type APIEndpoint struct {
	ID          uuid.UUID  `json:"id"`
	ScanID      uuid.UUID  `json:"scan_id"`
	URL         string     `json:"url"`
	Method      string     `json:"method"`
	StatusCode  int        `json:"status_code"`
	ContentType *string    `json:"content_type,omitempty"`
	Length      int        `json:"length"`
	Source      string     `json:"source"` // kiterunner, arjun, ffuf, swagger
	CreatedAt   time.Time  `json:"created_at"`
}

// APIParameter represents a discovered API parameter
type APIParameter struct {
	ID         uuid.UUID `json:"id"`
	ScanID     uuid.UUID `json:"scan_id"`
	EndpointID *uuid.UUID `json:"endpoint_id,omitempty"`
	URL        string    `json:"url"`
	Name       string    `json:"name"`
	ParamType  string    `json:"param_type"` // query, body, header, path
	Method     string    `json:"method"`
	Reason     *string   `json:"reason,omitempty"` // Why it was detected
	CreatedAt  time.Time `json:"created_at"`
}

// GraphQLSchema represents discovered GraphQL schema information
type GraphQLSchema struct {
	ID             uuid.UUID        `json:"id"`
	ScanID         uuid.UUID        `json:"scan_id"`
	URL            string           `json:"url"`
	IntrospectionEnabled bool       `json:"introspection_enabled"`
	Types          []GraphQLType    `json:"types,omitempty"`
	Queries        []GraphQLField   `json:"queries,omitempty"`
	Mutations      []GraphQLField   `json:"mutations,omitempty"`
	Subscriptions  []GraphQLField   `json:"subscriptions,omitempty"`
	RawSchema      *string          `json:"raw_schema,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
}

// GraphQLType represents a GraphQL type
type GraphQLType struct {
	Name        string           `json:"name"`
	Kind        string           `json:"kind"` // OBJECT, SCALAR, ENUM, INPUT_OBJECT, etc.
	Description *string          `json:"description,omitempty"`
	Fields      []GraphQLField   `json:"fields,omitempty"`
}

// GraphQLField represents a GraphQL field
type GraphQLField struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Description *string           `json:"description,omitempty"`
	Args        []GraphQLArg      `json:"args,omitempty"`
	IsDeprecated bool             `json:"is_deprecated"`
}

// GraphQLArg represents a GraphQL argument
type GraphQLArg struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	DefaultValue *string `json:"default_value,omitempty"`
}

// SwaggerSpec represents discovered OpenAPI/Swagger specification
type SwaggerSpec struct {
	ID          uuid.UUID      `json:"id"`
	ScanID      uuid.UUID      `json:"scan_id"`
	URL         string         `json:"url"`
	Version     string         `json:"version"` // 2.0, 3.0.0, etc.
	Title       *string        `json:"title,omitempty"`
	Description *string        `json:"description,omitempty"`
	BasePath    *string        `json:"base_path,omitempty"`
	Paths       []SwaggerPath  `json:"paths,omitempty"`
	RawSpec     *string        `json:"raw_spec,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

// SwaggerPath represents a path in OpenAPI spec
type SwaggerPath struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Summary     *string           `json:"summary,omitempty"`
	Description *string           `json:"description,omitempty"`
	Parameters  []SwaggerParam    `json:"parameters,omitempty"`
	Responses   map[string]string `json:"responses,omitempty"`
}

// SwaggerParam represents a parameter in OpenAPI spec
type SwaggerParam struct {
	Name     string  `json:"name"`
	In       string  `json:"in"` // query, path, header, body
	Type     string  `json:"type"`
	Required bool    `json:"required"`
}

// ScanLog represents a log entry for a scan
type ScanLog struct {
	ID        uuid.UUID `json:"id"`
	ScanID    uuid.UUID `json:"scan_id"`
	Level     string    `json:"level"` // info, warning, error, debug
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateAPIScanRequest represents a request to create an API scan
type CreateAPIScanRequest struct {
	Name     string          `json:"name"`
	Target   string          `json:"target"`
	ScanType string          `json:"scan_type"`
	Config   json.RawMessage `json:"config,omitempty"`
}

// APIScanConfig represents configuration for API scanning
type APIScanConfig struct {
	// Kiterunner options
	KiterunnerWordlist string   `json:"kiterunner_wordlist,omitempty"`
	KiterunnerRoutes   []string `json:"kiterunner_routes,omitempty"`

	// Arjun options
	ArjunMethods       []string `json:"arjun_methods,omitempty"` // GET, POST, etc.
	ArjunWordlist      string   `json:"arjun_wordlist,omitempty"`
	ArjunThreads       int      `json:"arjun_threads,omitempty"`

	// GraphQL options
	GraphQLEndpoints   []string `json:"graphql_endpoints,omitempty"` // Custom endpoints to check

	// Swagger options
	SwaggerEndpoints   []string `json:"swagger_endpoints,omitempty"` // Custom endpoints to check

	// General options
	Timeout            int      `json:"timeout,omitempty"` // Timeout in seconds
	Threads            int      `json:"threads,omitempty"`
	FollowRedirects    bool     `json:"follow_redirects,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
}

// APIScanResults represents the combined results of an API scan
type APIScanResults struct {
	Endpoints  []APIEndpoint   `json:"endpoints"`
	Parameters []APIParameter  `json:"parameters"`
	GraphQL    []GraphQLSchema `json:"graphql,omitempty"`
	Swagger    []SwaggerSpec   `json:"swagger,omitempty"`
}
