package scanner

import (
	"bytes"
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

type GraphQLScanner struct {
	db     *database.Database
	client *http.Client
}

func NewGraphQLScanner(db *database.Database) *GraphQLScanner {
	return &GraphQLScanner{
		db: db,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Common GraphQL endpoint paths
var defaultGraphQLEndpoints = []string{
	"/graphql",
	"/graphql/",
	"/api/graphql",
	"/api/graphql/",
	"/v1/graphql",
	"/v2/graphql",
	"/query",
	"/gql",
	"/graphiql",
	"/playground",
	"/explorer",
	"/altair",
	"/__graphql",
}

// GraphQL introspection query
const introspectionQuery = `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
`

// IntrospectionResponse represents the GraphQL introspection response
type IntrospectionResponse struct {
	Data struct {
		Schema struct {
			QueryType        *NamedType  `json:"queryType"`
			MutationType     *NamedType  `json:"mutationType"`
			SubscriptionType *NamedType  `json:"subscriptionType"`
			Types            []TypeInfo  `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type NamedType struct {
	Name string `json:"name"`
}

type TypeInfo struct {
	Kind        string      `json:"kind"`
	Name        string      `json:"name"`
	Description *string     `json:"description"`
	Fields      []FieldInfo `json:"fields"`
	InputFields []InputInfo `json:"inputFields"`
	EnumValues  []EnumValue `json:"enumValues"`
}

type FieldInfo struct {
	Name              string      `json:"name"`
	Description       *string     `json:"description"`
	Args              []InputInfo `json:"args"`
	Type              TypeRef     `json:"type"`
	IsDeprecated      bool        `json:"isDeprecated"`
	DeprecationReason *string     `json:"deprecationReason"`
}

type InputInfo struct {
	Name         string  `json:"name"`
	Description  *string `json:"description"`
	Type         TypeRef `json:"type"`
	DefaultValue *string `json:"defaultValue"`
}

type TypeRef struct {
	Kind   string   `json:"kind"`
	Name   *string  `json:"name"`
	OfType *TypeRef `json:"ofType"`
}

type EnumValue struct {
	Name              string  `json:"name"`
	Description       *string `json:"description"`
	IsDeprecated      bool    `json:"isDeprecated"`
	DeprecationReason *string `json:"deprecationReason"`
}

func (g *GraphQLScanner) Scan(ctx context.Context, scan *models.APIScan, config *models.APIScanConfig) error {
	g.db.UpdateAPIScanStatus(scan.ID, "running", 0, nil)
	g.db.AddLog(scan.ID, "info", "Starting GraphQL introspection scan for "+scan.Target)

	// Get base URL
	baseURL := strings.TrimSuffix(scan.Target, "/")

	// Determine endpoints to check
	endpoints := defaultGraphQLEndpoints
	if config != nil && len(config.GraphQLEndpoints) > 0 {
		endpoints = config.GraphQLEndpoints
	}

	g.db.AddLog(scan.ID, "info", fmt.Sprintf("Checking %d GraphQL endpoints", len(endpoints)))

	foundSchemas := 0

	for i, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			g.db.UpdateAPIScanStatus(scan.ID, "cancelled", 0, nil)
			return ctx.Err()
		default:
		}

		progress := int(float64(i+1) / float64(len(endpoints)) * 80)
		g.db.UpdateAPIScanStatus(scan.ID, "running", 10+progress, nil)

		url := baseURL + endpoint
		g.db.AddLog(scan.ID, "info", "Checking: "+url)

		schema, err := g.introspect(ctx, url, config)
		if err != nil {
			continue
		}

		if schema != nil {
			schema.ScanID = scan.ID
			if err := g.db.SaveGraphQLSchema(schema); err != nil {
				g.db.AddLog(scan.ID, "warning", "Failed to save schema: "+err.Error())
			} else {
				foundSchemas++
				g.db.AddLog(scan.ID, "info", fmt.Sprintf("GraphQL introspection enabled at %s - Found %d types, %d queries, %d mutations",
					url, len(schema.Types), len(schema.Queries), len(schema.Mutations)))
			}
		}
	}

	g.db.UpdateAPIScanStatus(scan.ID, "running", 95, nil)
	g.db.AddLog(scan.ID, "info", fmt.Sprintf("GraphQL scan completed. Found %d schemas with introspection enabled", foundSchemas))

	return nil
}

func (g *GraphQLScanner) introspect(ctx context.Context, url string, config *models.APIScanConfig) (*models.GraphQLSchema, error) {
	// Prepare introspection query
	query := map[string]interface{}{
		"query": introspectionQuery,
	}
	body, _ := json.Marshal(query)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add custom headers
	if config != nil && len(config.Headers) > 0 {
		for key, value := range config.Headers {
			req.Header.Set(key, value)
		}
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("non-200 status: %d", resp.StatusCode)
	}

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse introspection response
	var introspection IntrospectionResponse
	if err := json.Unmarshal(respBody, &introspection); err != nil {
		return nil, err
	}

	// Check for errors
	if len(introspection.Errors) > 0 {
		return nil, fmt.Errorf("introspection error: %s", introspection.Errors[0].Message)
	}

	// Check if we got schema data
	if introspection.Data.Schema.QueryType == nil && len(introspection.Data.Schema.Types) == 0 {
		return nil, fmt.Errorf("no schema data received")
	}

	// Convert to our model
	schema := &models.GraphQLSchema{
		ID:                   uuid.New(),
		URL:                  url,
		IntrospectionEnabled: true,
		CreatedAt:            time.Now(),
	}

	// Store raw schema
	rawSchema := string(respBody)
	schema.RawSchema = &rawSchema

	// Process types
	for _, t := range introspection.Data.Schema.Types {
		// Skip internal types
		if strings.HasPrefix(t.Name, "__") {
			continue
		}

		gqlType := models.GraphQLType{
			Name:        t.Name,
			Kind:        t.Kind,
			Description: t.Description,
		}

		// Process fields
		for _, f := range t.Fields {
			field := models.GraphQLField{
				Name:         f.Name,
				Type:         formatType(f.Type),
				Description:  f.Description,
				IsDeprecated: f.IsDeprecated,
			}

			// Process args
			for _, a := range f.Args {
				field.Args = append(field.Args, models.GraphQLArg{
					Name:         a.Name,
					Type:         formatType(a.Type),
					DefaultValue: a.DefaultValue,
				})
			}

			gqlType.Fields = append(gqlType.Fields, field)
		}

		schema.Types = append(schema.Types, gqlType)

		// Identify Query, Mutation, Subscription types
		if introspection.Data.Schema.QueryType != nil && t.Name == introspection.Data.Schema.QueryType.Name {
			for _, f := range t.Fields {
				field := models.GraphQLField{
					Name:         f.Name,
					Type:         formatType(f.Type),
					Description:  f.Description,
					IsDeprecated: f.IsDeprecated,
				}
				for _, a := range f.Args {
					field.Args = append(field.Args, models.GraphQLArg{
						Name: a.Name,
						Type: formatType(a.Type),
					})
				}
				schema.Queries = append(schema.Queries, field)
			}
		}

		if introspection.Data.Schema.MutationType != nil && t.Name == introspection.Data.Schema.MutationType.Name {
			for _, f := range t.Fields {
				field := models.GraphQLField{
					Name:         f.Name,
					Type:         formatType(f.Type),
					Description:  f.Description,
					IsDeprecated: f.IsDeprecated,
				}
				for _, a := range f.Args {
					field.Args = append(field.Args, models.GraphQLArg{
						Name: a.Name,
						Type: formatType(a.Type),
					})
				}
				schema.Mutations = append(schema.Mutations, field)
			}
		}

		if introspection.Data.Schema.SubscriptionType != nil && t.Name == introspection.Data.Schema.SubscriptionType.Name {
			for _, f := range t.Fields {
				field := models.GraphQLField{
					Name:         f.Name,
					Type:         formatType(f.Type),
					Description:  f.Description,
					IsDeprecated: f.IsDeprecated,
				}
				schema.Subscriptions = append(schema.Subscriptions, field)
			}
		}
	}

	return schema, nil
}

func formatType(t TypeRef) string {
	if t.Name != nil {
		return *t.Name
	}
	if t.OfType != nil {
		inner := formatType(*t.OfType)
		switch t.Kind {
		case "NON_NULL":
			return inner + "!"
		case "LIST":
			return "[" + inner + "]"
		default:
			return inner
		}
	}
	return t.Kind
}

// CheckEndpoint quickly checks if a URL is a GraphQL endpoint
func (g *GraphQLScanner) CheckEndpoint(ctx context.Context, url string) (bool, error) {
	// Simple query to test if it's a GraphQL endpoint
	query := map[string]interface{}{
		"query": "{ __typename }",
	}
	body, _ := json.Marshal(query)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, nil
	}

	respBody, _ := io.ReadAll(resp.Body)

	// Check if response looks like GraphQL
	return strings.Contains(string(respBody), "__typename") ||
		strings.Contains(string(respBody), "data") ||
		strings.Contains(string(respBody), "errors"), nil
}
