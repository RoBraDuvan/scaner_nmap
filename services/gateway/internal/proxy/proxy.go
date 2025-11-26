package proxy

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ServiceProxy handles proxying requests to backend services
type ServiceProxy struct {
	client *http.Client
}

// NewServiceProxy creates a new proxy instance
func NewServiceProxy() *ServiceProxy {
	return &ServiceProxy{
		client: &http.Client{
			Timeout: 5 * time.Minute, // Long timeout for scans
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// ProxyTo creates a handler that proxies requests to the target URL
func (p *ServiceProxy) ProxyTo(targetBaseURL string, stripPrefix string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Build target URL
		path := c.Path()
		if stripPrefix != "" {
			path = strings.TrimPrefix(path, stripPrefix)
		}

		targetURL := targetBaseURL + path
		if c.Request().URI().QueryString() != nil && len(c.Request().URI().QueryString()) > 0 {
			targetURL += "?" + string(c.Request().URI().QueryString())
		}

		log.Printf("🔀 Proxying %s %s → %s", c.Method(), c.Path(), targetURL)

		// Create proxy request
		req, err := http.NewRequestWithContext(c.Context(), c.Method(), targetURL, strings.NewReader(string(c.Body())))
		if err != nil {
			log.Printf("❌ Error creating proxy request: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to create proxy request"})
		}

		// Copy headers
		c.Request().Header.VisitAll(func(key, value []byte) {
			keyStr := string(key)
			// Skip hop-by-hop headers
			if keyStr != "Connection" && keyStr != "Keep-Alive" && keyStr != "Transfer-Encoding" {
				req.Header.Set(keyStr, string(value))
			}
		})

		// Add forwarding headers
		req.Header.Set("X-Forwarded-For", c.IP())
		req.Header.Set("X-Forwarded-Host", c.Hostname())
		req.Header.Set("X-Real-IP", c.IP())

		// Execute request
		resp, err := p.client.Do(req)
		if err != nil {
			log.Printf("❌ Error proxying request: %v", err)
			return c.Status(502).JSON(fiber.Map{"error": "Service unavailable", "details": err.Error()})
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				c.Set(key, value)
			}
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("❌ Error reading response body: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to read response"})
		}

		return c.Status(resp.StatusCode).Send(body)
	}
}
