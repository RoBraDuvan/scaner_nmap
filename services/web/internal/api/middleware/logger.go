package middleware

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Logger returns a logging middleware
func Logger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process request
		err := c.Next()

		// Log the request
		log.Printf("[WEB] %s %s %d %v",
			c.Method(),
			c.Path(),
			c.Response().StatusCode(),
			time.Since(start),
		)

		return err
	}
}
