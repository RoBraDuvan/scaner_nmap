package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Database struct {
	Pool *pgxpool.Pool
}

func NewDatabase(databaseURL string) (*Database, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database URL: %w", err)
	}

	// Retry logic with exponential backoff
	maxRetries := 10
	var pool *pgxpool.Pool

	for i := 0; i < maxRetries; i++ {
		pool, err = pgxpool.NewWithConfig(context.Background(), config)
		if err != nil {
			waitTime := time.Duration(1<<uint(i)) * time.Second
			if waitTime > 30*time.Second {
				waitTime = 30 * time.Second
			}
			log.Printf("Failed to create connection pool (attempt %d/%d): %v. Retrying in %v...", i+1, maxRetries, err, waitTime)
			time.Sleep(waitTime)
			continue
		}

		// Test connection
		err = pool.Ping(context.Background())
		if err == nil {
			break
		}

		pool.Close()
		waitTime := time.Duration(1<<uint(i)) * time.Second
		if waitTime > 30*time.Second {
			waitTime = 30 * time.Second
		}
		log.Printf("Failed to ping database (attempt %d/%d): %v. Retrying in %v...", i+1, maxRetries, err, waitTime)
		time.Sleep(waitTime)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
	}

	log.Println("Connected to PostgreSQL database")

	return &Database{Pool: pool}, nil
}

func (db *Database) Close() {
	db.Pool.Close()
}
