# Nmap Scanner Backend (Go)

High-performance Go backend for the Nmap Scanner application.

## Features

- ⚡ **Fast**: Built with Go and Fiber framework
- 🔍 **Dual Nmap Support**: Use gonmap library or system nmap
- 🐳 **Containerized**: Ready for Docker deployment
- 💾 **PostgreSQL**: Robust database storage
- 🔄 **Redis**: Caching and queue support

## Technology Stack

- **Framework**: Fiber v2 (Express-inspired web framework)
- **Database**: PostgreSQL with pgx driver
- **Cache**: Redis with go-redis
- **Scanner**: Ullaakut/nmap (gonmap) or system nmap
- **UUID**: Google UUID

## Environment Variables

- `PORT`: Server port (default: 8001)
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `USE_SYSTEM_NMAP`: Use system nmap instead of gonmap (default: false)
- `NMAP_PATH`: Path to system nmap binary (default: /usr/bin/nmap)
- `ENVIRONMENT`: Environment mode (development/production)
- `SECRET_KEY`: Application secret key

## Running Locally

```bash
# Install dependencies
go mod download

# Run the server
go run cmd/server/main.go
```

## Running with Docker

```bash
# Build image
docker build -t nmap-scanner-go .

# Run container
docker run -p 8001:8001 nmap-scanner-go
```

## API Endpoints

### Scans
- `GET /api/scans` - List all scans
- `POST /api/scans` - Create and start a new scan
- `GET /api/scans/:id` - Get scan details
- `GET /api/scans/:id/results` - Get scan results
- `GET /api/scans/:id/logs` - Get scan logs

### Templates
- `GET /api/templates` - List all templates
- `POST /api/templates` - Create a new template
- `GET /api/templates/:id` - Get template details
- `PUT /api/templates/:id` - Update a template
- `DELETE /api/templates/:id` - Delete a template

### Health
- `GET /health` - Health check endpoint

## Performance

Go backend offers significant performance improvements:
- **Faster startup time**: ~100ms vs ~2s (Python)
- **Lower memory usage**: ~20MB vs ~50MB (Python)
- **Better concurrency**: Goroutines vs threads
- **Faster response times**: Native compilation benefits
