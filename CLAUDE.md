# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security Scanner Platform - A microservices-based security scanning tool with multiple scanning capabilities including network scanning (Nmap), vulnerability detection (Nuclei), web analysis, reconnaissance, API discovery, and CMS detection.

**Everything runs in Docker containers.** No local installation of tools is required.

## Common Commands

### Start/Stop Services
```bash
# Start all services
docker-compose up -d

# Start with rebuild
docker-compose up -d --build

# Stop all services
docker-compose down

# Rebuild specific service
docker-compose build <service-name>
docker-compose up -d <service-name>

# View logs
docker-compose logs -f
docker-compose logs -f <service-name>

# Restart a service
docker-compose restart <service-name>
```

### Service Names
- `gateway` - API Gateway (port 8000)
- `network-service` - Nmap/Masscan/DNS (port 8001)
- `web-service` - Nuclei/ffuf/testssl (port 8002)
- `recon-service` - Subfinder/Amass (port 8003)
- `api-service` - Kiterunner/Arjun (port 8004)
- `cms-service` - WhatWeb/CMSeeK/WPScan (port 8005)
- `frontend` - React UI (port 3000)
- `database` - PostgreSQL (port 5432)
- `redis` - Redis cache (port 6379)

### Access Points
- Frontend UI: http://localhost:3000
- API Gateway: http://localhost:8000
- Health Check: http://localhost:8000/health

### Database Access
```bash
docker-compose exec database psql -U scanner_user -d nmap_scanner
```

## Architecture

```
Frontend (React:3000)
         │
         ▼
    API Gateway (Go/Fiber:8000)
         │
    ┌────┴────┬─────┬─────┬─────┐
    ▼         ▼     ▼     ▼     ▼
 Network   Web   Recon  API   CMS
  8001    8002   8003  8004  8005
    │         │     │     │     │
    └────┬────┴─────┴─────┴─────┘
         ▼
   PostgreSQL + Redis
```

### Gateway Routing
Routes defined in `services/gateway/cmd/server/main.go`:
- `/api/scans/*` → Network Service
- `/api/vulnerabilities/*` → Web Service
- `/api/webscans/*` → Web Service
- `/api/recon/*` → Recon Service
- `/api/apiscans/*` → API Service
- `/api/cmsscans/*` → CMS Service
- `/api/templates/*` → Network Service

## Technology Stack

| Component | Technology |
|-----------|------------|
| Backend Services | Go 1.21 with Fiber v2 (CMS uses Gin) |
| Frontend | React 18, React Router v6, Axios |
| Database | PostgreSQL 15 with pgx driver |
| Cache | Redis |
| Container | Docker with multi-stage builds |

## Project Structure

```
├── docker-compose.yaml      # Service orchestration
├── database/
│   └── init.sql             # Schema and default templates
├── services/
│   ├── gateway/             # API routing
│   ├── network/             # Nmap, Masscan, DNS
│   ├── web/                 # Nuclei, ffuf, testssl
│   ├── recon/               # Subfinder, Amass
│   ├── api/                 # Kiterunner, Arjun
│   └── cms/                 # WhatWeb, CMSeeK, WPScan
└── frontend/
    └── src/
        ├── pages/           # React page components
        ├── components/      # Shared components
        └── services/api.js  # Axios HTTP client
```

## Adding a New Microservice

1. Create `services/newservice/` with Go module structure:
   ```
   services/newservice/
   ├── cmd/server/main.go
   ├── internal/
   │   ├── handlers/
   │   ├── database/
   │   └── models/
   ├── Dockerfile
   └── go.mod
   ```

2. Add to `docker-compose.yaml`:
   ```yaml
   newservice:
     build: ./services/newservice
     environment:
       - DATABASE_URL=...
     depends_on:
       database: { condition: service_healthy }
   ```

3. Add gateway routes in `services/gateway/cmd/server/main.go`

4. Create frontend pages in `frontend/src/pages/`

5. Add routes in `frontend/src/App.js`

## Key Patterns

### Backend Service Structure (Go)
```go
// cmd/server/main.go
app := fiber.New()
app.Use(recover.New())
app.Use(cors.New())

db := database.NewDatabase(os.Getenv("DATABASE_URL"))
handler := handlers.NewHandler(db)

app.Get("/scans", handler.ListScans)
app.Post("/scans", handler.CreateScan)
```

### Frontend API Calls
```javascript
// services/api.js exports configured axios instance
import api from '../services/api';
const response = await api.get('/scans/');
```

### Database Models
- Use UUID for primary keys
- JSONB for flexible configuration fields
- Status enum: `pending`, `running`, `completed`, `failed`, `cancelled`

## Environment Variables

Key variables in `.env`:
```
DATABASE_URL=postgresql://scanner_user:scanner_pass_2024@database:5432/nmap_scanner
REDIS_URL=redis://redis:6379/0
```

## Notes

- Network service runs with `privileged: true` for Nmap raw socket access
- All services share the same PostgreSQL database
- Frontend proxies API calls through the gateway
- Scanner tools are installed in Docker images, not locally
