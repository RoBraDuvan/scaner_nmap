# Security Scanner - Network & Vulnerability Scanner

Sistema completo de escaneo de redes y detección de vulnerabilidades con interfaz web moderna.

## Características

### Network Scanning (Nmap)
- **Múltiples Tipos de Escaneo**: Quick, Full, Service Detection, Stealth, Vulnerability, UDP, Aggressive
- **Detección de Servicios y OS**: Identificación automática de servicios y sistemas operativos
- **Detección de Fabricante MAC**: Identifica fabricantes de dispositivos de red
- **Informes Detallados**: Exportación en JSON, HTML y CSV

### Vulnerability Scanning (Nuclei)
- **Escaneo de Vulnerabilidades**: Detección de CVEs, misconfigurations y más
- **Templates Personalizables**: Filtrado por tags (cve, xss, sqli, wordpress, etc.)
- **Filtro por Severidad**: Critical, High, Medium, Low, Info
- **Resultados Detallados**: Request/Response HTTP, comandos cURL reproducibles

### General
- **Dashboard Centralizado**: Vista general de todos los escaneos y estadísticas
- **Interfaz Web Moderna**: React con diseño intuitivo y responsivo
- **Escaneos Asíncronos**: Procesamiento en background con seguimiento en tiempo real
- **Base de Datos PostgreSQL**: Almacenamiento persistente de resultados
- **Arquitectura de Microservicios**: Desplegable con Docker Compose

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend                              │
│                    React (Port 3000)                         │
└─────────────────────┬───────────────────────┬───────────────┘
                      │                       │
                      ▼                       ▼
┌─────────────────────────────┐   ┌─────────────────────────────┐
│     Python Backend          │   │       Go Backend            │
│   FastAPI (Port 8000)       │   │      Fiber (Port 8001)      │
│   - Network Scans (Nmap)    │   │   - Vulnerability Scans     │
│   - Templates               │   │   - Nuclei Integration      │
│   - Reports                 │   │   - High Performance        │
└─────────────┬───────────────┘   └─────────────┬───────────────┘
              │                                 │
              ▼                                 ▼
┌─────────────────────────────────────────────────────────────┐
│                      PostgreSQL                              │
│                    Database (Port 5432)                      │
└─────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────┐
│                         Redis                                │
│                    Cache (Port 6379)                         │
└─────────────────────────────────────────────────────────────┘
```

## Requisitos Previos

- Docker
- Docker Compose
- Git

## Instalación y Despliegue

### 1. Clonar el repositorio

```bash
git clone <repository-url>
cd scaner_nmap
```

### 2. Iniciar servicios con Docker Compose

```bash
docker-compose up -d
```

### 3. Acceder a la aplicación

- **Frontend**: http://localhost:3000
- **Python Backend API**: http://localhost:8000
- **Go Backend API**: http://localhost:8001
- **API Docs (Python)**: http://localhost:8000/docs

## Estructura del Proyecto

```
scaner_nmap/
├── docker-compose.yaml          # Configuración de servicios Docker
├── backend/                     # Backend Python (FastAPI)
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py              # Aplicación principal
│       ├── api/                 # Endpoints REST
│       │   ├── scans.py         # API de escaneos de red
│       │   ├── templates.py     # API de plantillas Nmap
│       │   ├── reports.py       # API de informes
│       │   └── vulnerability_templates.py  # Templates de vulnerabilidades
│       ├── models/              # Modelos de base de datos
│       ├── services/            # Lógica de negocio
│       │   └── scanner.py       # Motor de escaneo Nmap
│       └── core/                # Configuración
│           ├── config.py
│           └── database.py
├── backend-go/                  # Backend Go (Fiber)
│   ├── Dockerfile
│   ├── go.mod
│   └── cmd/server/main.go       # Servidor principal
│   └── internal/
│       ├── api/handlers/        # Handlers HTTP
│       │   └── vulnerabilities.go
│       ├── models/              # Modelos
│       │   └── vulnerability.go
│       └── scanner/             # Scanners
│           └── nuclei.go        # Integración Nuclei
├── frontend/                    # Frontend React
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── src/
│       ├── App.js
│       ├── components/          # Componentes React
│       │   └── Header.js
│       ├── pages/               # Páginas
│       │   ├── Dashboard.js     # Dashboard principal
│       │   ├── NetworkScans.js  # Lista de scans de red
│       │   ├── NewScan.js       # Crear scan de red
│       │   ├── ScanDetails.js   # Detalles de scan de red
│       │   ├── Vulnerabilities.js    # Lista de scans de vulnerabilidades
│       │   ├── NewVulnScan.js        # Crear scan de vulnerabilidades
│       │   ├── VulnScanDetails.js    # Detalles de vulnerabilidades
│       │   └── Templates.js     # Plantillas Nmap
│       └── services/            # Servicios API
└── database/
    └── init.sql                 # Schema inicial con tablas y templates
```

## Uso

### Dashboard Principal

El dashboard muestra:
- Estadísticas de Network Scans y Vulnerability Scans
- Acciones rápidas para crear nuevos scans
- Lista de scans recientes

### Network Scans (Nmap)

1. Navega a "Network Scans" → "New Scan"
2. Configura el escaneo:
   - **Name**: Nombre descriptivo del escaneo
   - **Target**: IP, hostname, CIDR (ej: 192.168.1.0/24)
   - **Scan Type**: Selecciona un tipo predefinido
   - **Nmap Arguments**: Argumentos personalizados (opcional)
3. Click en "Start Scan"

#### Tipos de Escaneo de Red

| Tipo | Descripción | Argumentos |
|------|-------------|------------|
| **Quick** | Escaneo rápido de los 100 puertos más comunes | `-F -T4` |
| **Full** | Escaneo completo de todos los 65535 puertos | `-p- -T4` |
| **Service** | Detección de servicios y OS | `-sV -O -T4` |
| **Stealth** | Escaneo sigiloso SYN | `-sS -T2 -f` |
| **Vulnerability** | Escaneo con scripts NSE de vulnerabilidades | `-sV --script vuln -T4` |
| **Ping Sweep** | Descubrimiento de hosts activos | `-sn -T4` |
| **UDP** | Escaneo de puertos UDP comunes | `-sU --top-ports 100 -T4` |
| **Aggressive** | Escaneo agresivo completo | `-A -T4` |

### Vulnerability Scans (Nuclei)

1. Navega a "Vulnerabilities" → "New Vuln Scan"
2. Configura el escaneo:
   - **Name**: Nombre descriptivo
   - **Target**: URL o IP (ej: https://example.com)
   - **Severity**: Selecciona niveles de severidad a buscar
   - **Tags**: Filtra por tags de Nuclei (ej: cve, xss, sqli, jenkins, wordpress)
3. Click en "Start Vulnerability Scan"

#### Templates de Vulnerabilidades Predefinidos

| Categoría | Templates |
|-----------|-----------|
| **Discovery** | Web Technologies, Exposed Panels |
| **Vulnerability** | CVE Detection, OWASP Top 10 |
| **CMS** | WordPress Security, Joomla Security |
| **Injection** | SQL Injection, XSS Detection |
| **Network** | Network Services, Default Credentials |

## API Endpoints

### Network Scans (Python Backend - Port 8000)

```
POST   /api/scans/              - Crear nuevo escaneo de red
GET    /api/scans/              - Listar escaneos
GET    /api/scans/{id}          - Obtener detalles de escaneo
GET    /api/scans/{id}/results  - Obtener resultados
GET    /api/scans/{id}/logs     - Obtener logs
DELETE /api/scans/{id}          - Eliminar escaneo
POST   /api/scans/{id}/cancel   - Cancelar escaneo
```

### Templates (Python Backend)

```
GET    /api/templates/          - Listar plantillas personalizadas
GET    /api/templates/builtin   - Plantillas predefinidas de Nmap
GET    /api/vulnerability-templates/  - Templates de vulnerabilidades
```

### Reports (Python Backend)

```
GET    /api/reports/{id}/json   - Informe JSON
GET    /api/reports/{id}/html   - Informe HTML
GET    /api/reports/{id}/csv    - Informe CSV
```

### Vulnerability Scans (Go Backend - Port 8001)

```
POST   /api/vulnerabilities/              - Crear scan de vulnerabilidades
GET    /api/vulnerabilities/              - Listar scans
GET    /api/vulnerabilities/{id}          - Obtener detalles
GET    /api/vulnerabilities/{id}/results  - Obtener vulnerabilidades encontradas
GET    /api/vulnerabilities/{id}/logs     - Obtener logs
GET    /api/vulnerabilities/{id}/stats    - Estadísticas por severidad
DELETE /api/vulnerabilities/{id}          - Eliminar scan
POST   /api/vulnerabilities/{id}/cancel   - Cancelar scan
```

## Configuración

### Variables de Entorno

Edita `docker-compose.yaml` para personalizar:

```yaml
environment:
  DATABASE_URL: postgresql://scanner_user:scanner_pass_2024@database:5432/nmap_scanner
  REDIS_URL: redis://redis:6379/0
  SECRET_KEY: your-secret-key
  ENVIRONMENT: production
```

### Base de Datos

- **Host**: localhost:5432
- **Database**: nmap_scanner
- **User**: scanner_user
- **Password**: scanner_pass_2024

### Seguridad

Para producción:
1. Cambia `SECRET_KEY` en variables de entorno
2. Actualiza las credenciales de la base de datos
3. Configura CORS en los backends
4. Habilita HTTPS con certificados SSL

## Monitoreo

### Ver logs de servicios

```bash
# Todos los servicios
docker-compose logs -f

# Backend Python
docker-compose logs -f backend

# Backend Go
docker-compose logs -f backend-go

# Frontend
docker-compose logs -f frontend

# Base de datos
docker-compose logs -f database
```

### Estado de servicios

```bash
docker-compose ps
```

## Comandos Útiles

```bash
# Detener servicios
docker-compose down

# Detener y eliminar volúmenes (¡cuidado! elimina la BD)
docker-compose down -v

# Reiniciar servicios
docker-compose restart

# Reconstruir servicios
docker-compose up -d --build

# Reconstruir un servicio específico
docker-compose build frontend && docker-compose up -d frontend
```

## Desarrollo

### Backend Python

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Backend Go

```bash
cd backend-go
go mod download
go run cmd/server/main.go
```

### Frontend

```bash
cd frontend
npm install
npm start
```

## Solución de Problemas

### Error: Permission denied para Nmap

El backend necesita privilegios especiales para ejecutar Nmap. Asegúrate de que el contenedor tenga `privileged: true` y `cap_add: NET_ADMIN, NET_RAW`.

### Base de datos no conecta

```bash
docker-compose ps database
docker-compose logs database
```

### Nuclei no encuentra vulnerabilidades

- Asegúrate de usar tags específicos (ej: `jenkins`, `wordpress`, `cve`)
- Sin tags, Nuclei ejecuta todos los templates y puede no encontrar coincidencias
- Verifica que el target sea accesible

### Frontend no puede conectar al backend

Verifica las variables de entorno `REACT_APP_API_URL` y `REACT_APP_GO_API_URL` y que CORS esté configurado correctamente.

## Advertencias de Seguridad

- Este sistema ejecuta Nmap y Nuclei con privilegios elevados
- Solo úsalo en redes y sistemas autorizados
- Los escaneos pueden ser detectados por sistemas IDS/IPS
- Cumple con las leyes y políticas de seguridad locales
- **No escanees redes o sistemas sin autorización explícita**

## Tecnologías

- **Frontend**: React, React Router, Axios, date-fns
- **Backend Python**: FastAPI, SQLAlchemy, asyncpg, python-nmap
- **Backend Go**: Fiber, pgx, Nuclei
- **Base de Datos**: PostgreSQL 15
- **Cache**: Redis 7
- **Contenedores**: Docker, Docker Compose

## Licencia

MIT License

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o pull request.
