# Nmap Scanner - Advanced Network Security Tool

Sistema completo de escaneo de redes con interfaz web, construido con Nmap, FastAPI y React.

## Características

- **Interfaz Web Moderna**: Interfaz React intuitiva para configurar y visualizar escaneos
- **Motor de Escaneo Potente**: Aprovecha todas las capacidades de Nmap
- **Múltiples Tipos de Escaneo**: Quick, Full, Service Detection, Stealth, Vulnerability, UDP, Aggressive
- **Informes Detallados**: Exportación en JSON, HTML y CSV
- **Escaneos Asíncronos**: Procesamiento en background con seguimiento en tiempo real
- **Base de Datos PostgreSQL**: Almacenamiento persistente de resultados
- **Arquitectura de Microservicios**: Desplegable con Docker Compose

## Arquitectura

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   React     │─────▶│   FastAPI   │─────▶│  PostgreSQL │
│  Frontend   │      │   Backend   │      │  Database   │
└─────────────┘      └─────────────┘      └─────────────┘
                           │
                           ▼
                     ┌─────────────┐
                     │    Redis    │
                     │   Cache     │
                     └─────────────┘
                           │
                           ▼
                     ┌─────────────┐
                     │    Nmap     │
                     │   Engine    │
                     └─────────────┘
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
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

## Estructura del Proyecto

```
scaner_nmap/
├── docker-compose.yaml       # Configuración de servicios Docker
├── backend/                  # Backend FastAPI
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py          # Aplicación principal
│       ├── api/             # Endpoints REST
│       │   ├── scans.py     # API de escaneos
│       │   ├── templates.py # API de plantillas
│       │   └── reports.py   # API de informes
│       ├── models/          # Modelos de base de datos
│       │   └── scan.py
│       ├── services/        # Lógica de negocio
│       │   └── scanner.py   # Motor de escaneo Nmap
│       └── core/            # Configuración
│           ├── config.py
│           └── database.py
├── frontend/                # Frontend React
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── src/
│       ├── App.js
│       ├── components/      # Componentes React
│       ├── pages/           # Páginas
│       └── services/        # Servicios API
└── database/
    └── init.sql            # Schema inicial
```

## Uso

### Crear un Nuevo Escaneo

1. Navega a "New Scan"
2. Configura el escaneo:
   - **Name**: Nombre descriptivo del escaneo
   - **Target**: IP, hostname, CIDR (ej: 192.168.1.0/24)
   - **Scan Type**: Selecciona un tipo predefinido
   - **Nmap Arguments**: Argumentos personalizados (opcional)
3. Click en "Start Scan"

### Tipos de Escaneo Disponibles

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

### Ver Resultados

1. En el Dashboard, click en "View Details" de un escaneo
2. Visualiza:
   - **Results**: Hosts descubiertos, puertos abiertos, servicios
   - **Logs**: Registro detallado del escaneo
3. Descarga informes en formato JSON, CSV o HTML

## API Endpoints

### Scans

```
POST   /api/scans/              - Crear nuevo escaneo
GET    /api/scans/              - Listar escaneos
GET    /api/scans/{id}          - Obtener detalles de escaneo
GET    /api/scans/{id}/results  - Obtener resultados
GET    /api/scans/{id}/logs     - Obtener logs
DELETE /api/scans/{id}          - Eliminar escaneo
POST   /api/scans/{id}/cancel   - Cancelar escaneo
```

### Templates

```
GET    /api/templates/          - Listar plantillas
GET    /api/templates/builtin   - Plantillas predefinidas
GET    /api/templates/{id}      - Obtener plantilla
```

### Reports

```
GET    /api/reports/{id}/json   - Informe JSON
GET    /api/reports/{id}/html   - Informe HTML
GET    /api/reports/{id}/csv    - Informe CSV
```

## Configuración

### Variables de Entorno

Edita `docker-compose.yaml` para personalizar:

```yaml
environment:
  DATABASE_URL: postgresql://user:pass@database:5432/nmap_scanner
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
3. Configura CORS en `backend/app/core/config.py`
4. Habilita HTTPS con certificados SSL

## Monitoreo

### Ver logs de servicios

```bash
# Todos los servicios
docker-compose logs -f

# Backend
docker-compose logs -f backend

# Frontend
docker-compose logs -f frontend

# Base de datos
docker-compose logs -f database
```

### Estado de servicios

```bash
docker-compose ps
```

## Detener y Reiniciar

```bash
# Detener servicios
docker-compose down

# Detener y eliminar volúmenes (¡cuidado! elimina la BD)
docker-compose down -v

# Reiniciar servicios
docker-compose restart

# Reconstruir servicios
docker-compose up -d --build
```

## Desarrollo

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
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

Verifica que el servicio de PostgreSQL esté corriendo:

```bash
docker-compose ps database
docker-compose logs database
```

### Frontend no puede conectar al backend

Verifica la variable `REACT_APP_API_URL` en el frontend y que CORS esté configurado correctamente en el backend.

## Advertencias de Seguridad

- Este sistema ejecuta Nmap con privilegios elevados
- Solo úsalo en redes autorizadas
- Los escaneos de red pueden ser detectados por sistemas IDS/IPS
- Cumple con las leyes y políticas de seguridad locales
- No escanees redes sin autorización explícita

## Licencia

MIT License

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o pull request.

## Soporte

Para reportar bugs o solicitar características, abre un issue en el repositorio.
