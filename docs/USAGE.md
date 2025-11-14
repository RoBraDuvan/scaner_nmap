# Guía de Uso - Nmap Scanner

## Comandos Rápidos

### Iniciar el Sistema

```bash
docker-compose up -d
```

### Ver Estado de Servicios

```bash
docker-compose ps
```

### Ver Logs en Tiempo Real

```bash
# Todos los servicios
docker-compose logs -f

# Solo backend
docker-compose logs -f backend

# Solo frontend
docker-compose logs -f frontend
```

### Detener el Sistema

```bash
docker-compose down
```

### Reiniciar Servicios

```bash
# Reiniciar todos
docker-compose restart

# Reiniciar uno específico
docker-compose restart backend
```

## Acceso a la Aplicación

| Servicio | URL | Descripción |
|----------|-----|-------------|
| Frontend | http://localhost:3000 | Interfaz web principal |
| Backend API | http://localhost:8000 | API REST |
| API Docs | http://localhost:8000/docs | Documentación Swagger |
| PostgreSQL | localhost:5432 | Base de datos |
| Redis | localhost:6379 | Cache |

## Realizar Escaneos

### 1. Desde la Interfaz Web

1. Navegar a http://localhost:3000
2. Click en "New Scan"
3. Completar formulario:
   - **Name**: Nombre del escaneo
   - **Target**: IP o red (ej: 192.168.1.0/24)
   - **Scan Type**: Seleccionar tipo
4. Click "Start Scan"
5. Ver progreso en el Dashboard
6. Click "View Details" para ver resultados

### 2. Desde la API (curl)

```bash
# Crear escaneo
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Network Scan",
    "target": "192.168.1.0/24",
    "scan_type": "quick"
  }'

# Listar escaneos
curl http://localhost:8000/api/scans/

# Ver detalles de escaneo
curl http://localhost:8000/api/scans/{scan_id}

# Ver resultados
curl http://localhost:8000/api/scans/{scan_id}/results

# Descargar informe JSON
curl http://localhost:8000/api/reports/{scan_id}/json > report.json

# Descargar informe HTML
curl http://localhost:8000/api/reports/{scan_id}/html > report.html

# Descargar informe CSV
curl http://localhost:8000/api/reports/{scan_id}/csv > report.csv
```

### 3. Desde Python

```python
import requests

API_URL = "http://localhost:8000/api"

# Crear escaneo
scan_data = {
    "name": "My Network Scan",
    "target": "192.168.1.0/24",
    "scan_type": "service"
}

response = requests.post(f"{API_URL}/scans/", json=scan_data)
scan = response.json()
scan_id = scan["id"]

print(f"Scan created: {scan_id}")

# Ver estado
import time
while True:
    response = requests.get(f"{API_URL}/scans/{scan_id}")
    scan = response.json()
    print(f"Status: {scan['status']} - Progress: {scan['progress']}%")

    if scan["status"] in ["completed", "failed"]:
        break

    time.sleep(5)

# Obtener resultados
response = requests.get(f"{API_URL}/scans/{scan_id}/results")
results = response.json()

for result in results:
    print(f"\nHost: {result['host']}")
    print(f"State: {result['state']}")
    print(f"Ports: {len(result.get('ports', []))}")
```

## Tipos de Escaneo

### Quick Scan
```bash
Target: scanme.nmap.org
Tipo: quick
Duración: 1-5 minutos
Uso: Escaneo rápido inicial
```

### Full Port Scan
```bash
Target: 192.168.1.100
Tipo: full
Duración: 30-60 minutos
Uso: Escaneo exhaustivo de todos los puertos
```

### Service Detection
```bash
Target: 192.168.1.0/24
Tipo: service
Duración: 5-15 minutos
Uso: Identificar servicios y versiones
```

### Vulnerability Scan
```bash
Target: 192.168.1.100
Tipo: vulnerability
Duración: 15-30 minutos
Uso: Detección de vulnerabilidades conocidas
```

### Stealth Scan
```bash
Target: 192.168.1.100
Tipo: stealth
Duración: 10-20 minutos
Uso: Escaneo sigiloso SYN
```

### UDP Scan
```bash
Target: 192.168.1.100
Tipo: udp
Duración: 10-20 minutos
Uso: Escanear puertos UDP comunes
```

### Aggressive Scan
```bash
Target: 192.168.1.100
Tipo: aggressive
Duración: 20-40 minutos
Uso: Escaneo completo con OS detection, scripts, traceroute
```

### Ping Sweep
```bash
Target: 192.168.1.0/24
Tipo: ping
Duración: 1-5 minutos
Uso: Descubrir hosts activos
```

## Ejemplos de Targets

```bash
# IP única
scanme.nmap.org
192.168.1.1

# Rango de IPs
192.168.1.1-50

# Red completa (CIDR)
192.168.1.0/24
10.0.0.0/16

# Múltiples hosts
192.168.1.1,192.168.1.10,192.168.1.20

# Archivo con lista de hosts
file:/path/to/hosts.txt
```

## Exportar Informes

### JSON
```bash
# Desde interfaz web
Dashboard > View Details > Download JSON

# Desde API
curl http://localhost:8000/api/reports/{scan_id}/json > scan_report.json
```

### HTML
```bash
# Desde interfaz web
Dashboard > View Details > Download HTML

# Desde API
curl http://localhost:8000/api/reports/{scan_id}/html > scan_report.html
```

### CSV
```bash
# Desde interfaz web
Dashboard > View Details > Download CSV

# Desde API
curl http://localhost:8000/api/reports/{scan_id}/csv > scan_report.csv
```

## Gestión de Base de Datos

### Acceso Directo a PostgreSQL

```bash
# Conectar a la base de datos
docker-compose exec database psql -U scanner_user -d nmap_scanner

# Ver escaneos
SELECT id, name, status, created_at FROM scans ORDER BY created_at DESC LIMIT 10;

# Ver resultados de un escaneo
SELECT host, state, ports FROM scan_results WHERE scan_id = 'uuid-here';

# Eliminar escaneos antiguos
DELETE FROM scans WHERE created_at < NOW() - INTERVAL '30 days';
```

### Backup Manual

```bash
# Crear backup
docker-compose exec database pg_dump -U scanner_user nmap_scanner > backup_$(date +%Y%m%d_%H%M%S).sql

# Restaurar backup
docker-compose exec -T database psql -U scanner_user nmap_scanner < backup_20240101_120000.sql
```

## Solución de Problemas Comunes

### Backend no inicia

```bash
# Ver logs
docker-compose logs backend

# Verificar que la BD esté lista
docker-compose ps database

# Reiniciar backend
docker-compose restart backend
```

### Frontend no carga

```bash
# Ver logs
docker-compose logs frontend

# Verificar que nginx esté corriendo
docker-compose ps frontend

# Reconstruir frontend
docker-compose up -d --build frontend
```

### Escaneo se queda en "pending"

```bash
# Verificar logs del backend
docker-compose logs -f backend

# Verificar privilegios del contenedor
docker inspect nmap_scanner_backend | grep -i privileged

# Reiniciar backend
docker-compose restart backend
```

### Error de permisos de Nmap

```bash
# El backend necesita privilegios especiales
# Verificar en docker-compose.yaml:
privileged: true
cap_add:
  - NET_ADMIN
  - NET_RAW
```

### Base de datos no conecta

```bash
# Verificar estado
docker-compose ps database

# Ver logs
docker-compose logs database

# Reiniciar
docker-compose restart database
```

## Mejores Prácticas

### Seguridad

1. **Solo escanear redes autorizadas**
2. **Cambiar credenciales por defecto en producción**
3. **Habilitar HTTPS para producción**
4. **Configurar firewall apropiadamente**
5. **Limitar acceso a la API**

### Rendimiento

1. **Usar "Quick Scan" para pruebas iniciales**
2. **Evitar escaneos completos en redes grandes**
3. **Programar escaneos pesados fuera de horario pico**
4. **Limpiar escaneos antiguos regularmente**

### Targets

1. **scanme.nmap.org** - Servidor de prueba oficial
2. **Redes internas** - Solo con autorización
3. **CIDR pequeños** - Para escaneos completos (/24 máximo)
4. **IPs específicas** - Para análisis detallado

## Comandos Útiles

```bash
# Ver todos los contenedores
docker-compose ps

# Ver uso de recursos
docker stats

# Limpiar todo (¡cuidado! elimina datos)
docker-compose down -v

# Ver configuración
docker-compose config

# Reconstruir todo
docker-compose up -d --build

# Ver versión de nmap en el contenedor
docker-compose exec backend nmap --version

# Ejecutar comando en contenedor
docker-compose exec backend /bin/bash
```

## Monitoreo

### Health Checks

```bash
# Backend health
curl http://localhost:8000/health

# Database health
docker-compose exec database pg_isready -U scanner_user

# Redis health
docker-compose exec redis redis-cli ping
```

### Métricas

```bash
# Ver estadísticas de contenedores
docker stats nmap_scanner_backend nmap_scanner_frontend nmap_scanner_db

# Ver logs de errores
docker-compose logs | grep -i error

# Ver escaneos activos
curl http://localhost:8000/api/scans/?status=running
```

## Soporte

Para reportar issues o solicitar funcionalidades:
- Crear issue en el repositorio
- Consultar la documentación completa en [README.md](README.md)
- Ver guía de despliegue en [DEPLOYMENT.md](DEPLOYMENT.md)
