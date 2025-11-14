# Guía de Despliegue - Nmap Scanner

## Despliegue Rápido con Docker Compose

### 1. Verificar Requisitos

```bash
# Verificar Docker
docker --version

# Verificar Docker Compose
docker-compose --version
```

### 2. Configurar Variables de Entorno

```bash
# Copiar archivo de ejemplo
cp .env.example .env

# Editar variables (IMPORTANTE: cambiar SECRET_KEY y passwords en producción)
nano .env
```

### 3. Iniciar Servicios

```bash
# Construir e iniciar todos los servicios
docker-compose up -d --build

# Verificar que todos los servicios estén corriendo
docker-compose ps
```

### 4. Verificar Salud de Servicios

```bash
# Backend health check
curl http://localhost:8000/health

# Ver logs
docker-compose logs -f
```

### 5. Acceder a la Aplicación

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

## Despliegue en Producción

### Configuración de Seguridad

1. **Cambiar Credenciales**

Edita `docker-compose.yaml`:

```yaml
environment:
  POSTGRES_PASSWORD: <strong-password>
  SECRET_KEY: <generate-secure-key>
```

2. **Generar SECRET_KEY Segura**

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

3. **Configurar CORS**

Edita `backend/app/core/config.py`:

```python
CORS_ORIGINS: List[str] = [
    "https://yourdomain.com",
]
```

4. **Habilitar HTTPS**

Usa un reverse proxy como Nginx o Traefik con certificados SSL.

### Ejemplo con Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name scanner.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name scanner.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Frontend
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # API Docs
    location /docs {
        proxy_pass http://localhost:8000;
    }
}
```

### Optimizaciones de Rendimiento

1. **Límites de Recursos**

Edita `docker-compose.yaml`:

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

2. **Escalado de Workers**

```yaml
  backend:
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Backup de Base de Datos

```bash
# Backup
docker-compose exec database pg_dump -U scanner_user nmap_scanner > backup_$(date +%Y%m%d).sql

# Restore
docker-compose exec -T database psql -U scanner_user nmap_scanner < backup_20240101.sql
```

## Despliegue en Cloud

### AWS (EC2 + RDS)

1. Lanzar EC2 instance (Ubuntu 22.04)
2. Instalar Docker y Docker Compose
3. Configurar RDS PostgreSQL
4. Actualizar `DATABASE_URL` con endpoint de RDS
5. Configurar Security Groups para puertos 3000 y 8000

### Google Cloud (GCE + Cloud SQL)

1. Crear VM instance
2. Crear Cloud SQL PostgreSQL instance
3. Configurar Cloud SQL Proxy
4. Desplegar con Docker Compose

### Digital Ocean

1. Crear Droplet con Docker pre-instalado
2. Configurar Managed PostgreSQL Database
3. Actualizar variables de entorno
4. Desplegar aplicación

## Monitoreo y Logs

### Logs Centralizados

```bash
# Ver logs en tiempo real
docker-compose logs -f

# Logs de un servicio específico
docker-compose logs -f backend

# Últimas 100 líneas
docker-compose logs --tail=100
```

### Métricas con Prometheus

Agrega a `docker-compose.yaml`:

```yaml
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
```

## Actualización de Versiones

```bash
# Pull latest changes
git pull

# Rebuild containers
docker-compose down
docker-compose up -d --build

# Verificar servicios
docker-compose ps
```

## Rollback

```bash
# Detener servicios actuales
docker-compose down

# Checkout versión anterior
git checkout <previous-version>

# Reiniciar servicios
docker-compose up -d --build
```

## Troubleshooting

### Servicio no inicia

```bash
# Ver logs del servicio
docker-compose logs <service-name>

# Reiniciar servicio específico
docker-compose restart <service-name>
```

### Base de datos corrupta

```bash
# Detener servicios
docker-compose down

# Eliminar volumen (¡cuidado!)
docker volume rm scaner_nmap_postgres_data

# Reiniciar
docker-compose up -d
```

### Problemas de permisos Nmap

Asegúrate de que el backend tenga:

```yaml
  backend:
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
```

## Mantenimiento

### Limpieza de Recursos

```bash
# Eliminar escaneos antiguos (en database)
docker-compose exec database psql -U scanner_user -d nmap_scanner -c "DELETE FROM scans WHERE created_at < NOW() - INTERVAL '30 days';"

# Limpiar imágenes Docker no usadas
docker system prune -a

# Limpiar volúmenes no usados
docker volume prune
```

### Rotación de Logs

Configura logrotate para logs de Docker:

```bash
/var/lib/docker/containers/*/*.log {
    rotate 7
    daily
    compress
    missingok
    delaycompress
    copytruncate
}
```

## Checklist Pre-Producción

- [ ] Cambiar todas las contraseñas por defecto
- [ ] Generar SECRET_KEY segura
- [ ] Configurar CORS apropiadamente
- [ ] Habilitar HTTPS
- [ ] Configurar firewall (UFW/iptables)
- [ ] Configurar backup automático de BD
- [ ] Configurar monitoreo y alertas
- [ ] Documentar procedimientos de recuperación
- [ ] Probar restore de backups
- [ ] Configurar límites de rate limiting
- [ ] Revisar permisos de archivos y directorios
- [ ] Actualizar variables de entorno de producción
