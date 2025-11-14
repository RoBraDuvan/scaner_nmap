# Changelog - Nmap Scanner

## Version 1.0.0 - 2025-11-14

### ✨ Características Iniciales

**Backend (FastAPI + Python)**
- API REST asíncrona completa con FastAPI
- 8 tipos de escaneo predefinidos:
  - Quick Scan (puertos comunes)
  - Full Port Scan (todos los puertos)
  - Service Version Detection (detección de servicios y OS)
  - Stealth Scan (escaneo sigiloso SYN)
  - Vulnerability Scan (scripts NSE de vulnerabilidades)
  - Ping Sweep (descubrimiento de hosts)
  - UDP Scan (puertos UDP comunes)
  - Aggressive Scan (escaneo completo agresivo)
- Motor de escaneo con python-nmap
- Procesamiento asíncrono en background
- Sistema de logs detallado por escaneo
- Generación de informes en múltiples formatos (JSON, HTML, CSV)
- Base de datos PostgreSQL con SQLAlchemy async
- Documentación automática con Swagger/OpenAPI

**Frontend (React)**
- Dashboard moderno y responsive
- Formulario interactivo de creación de escaneos
- Vista detallada de resultados con tabs (Results/Logs)
- Auto-refresh cada 5 segundos
- Descarga de informes en múltiples formatos
- Catálogo de plantillas de escaneo
- Filtrado por estado de escaneos
- Progress bars para escaneos activos

**Infraestructura**
- Docker Compose para orquestación de servicios
- PostgreSQL 15 para almacenamiento persistente
- Redis 7 para cache y colas
- Nginx para servir el frontend
- Multi-stage builds optimizados

**Base de Datos**
- Tabla `scans` - Información de escaneos
- Tabla `scan_results` - Resultados por host
- Tabla `scan_templates` - Plantillas predefinidas (8 templates iniciales)
- Tabla `scan_logs` - Logs de ejecución
- Índices optimizados para consultas rápidas

### 🐛 Correcciones (Build Inicial)

**Issue #1: Missing Optional import**
- **Problema**: Error `NameError: name 'Optional' is not defined` en templates.py
- **Causa**: Falta importar `Optional` de typing
- **Solución**: Agregado `Optional` al import en línea 7 de `backend/app/api/templates.py`
- **Commit**: Agregado `from typing import List, Optional`

**Issue #2: run_in_executor arguments error**
- **Problema**: Error `run_in_executor() got an unexpected keyword argument 'arguments'`
- **Causa**: `run_in_executor` no acepta argumentos con nombre directamente
- **Solución**: Envuelto la llamada a `nm.scan()` en una lambda function
- **Ubicación**: `backend/app/services/scanner.py` líneas 51-56
- **Commit**: Cambiado a `lambda: self.nm.scan(target, arguments=arguments)`

**Issue #3: npm ci error in frontend build**
- **Problema**: `npm ci` requiere package-lock.json
- **Causa**: No existe package-lock.json en el proyecto
- **Solución**: Cambiado `npm ci` por `npm install` en Dockerfile
- **Ubicación**: `frontend/Dockerfile` línea 10
- **Commit**: `RUN npm install`

### 📦 Dependencias

**Backend**
- fastapi==0.104.1
- uvicorn[standard]==0.24.0
- python-nmap==0.7.1
- sqlalchemy==2.0.23
- psycopg2-binary==2.9.9
- alembic==1.12.1
- pydantic==2.5.0
- redis==5.0.1
- celery==5.3.4
- asyncpg==0.29.0

**Frontend**
- react==18.2.0
- react-dom==18.2.0
- react-router-dom==6.20.0
- axios==1.6.2
- recharts==2.10.3
- react-icons==4.12.0
- date-fns==3.0.0

### 🚀 Deployment

**Servicios Docker:**
- `nmap_scanner_backend` - Backend FastAPI (puerto 8000)
- `nmap_scanner_frontend` - Frontend React/Nginx (puerto 3000)
- `nmap_scanner_db` - PostgreSQL 15 (puerto 5432)
- `nmap_scanner_redis` - Redis 7 (puerto 6379)

**Comandos de inicio:**
```bash
# Iniciar todos los servicios
docker-compose up -d

# Ver estado
docker-compose ps

# Ver logs
docker-compose logs -f

# Detener
docker-compose down
```

### 📝 Notas

- El backend requiere privilegios especiales (`NET_ADMIN`, `NET_RAW`) para ejecutar Nmap
- Solo escanear redes autorizadas
- Cambiar credenciales por defecto en producción
- El sistema incluye 8 templates de escaneo predefinidos en la base de datos

### 🔐 Seguridad

- Cambiar `SECRET_KEY` en producción
- Actualizar credenciales de PostgreSQL
- Configurar CORS apropiadamente
- Habilitar HTTPS para producción
- Solo usar en redes autorizadas
- Cumplir con leyes y políticas de seguridad locales

### 📚 Documentación

- README.md - Documentación completa
- QUICK_START.md - Inicio rápido en 5 minutos
- DEPLOYMENT.md - Guía de despliegue en producción
- USAGE.md - Guía de uso detallada
- CHANGELOG.md - Registro de cambios (este archivo)

### 🎯 Próximas Características (Roadmap)

- [ ] Autenticación y autorización de usuarios
- [ ] Programación de escaneos periódicos
- [ ] Notificaciones por email/webhook
- [ ] Comparación de escaneos
- [ ] Dashboard de estadísticas
- [ ] Exportación de informes a PDF
- [ ] API webhooks para integración
- [ ] Gestión de equipos y permisos
- [ ] Histórico de cambios en hosts
- [ ] Detección de cambios automática

### 👥 Contribuidores

- Sistema desarrollado
- Documentación completa incluida

### 📄 Licencia

MIT License

---

## Instalación

```bash
# Clonar repositorio
git clone <repository-url>
cd scaner_nmap

# Iniciar servicios
docker-compose up -d

# Acceder
# Frontend: http://localhost:3000
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

## Soporte

Para reportar bugs o solicitar características, crear un issue en el repositorio.
