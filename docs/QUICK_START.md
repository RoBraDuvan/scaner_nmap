# Quick Start - Nmap Scanner

Guía rápida para empezar a usar el sistema en menos de 5 minutos.

## 🚀 Inicio Rápido

### 1. Clonar el repositorio

```bash
git clone <repository-url>
cd scaner_nmap
```

### 2. Iniciar con Docker Compose

```bash
docker-compose up -d
```

### 3. Acceder a la aplicación

Abre tu navegador en: **http://localhost:3000**

## 📝 Crear tu Primer Escaneo

### Opción 1: Quick Scan (Rápido)

1. Click en **"New Scan"**
2. Completa el formulario:
   - **Name**: "Mi Primer Escaneo"
   - **Target**: "scanme.nmap.org" (sitio de prueba oficial de Nmap)
   - **Scan Type**: "Quick Scan"
3. Click en **"Start Scan"**

### Opción 2: Via API (curl)

```bash
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Scan",
    "target": "scanme.nmap.org",
    "scan_type": "quick"
  }'
```

## 📊 Ver Resultados

1. En el Dashboard, verás tu escaneo en progreso
2. Click en **"View Details"** cuando el status sea "completed"
3. Explora:
   - **Results**: Hosts, puertos y servicios descubiertos
   - **Logs**: Registro detallado del escaneo
4. Descarga informes en JSON, HTML o CSV

## 🎯 Ejemplos de Targets

```bash
# IP única
192.168.1.1

# Rango de IPs
192.168.1.1-50

# Red CIDR
192.168.1.0/24

# Hostname
scanme.nmap.org

# Múltiples hosts
192.168.1.1,192.168.1.10,192.168.1.20
```

## 🔧 Tipos de Escaneo Comunes

| Tipo | Uso | Tiempo Estimado |
|------|-----|-----------------|
| Quick | Escaneo rápido inicial | 1-5 min |
| Service | Identificar servicios | 5-15 min |
| Full | Escaneo completo | 30-60 min |
| Vulnerability | Buscar vulnerabilidades | 15-30 min |

## 📚 Próximos Pasos

- Lee el [README.md](README.md) completo para más detalles
- Consulta [DEPLOYMENT.md](DEPLOYMENT.md) para producción
- Explora la API docs en http://localhost:8000/docs

## ⚠️ Importante

- Solo escanea redes autorizadas
- `scanme.nmap.org` es un servidor de prueba oficial
- Los escaneos pueden demorar dependiendo del tamaño de la red

## 🛑 Detener el Sistema

```bash
docker-compose down
```

## 💡 Tips

- Usa "Quick Scan" para pruebas rápidas
- "Service Detection" para identificar versiones
- "Vulnerability Scan" para análisis de seguridad
- Los escaneos se actualizan automáticamente en el Dashboard
