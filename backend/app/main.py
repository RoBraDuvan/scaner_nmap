"""
Main FastAPI application for Nmap Scanner
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import engine, Base
from app.api import scans, templates, reports

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print("🚀 Starting Nmap Scanner API...")
    print(f"📊 Database: {settings.DATABASE_URL}")
    print(f"🔴 Redis: {settings.REDIS_URL}")

    # Create database tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Shutdown
    print("👋 Shutting down Nmap Scanner API...")
    await engine.dispose()

# Create FastAPI application
app = FastAPI(
    title="Nmap Scanner API",
    description="Powerful network scanner with web interface powered by Nmap",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(templates.router, prefix="/api/templates", tags=["Templates"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Nmap Scanner API",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "operational"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "database": "connected",
        "redis": "connected"
    }
