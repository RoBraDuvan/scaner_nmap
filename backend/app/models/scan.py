"""
Database models for scans
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.core.database import Base

class Scan(Base):
    """Scan model"""
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(50), default="pending")
    progress = Column(Integer, default=0)
    created_at = Column(DateTime, server_default=func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    configuration = Column(JSONB, nullable=True)

    # Relationships
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")

class ScanResult(Base):
    """Scan result model"""
    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"))
    host = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=True)
    state = Column(String(50), nullable=True)
    ports = Column(JSONB, nullable=True)
    os_detection = Column(JSONB, nullable=True)
    services = Column(JSONB, nullable=True)
    vulnerabilities = Column(JSONB, nullable=True)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="results")

class ScanTemplate(Base):
    """Scan template model"""
    __tablename__ = "scan_templates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    scan_type = Column(String(50), nullable=False)
    nmap_arguments = Column(String(500), nullable=True)
    configuration = Column(JSONB, nullable=True)
    is_default = Column(String(10), default="false")
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class ScanLog(Base):
    """Scan log model"""
    __tablename__ = "scan_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"))
    level = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="logs")
