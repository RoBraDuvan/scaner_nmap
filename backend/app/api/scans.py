"""
Scans API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional
from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime

from app.core.database import get_db
from app.models.scan import Scan, ScanResult, ScanLog
from app.services.scanner import scanner

router = APIRouter()

# Pydantic schemas
class ScanConfiguration(BaseModel):
    """Scan configuration schema"""
    timeout: Optional[int] = Field(default=1800, description="Scan timeout in seconds")
    max_hosts: Optional[int] = Field(default=256, description="Maximum number of hosts")
    timing: Optional[str] = Field(default="T4", description="Nmap timing template")
    additional_args: Optional[str] = Field(default="", description="Additional nmap arguments")

class ScanCreate(BaseModel):
    """Create scan request schema"""
    name: str = Field(..., description="Scan name")
    target: str = Field(..., description="Target IP, hostname, or network (e.g., 192.168.1.0/24)")
    scan_type: str = Field(..., description="Scan type (quick, full, service, etc.)")
    nmap_arguments: Optional[str] = Field(default=None, description="Custom nmap arguments")
    configuration: Optional[ScanConfiguration] = None

class ScanResponse(BaseModel):
    """Scan response schema"""
    id: UUID
    name: str
    target: str
    scan_type: str
    status: str
    progress: int
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True

class ScanResultResponse(BaseModel):
    """Scan result response schema"""
    id: UUID
    scan_id: UUID
    host: str
    hostname: Optional[str]
    state: Optional[str]
    ports: Optional[list]
    os_detection: Optional[dict]
    services: Optional[list]
    mac_address: Optional[str]
    mac_vendor: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class ScanLogResponse(BaseModel):
    """Scan log response schema"""
    id: UUID
    level: str
    message: str
    created_at: datetime

    class Config:
        from_attributes = True

async def run_scan_background(scan_id: str, target: str, arguments: str, db: AsyncSession):
    """Background task to run scan"""
    try:
        await scanner.execute_scan(scan_id, target, arguments, db)
    except Exception as e:
        print(f"Scan {scan_id} failed: {str(e)}")

@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Create and start a new scan

    Args:
        scan_data: Scan configuration
        background_tasks: FastAPI background tasks
        db: Database session

    Returns:
        Created scan object
    """
    # Determine nmap arguments
    if scan_data.nmap_arguments:
        nmap_args = scan_data.nmap_arguments
    else:
        templates = scanner.get_scan_templates()
        if scan_data.scan_type in templates:
            nmap_args = templates[scan_data.scan_type]["arguments"]
        else:
            raise HTTPException(status_code=400, detail=f"Unknown scan type: {scan_data.scan_type}")

    # Create scan record
    scan = Scan(
        name=scan_data.name,
        target=scan_data.target,
        scan_type=scan_data.scan_type,
        status="pending",
        configuration=scan_data.configuration.model_dump() if scan_data.configuration else None
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Start scan in background
    background_tasks.add_task(
        run_scan_background,
        str(scan.id),
        scan_data.target,
        nmap_args,
        db
    )

    return scan

@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    List all scans with optional filtering

    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        status: Filter by status (pending, running, completed, failed)
        db: Database session

    Returns:
        List of scans
    """
    query = select(Scan).order_by(desc(Scan.created_at))

    if status:
        query = query.where(Scan.status == status)

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    scans = result.scalars().all()

    return scans

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan details by ID

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        Scan object
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan

@router.get("/{scan_id}/results", response_model=List[ScanResultResponse])
async def get_scan_results(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan results by scan ID

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        List of scan results
    """
    result = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    results = result.scalars().all()

    return results

@router.get("/{scan_id}/logs", response_model=List[ScanLogResponse])
async def get_scan_logs(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan logs by scan ID

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        List of scan logs
    """
    result = await db.execute(
        select(ScanLog)
        .where(ScanLog.scan_id == scan_id)
        .order_by(ScanLog.created_at)
    )
    logs = result.scalars().all()

    return logs

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a scan and all its results

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        Success message
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.delete(scan)
    await db.commit()

    return {"message": "Scan deleted successfully"}

@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Cancel a running scan

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        Success message
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    scanner.cancel_scan(str(scan_id))

    scan.status = "cancelled"
    await db.commit()

    return {"message": "Scan cancelled"}
