"""
Scan templates API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pydantic import BaseModel, Field
from uuid import UUID

from app.core.database import get_db
from app.models.scan import ScanTemplate
from app.services.scanner import scanner

router = APIRouter()

# Pydantic schemas
class ScanTemplateResponse(BaseModel):
    """Scan template response schema"""
    id: UUID
    name: str
    description: Optional[str]
    scan_type: str
    nmap_arguments: Optional[str]
    configuration: Optional[dict]
    is_default: bool

    class Config:
        from_attributes = True

@router.get("/", response_model=List[ScanTemplateResponse])
async def list_templates(
    db: AsyncSession = Depends(get_db)
):
    """
    List all scan templates

    Args:
        db: Database session

    Returns:
        List of scan templates
    """
    result = await db.execute(select(ScanTemplate))
    templates = result.scalars().all()

    return templates

@router.get("/builtin")
async def get_builtin_templates():
    """
    Get built-in scan templates

    Returns:
        Dictionary of built-in templates
    """
    return scanner.get_scan_templates()

@router.get("/{template_id}", response_model=ScanTemplateResponse)
async def get_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get template by ID

    Args:
        template_id: Template UUID
        db: Database session

    Returns:
        Scan template
    """
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id)
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    return template
