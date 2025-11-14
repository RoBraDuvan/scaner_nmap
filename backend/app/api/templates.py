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

class ScanTemplateCreate(BaseModel):
    """Scan template creation schema"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scan_type: str = Field(..., min_length=1, max_length=50)
    nmap_arguments: Optional[str] = Field(None, max_length=500)
    configuration: Optional[dict] = None
    is_default: bool = False

class ScanTemplateUpdate(BaseModel):
    """Scan template update schema"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    scan_type: Optional[str] = Field(None, min_length=1, max_length=50)
    nmap_arguments: Optional[str] = Field(None, max_length=500)
    configuration: Optional[dict] = None
    is_default: Optional[bool] = None

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

@router.post("/", response_model=ScanTemplateResponse, status_code=201)
async def create_template(
    template_data: ScanTemplateCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new scan template

    Args:
        template_data: Template creation data
        db: Database session

    Returns:
        Created scan template
    """
    # Check if template with same name already exists
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.name == template_data.name)
    )
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(status_code=400, detail="Template with this name already exists")

    # Create new template
    template = ScanTemplate(**template_data.model_dump())
    db.add(template)
    await db.commit()
    await db.refresh(template)

    return template

@router.put("/{template_id}", response_model=ScanTemplateResponse)
async def update_template(
    template_id: UUID,
    template_data: ScanTemplateUpdate,
    db: AsyncSession = Depends(get_db)
):
    """
    Update an existing scan template

    Args:
        template_id: Template UUID
        template_data: Template update data
        db: Database session

    Returns:
        Updated scan template
    """
    # Get existing template
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id)
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Check if name is being changed and if new name already exists
    if template_data.name and template_data.name != template.name:
        result = await db.execute(
            select(ScanTemplate).where(ScanTemplate.name == template_data.name)
        )
        existing = result.scalar_one_or_none()

        if existing:
            raise HTTPException(status_code=400, detail="Template with this name already exists")

    # Update template fields
    update_data = template_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(template, field, value)

    await db.commit()
    await db.refresh(template)

    return template

@router.delete("/{template_id}")
async def delete_template(
    template_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a scan template

    Args:
        template_id: Template UUID
        db: Database session

    Returns:
        Success message
    """
    # Get existing template
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id)
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    await db.delete(template)
    await db.commit()

    return {"message": "Template deleted successfully"}
