"""
Reports API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID
from datetime import datetime
import json

from app.core.database import get_db
from app.models.scan import Scan, ScanResult

router = APIRouter()

@router.get("/{scan_id}/json")
async def get_json_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan report in JSON format

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        JSON report
    """
    # Get scan
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get results
    results_query = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    results = results_query.scalars().all()

    # Build report
    report = {
        "scan_info": {
            "id": str(scan.id),
            "name": scan.name,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "summary": {
            "total_hosts": len(results),
            "hosts_up": sum(1 for r in results if r.state == "up"),
            "hosts_down": sum(1 for r in results if r.state == "down"),
            "total_open_ports": sum(len(r.ports) for r in results if r.ports),
        },
        "results": [
            {
                "host": r.host,
                "hostname": r.hostname,
                "state": r.state,
                "ports": r.ports,
                "os_detection": r.os_detection,
                "services": r.services,
            }
            for r in results
        ]
    }

    return report

@router.get("/{scan_id}/html")
async def get_html_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan report in HTML format

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        HTML report
    """
    # Get scan
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get results
    results_query = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    results = results_query.scalars().all()

    # Generate HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Report - {scan.name}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
            h2 {{ color: #34495e; margin-top: 30px; }}
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
            .summary-card {{ background: #ecf0f1; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }}
            .summary-card h3 {{ margin: 0; color: #7f8c8d; font-size: 14px; }}
            .summary-card p {{ margin: 5px 0 0 0; font-size: 24px; font-weight: bold; color: #2c3e50; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #3498db; color: white; padding: 12px; text-align: left; }}
            td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
            tr:hover {{ background: #f8f9fa; }}
            .state-up {{ color: #27ae60; font-weight: bold; }}
            .state-down {{ color: #e74c3c; font-weight: bold; }}
            .port-list {{ list-style: none; padding: 0; margin: 0; }}
            .port-list li {{ padding: 3px 0; }}
            .metadata {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .metadata p {{ margin: 5px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Nmap Scan Report: {scan.name}</h1>

            <div class="metadata">
                <p><strong>Target:</strong> {scan.target}</p>
                <p><strong>Scan Type:</strong> {scan.scan_type}</p>
                <p><strong>Status:</strong> {scan.status}</p>
                <p><strong>Started:</strong> {scan.started_at or 'N/A'}</p>
                <p><strong>Completed:</strong> {scan.completed_at or 'N/A'}</p>
            </div>

            <h2>📊 Summary</h2>
            <div class="summary">
                <div class="summary-card">
                    <h3>Total Hosts</h3>
                    <p>{len(results)}</p>
                </div>
                <div class="summary-card">
                    <h3>Hosts Up</h3>
                    <p>{sum(1 for r in results if r.state == 'up')}</p>
                </div>
                <div class="summary-card">
                    <h3>Hosts Down</h3>
                    <p>{sum(1 for r in results if r.state == 'down')}</p>
                </div>
                <div class="summary-card">
                    <h3>Open Ports</h3>
                    <p>{sum(len(r.ports) for r in results if r.ports)}</p>
                </div>
            </div>

            <h2>🖥️ Host Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Hostname</th>
                        <th>State</th>
                        <th>Open Ports</th>
                        <th>Services</th>
                    </tr>
                </thead>
                <tbody>
    """

    for result in results:
        state_class = "state-up" if result.state == "up" else "state-down"
        ports_html = ""
        if result.ports:
            ports_html = "<ul class='port-list'>"
            for port in result.ports[:10]:  # Limit to first 10 ports
                ports_html += f"<li>{port.get('port')}/{port.get('protocol')} - {port.get('service')}</li>"
            ports_html += "</ul>"

        services_html = ""
        if result.services:
            services_html = "<br>".join(result.services[:5])  # Limit to first 5 services

        html_content += f"""
                    <tr>
                        <td>{result.host}</td>
                        <td>{result.hostname or 'N/A'}</td>
                        <td class="{state_class}">{result.state}</td>
                        <td>{ports_html or 'None'}</td>
                        <td>{services_html or 'None'}</td>
                    </tr>
        """

    html_content += """
                </tbody>
            </table>

            <p style="margin-top: 30px; text-align: center; color: #7f8c8d; font-size: 12px;">
                Generated by Nmap Scanner - """ + datetime.now().isoformat() + """
            </p>
        </div>
    </body>
    </html>
    """

    return Response(content=html_content, media_type="text/html")

@router.get("/{scan_id}/csv")
async def get_csv_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan report in CSV format

    Args:
        scan_id: Scan UUID
        db: Database session

    Returns:
        CSV report
    """
    # Get results
    results_query = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    results = results_query.scalars().all()

    if not results:
        raise HTTPException(status_code=404, detail="No results found")

    # Generate CSV
    csv_lines = ["Host,Hostname,State,Port,Protocol,Service,Version,Product"]

    for result in results:
        if result.ports:
            for port in result.ports:
                csv_lines.append(
                    f"{result.host},{result.hostname or 'N/A'},{result.state},"
                    f"{port.get('port')},{port.get('protocol')},{port.get('service')},"
                    f"{port.get('version', '')},{port.get('product', '')}"
                )
        else:
            csv_lines.append(f"{result.host},{result.hostname or 'N/A'},{result.state},,,,,")

    csv_content = "\n".join(csv_lines)

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"}
    )
