"""
Nmap scanner service
"""
import nmap
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.scan import Scan, ScanResult, ScanLog
from app.core.config import settings

class NmapScanner:
    """Nmap scanner service"""

    def __init__(self):
        self.nm = nmap.PortScanner()
        self.active_scans: Dict[str, bool] = {}

    async def execute_scan(
        self,
        scan_id: str,
        target: str,
        arguments: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Execute nmap scan asynchronously

        Args:
            scan_id: UUID of the scan
            target: Target host(s) or network
            arguments: Nmap arguments
            db: Database session

        Returns:
            Scan results dictionary
        """
        self.active_scans[scan_id] = True

        try:
            # Update scan status to running
            await self._update_scan_status(
                db, scan_id, "running",
                started_at=datetime.utcnow()
            )
            await self._add_log(db, scan_id, "info", f"Starting scan on target: {target}")

            # Execute nmap scan in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.nm.scan(target, arguments=arguments)
            )

            # Process scan results
            results = await self._process_scan_results(db, scan_id, self.nm)

            # Update scan status to completed
            await self._update_scan_status(
                db, scan_id, "completed",
                progress=100,
                completed_at=datetime.utcnow()
            )
            await self._add_log(db, scan_id, "success", "Scan completed successfully")

            return {
                "status": "completed",
                "hosts_scanned": len(results),
                "results": results
            }

        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            await self._update_scan_status(
                db, scan_id, "failed",
                error_message=error_msg,
                completed_at=datetime.utcnow()
            )
            await self._add_log(db, scan_id, "error", error_msg)
            raise

        finally:
            self.active_scans.pop(scan_id, None)

    async def _process_scan_results(
        self,
        db: AsyncSession,
        scan_id: str,
        nm: nmap.PortScanner
    ) -> List[Dict]:
        """Process and store scan results"""
        results = []

        for host in nm.all_hosts():
            host_data = {
                "host": host,
                "hostname": nm[host].hostname() if nm[host].hostname() else None,
                "state": nm[host].state(),
                "ports": [],
                "os_detection": {},
                "services": []
            }

            # Process ports
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = nm[host][proto][port]
                    port_data = {
                        "port": port,
                        "protocol": proto,
                        "state": port_info.get("state", "unknown"),
                        "service": port_info.get("name", "unknown"),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                        "extrainfo": port_info.get("extrainfo", "")
                    }
                    host_data["ports"].append(port_data)
                    host_data["services"].append(f"{port}/{proto} - {port_info.get('name', 'unknown')}")

            # Process OS detection if available
            if 'osmatch' in nm[host]:
                host_data["os_detection"] = {
                    "matches": [
                        {
                            "name": os.get("name", ""),
                            "accuracy": os.get("accuracy", ""),
                            "line": os.get("line", "")
                        }
                        for os in nm[host]['osmatch']
                    ]
                }

            # Create scan result record
            scan_result = ScanResult(
                scan_id=scan_id,
                host=host_data["host"],
                hostname=host_data["hostname"],
                state=host_data["state"],
                ports=host_data["ports"],
                os_detection=host_data["os_detection"],
                services=host_data["services"],
                raw_output=nm[host].get('raw', '')
            )

            db.add(scan_result)
            results.append(host_data)

        await db.commit()
        return results

    async def _update_scan_status(
        self,
        db: AsyncSession,
        scan_id: str,
        status: str,
        progress: Optional[int] = None,
        error_message: Optional[str] = None,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None
    ):
        """Update scan status in database"""
        update_data = {"status": status}

        if progress is not None:
            update_data["progress"] = progress
        if error_message is not None:
            update_data["error_message"] = error_message
        if started_at is not None:
            update_data["started_at"] = started_at
        if completed_at is not None:
            update_data["completed_at"] = completed_at

        stmt = (
            update(Scan)
            .where(Scan.id == scan_id)
            .values(**update_data)
        )
        await db.execute(stmt)
        await db.commit()

    async def _add_log(
        self,
        db: AsyncSession,
        scan_id: str,
        level: str,
        message: str
    ):
        """Add log entry for scan"""
        log = ScanLog(
            scan_id=scan_id,
            level=level,
            message=message
        )
        db.add(log)
        await db.commit()

    def cancel_scan(self, scan_id: str):
        """Cancel an active scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id] = False
            return True
        return False

    def get_scan_templates(self) -> Dict[str, Dict]:
        """Get predefined scan templates"""
        return {
            "quick": {
                "name": "Quick Scan",
                "arguments": "-F -T4",
                "description": "Fast scan of the most common 100 ports"
            },
            "full": {
                "name": "Full Port Scan",
                "arguments": "-p- -T4",
                "description": "Comprehensive scan of all 65535 ports"
            },
            "service": {
                "name": "Service Version Detection",
                "arguments": "-sV -O -T4",
                "description": "Detect service versions and OS"
            },
            "stealth": {
                "name": "Stealth Scan",
                "arguments": "-sS -T2 -f",
                "description": "SYN stealth scan with minimal footprint"
            },
            "vulnerability": {
                "name": "Vulnerability Scan",
                "arguments": "-sV --script vuln -T4",
                "description": "Scan with NSE vulnerability scripts"
            },
            "ping": {
                "name": "Ping Sweep",
                "arguments": "-sn -T4",
                "description": "Discover live hosts only"
            },
            "udp": {
                "name": "UDP Scan",
                "arguments": "-sU --top-ports 100 -T4",
                "description": "Scan common UDP ports"
            },
            "aggressive": {
                "name": "Aggressive Scan",
                "arguments": "-A -T4",
                "description": "Aggressive scan with OS detection, version, scripts and traceroute"
            }
        }

# Global scanner instance
scanner = NmapScanner()
