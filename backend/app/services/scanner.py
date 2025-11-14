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
            # Try to get hostname from multiple sources
            hostname = None
            if nm[host].hostname():
                hostname = nm[host].hostname()
            elif 'hostnames' in nm[host] and nm[host]['hostnames']:
                # Try alternative hostname sources
                for hn in nm[host]['hostnames']:
                    if hn.get('name'):
                        hostname = hn['name']
                        break

            # Extract MAC address and vendor if available
            mac_address = None
            mac_vendor = None
            if 'addresses' in nm[host]:
                if 'mac' in nm[host]['addresses']:
                    mac_address = nm[host]['addresses']['mac']
                # Vendor information is stored in a separate dictionary
                if 'vendor' in nm[host] and nm[host]['vendor']:
                    # Vendor dict is keyed by MAC address
                    mac_vendor = list(nm[host]['vendor'].values())[0] if nm[host]['vendor'] else None

            host_data = {
                "host": host,
                "hostname": hostname,
                "state": nm[host].state(),
                "ports": [],
                "os_detection": {},
                "services": [],
                "mac_address": mac_address,
                "mac_vendor": mac_vendor
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

            # Extract NetBIOS/SMB name from scripts if available and no hostname yet
            if not hostname and 'hostscript' in nm[host]:
                for script in nm[host]['hostscript']:
                    script_id = script.get('id', '')
                    output = script.get('output', '')

                    # Try nbstat script
                    if 'nbstat' in script_id and output:
                        lines = output.split('\n')
                        for line in lines:
                            # Look for NetBIOS computer name
                            if '<00>' in line and ('Workstation' in line or 'UNIQUE' in line):
                                parts = line.split()
                                if parts and parts[0] and not parts[0].startswith('<'):
                                    hostname = parts[0].strip()
                                    host_data["hostname"] = hostname
                                    break

                    # Try smb-os-discovery script
                    if not hostname and 'smb-os-discovery' in script_id and output:
                        for line in output.split('\n'):
                            if 'Computer name:' in line:
                                parts = line.split(':', 1)
                                if len(parts) > 1:
                                    hostname = parts[1].strip()
                                    host_data["hostname"] = hostname
                                    break
                            elif 'NetBIOS computer name:' in line:
                                parts = line.split(':', 1)
                                if len(parts) > 1:
                                    hostname = parts[1].strip()
                                    host_data["hostname"] = hostname
                                    break

                    if hostname:
                        break

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
            # Basic Port Scans
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
            "udp": {
                "name": "UDP Scan",
                "arguments": "-sU --top-ports 100 -T4",
                "description": "Scan common UDP ports"
            },
            # Network Discovery Scans
            "discovery": {
                "name": "Host Discovery",
                "arguments": "-sn -PE -PP -PM --dns-servers 8.8.8.8,1.1.1.1 -T4",
                "description": "Discover active hosts in network (ping sweep)"
            },
            "local_network": {
                "name": "Local Network Scan",
                "arguments": "-sn -PR --dns-servers 8.8.8.8,1.1.1.1 -T4",
                "description": "Complete local network scan with MAC vendor identification"
            },
            # Server-Specific Scans
            "web_server": {
                "name": "Web Server Scan",
                "arguments": "-p 80,443,8080,8443,3000,5000,8000 -sV --script http-title,http-methods,http-headers -T4",
                "description": "Scan web servers (HTTP/HTTPS) with service detection"
            },
            "db_server": {
                "name": "Database Server Scan",
                "arguments": "-p 3306,5432,1433,1521,27017,6379,5984,9200,11211 -sV -T4",
                "description": "Scan common database ports with version detection"
            },
            "mail_server": {
                "name": "Mail Server Scan",
                "arguments": "-p 25,110,143,465,587,993,995 -sV --script smtp-commands,pop3-capabilities,imap-capabilities -T4",
                "description": "Scan mail servers (SMTP, POP3, IMAP)"
            },
            "ftp_ssh_server": {
                "name": "FTP/SSH Server Scan",
                "arguments": "-p 20,21,22,23,990,2121,2222 -sV --script ftp-anon,ssh-auth-methods -T4",
                "description": "Scan file transfer and remote access services"
            },
            "dns_server": {
                "name": "DNS Server Scan",
                "arguments": "-p 53 -sU -sV --script dns-nsid,dns-recursion -T4",
                "description": "Scan DNS servers and detect configuration"
            },
            # Advanced Scans
            "service": {
                "name": "Service Version Detection",
                "arguments": "-sV -O -T4",
                "description": "Detect service versions and OS"
            },
            "vulnerability": {
                "name": "Vulnerability Scan",
                "arguments": "-sV --script vuln -T4",
                "description": "Scan with NSE vulnerability scripts"
            },
            "security_audit": {
                "name": "Security Audit",
                "arguments": "-p- -sV --script ssl-cert,ssl-enum-ciphers,ssh-auth-methods -T4",
                "description": "Complete security audit with SSL/TLS checks"
            },
            "stealth": {
                "name": "Stealth Scan",
                "arguments": "-sS -T2 -f",
                "description": "SYN stealth scan with minimal footprint"
            },
            "aggressive": {
                "name": "Aggressive Scan",
                "arguments": "-A -T4",
                "description": "Aggressive scan with OS detection, version, scripts and traceroute"
            }
        }

# Global scanner instance
scanner = NmapScanner()
