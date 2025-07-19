import os
import asyncio
import logging
import sqlite3
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from datetime import datetime
from contextlib import asynccontextmanager
from typing import List, Dict, Any
from pydantic import BaseModel, Field, field_validator
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent
import aiohttp
from dotenv import load_dotenv
import shodan

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Initialize Shodan API
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
try:
    shodan_api = shodan.Shodan(SHODAN_API_KEY)
except shodan.APIError as e:
    logger.error(f"Shodan API initialization failed: {str(e)}")
    shodan_api = None

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect("cybersecurity.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT,
            scan_type TEXT,
            arguments TEXT,
            results TEXT,
            created_at TIMESTAMP,
            chain TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            target TEXT,
            port INTEGER,
            service TEXT,
            vulnerability TEXT,
            cve_id TEXT,
            shodan_data TEXT,
            created_at TIMESTAMP,
            PRIMARY KEY (target, port)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            ip TEXT PRIMARY KEY,
            count INTEGER,
            last_reset TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Supported scan types
ALLOWED_SCAN_TYPES = {
    "-sS": "TCP SYN scan",
    "-sT": "TCP Connect scan",
    "-sU": "UDP scan",
    "-sF": "TCP FIN scan",
    "-sN": "TCP NULL scan",
    "-sX": "TCP Xmas scan",
    "-sA": "TCP ACK scan",
    "-sW": "TCP Window scan",
    "-sM": "TCP Maimon scan",
    "-sV": "Version detection",
    "-O": "OS detection",
    "-PE": "Ping scan (ICMP echo)",
    "-PP": "Ping scan (timestamp)"
}
# Allowed NSE scripts
ALLOWED_NSE_SCRIPTS = [
    "vulners", "http-enum", "smb-vuln-ms17-010", "ssl-cert", "http-title", "dns-brute",
    "http-vuln-cve2017-5638", "ftp-anon", "mysql-vuln-cve2012-2122"
]


# Pydantic models for validation
class ScanInput(BaseModel):
    target: str = Field(..., description="Target IP or hostname (e.g., 192.168.1.1 or scanme.nmap.org)")
    scan_type: str = Field(default="-sS", description="Nmap scan type (e.g., -sS, -sT, -sU, -sF, -sN, -sX, -sA, -sW, -sM, -sV, -O, -PE, -PP)")
    extra_args: str = Field(default="", description="Additional safe Nmap arguments (e.g., --spoof-mac 0, --data-length 100)")
    nse_scripts: str = Field(default="", description="Comma-separated NSE scripts (e.g., vulners,http-enum)")
    
    @field_validator("target")
    def validate_target(cls, v):
        if not v or len(v) > 255 or any(c in v for c in [" ", ";", "|", "&"]):
            raise ValueError("Invalid target: must be a valid IP/hostname, max 255 chars, no dangerous chars")
        return v
    
    @field_validator("scan_type")
    def validate_scan_type(cls, v):
        if v not in ALLOWED_SCAN_TYPES:
            raise ValueError(f"Invalid scan type: must be one of {list(ALLOWED_SCAN_TYPES.keys())}")
        return v
    
    @field_validator("extra_args")
    def validate_extra_args(cls, v):
        forbidden = ["--script", "-oA", "-oN", "-oX", "--output", "--privileged", "--unprivileged", "-iL"]
        if any(arg in v for arg in forbidden):
            raise ValueError(f"Forbidden arguments detected in extra_args: {forbidden}")
        return v
    
    @field_validator("nse_scripts")
    def validate_nse_scripts(cls, v):
        if not v:
            return v
        scripts = v.split(",")
        for script in scripts:
            if script.strip() not in ALLOWED_NSE_SCRIPTS:
                raise ValueError(f"Invalid NSE script: {script}. Must be one of {ALLOWED_NSE_SCRIPTS}")
        return v
    
class VulnerabilityOutput(BaseModel):
    target: str
    port: int
    service: str
    vulnerability: str
    cve_id: str = None
    shodan_data: str = None

class OSOutput(BaseModel):
    target: str
    os_name: str
    os_version: str
    accuracy: float

class FirewallOutput(BaseModel):
    target: str
    firewall_detected: bool
    details: str

class HostDiscoveryOutput(BaseModel):
    target: str
    status: str
    details: str

# MCP Server
mcp = FastMCP("CybersecurityNMAP")

# Configure nmap path for different environments
def get_nmap_path():
    """Find the correct nmap binary path for cross-platform compatibility."""
    import shutil
    import subprocess
    
    # Try different nmap paths
    nmap_paths = [
        "nmap",  # Default system PATH
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",  # Common Windows install path
        "C:\\Program Files\\Nmap\\nmap.exe",  # Alternative Windows path
        "/usr/bin/nmap",  # Linux/WSL path
        "/usr/local/bin/nmap",  # Alternative Linux path
    ]
    
    # First try using shutil.which to find nmap in PATH
    nmap_path = shutil.which("nmap")
    if nmap_path:
        try:
            # Test if nmap works
            result = subprocess.run([nmap_path, "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"Found working nmap at: {nmap_path}")
                return nmap_path
        except Exception as e:
            logger.warning(f"Failed to test nmap at {nmap_path}: {str(e)}")
    
    # Try WSL nmap if on Windows
    try:
        result = subprocess.run(["wsl", "nmap", "--version"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info("Found working nmap in WSL")
            return "wsl nmap"
    except Exception:
        pass
    
    # Try explicit paths
    for path in nmap_paths:
        try:
            if path == "nmap":
                continue  # Already tried with shutil.which
            result = subprocess.run([path, "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"Found working nmap at: {path}")
                return path
        except Exception:
            continue
    
    raise Exception("Could not find nmap binary. Please ensure nmap is installed and accessible.")

def run_nmap_process(target: str, arguments: str) -> str:
    """Run nmap using libnmap's NmapProcess for better cross-platform support."""
    try:
        nmap_path = get_nmap_path()
        
        # Handle WSL nmap specially
        if nmap_path == "wsl nmap":
            # For WSL, we need to run the command differently
            import subprocess
            cmd = f"wsl nmap {arguments} {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                raise Exception(f"Nmap scan failed: {result.stderr}")
            return result.stdout
        else:
            # Use libnmap for regular nmap installations
            nm_proc = NmapProcess(target, arguments, nmap_path=nmap_path)
            nm_proc.run()
            
            if nm_proc.rc != 0:
                raise Exception(f"Nmap scan failed: {nm_proc.stderr}")
            
            return nm_proc.stdout
    except Exception as e:
        logger.error(f"Nmap process error: {str(e)}")
        raise

# Lifespan management
@asynccontextmanager
async def app_lifespan(server: FastMCP) -> Dict[str, Any]:
    logger.info("Starting CybersecurityNMAP server")
    # Test nmap availability at startup
    try:
        nmap_path = get_nmap_path()
        logger.info(f"Nmap available at: {nmap_path}")
    except Exception as e:
        logger.error(f"Nmap not available: {str(e)}")
        raise
    
    try:
        yield {"nmap_available": True}
    finally:
        logger.info("Shutting down CybersecurityNMAP server")

mcp.lifespan = app_lifespan

async def query_shodan(target: str, port: int, service: str) -> Dict[str, Any]:
    """Query Shodan for vulnerability data."""
    if not shodan_api:
        return {"error": "Shodan API not initialized"}
    
    try:
        query = f"port:{port} {service} hostname:{target}"
        result = shodan_api.search(query)
        vulns = []
        for host in result.get("matches", []):
            if host.get("vulns"):
                vulns.extend(host["vulns"])
        return {"cve_ids": vulns, "details": f"Shodan found {len(vulns)} vulnerabilities for {service} on port {port}"}
    except shodan.APIError as e:
        logger.error(f"Shodan API error: {str(e)}")
        return {"error": str(e)}

@mcp.tool(title="Run NMAP Scan")
async def run_nmap_scan(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Run an Nmap scan on a target with specified scan type and optional NSE scripts."""
    try:
        # Check if nmap is available
        if not ctx.request_context.lifespan_context.get("nmap_available"):
            return [TextContent(type="text", text="Error: Nmap is not available")]
        
        target = params.target
        scan_type = params.scan_type
        extra_args = params.extra_args
        nse_scripts = params.nse_scripts
        
        arguments = f"{scan_type} {extra_args}"
        if nse_scripts:
            arguments += f" --script {nse_scripts}"
        arguments = arguments.strip()
        
        logger.info(f"Running Nmap scan: {arguments} on {target}")
        
        # Run nmap using libnmap
        nmap_output = run_nmap_process(target, arguments)
        
        # Parse the XML output
        try:
            nmap_report = NmapParser.parse(nmap_output)
        except Exception as e:
            # If XML parsing fails, return raw output
            logger.warning(f"Failed to parse nmap XML output: {str(e)}")
            return [TextContent(type="text", text=f"Nmap scan completed:\n{nmap_output}")]
        
        results = []
        for host in nmap_report.hosts:
            host_info = f"Host: {host.address} ({host.status})\n"
            ports_info = []
            
            for service in host.services:
                port = service.port
                protocol = service.protocol
                state = service.state
                service_name = service.service or "unknown"
                banner = service.banner or ""
                
                # Get script results if available
                script_results = []
                if hasattr(service, 'scripts') and service.scripts:
                    for script in service.scripts:
                        script_results.append(f"Script {script['id']}: {script['output']}")
                
                script_output = "\n".join(script_results) if script_results else "No script output"
                ports_info.append(f"Port {port}/{protocol}: {state} ({service_name} {banner})\n{script_output}")
            
            if ports_info:
                host_info += "\n".join(ports_info)
            else:
                host_info += "No open ports found."
            results.append(host_info)
        
        scan_id = f"scan_{hash(target + arguments + str(datetime.utcnow()))}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (id, target, scan_type, arguments, results, created_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, scan_type, arguments, "\n".join(results), datetime.utcnow(), "none")
        )
        conn.commit()
        conn.close()
        
        return [TextContent(type="text", text="\n\n".join(results) or "No results found.")]
    
    except Exception as e:
        logger.error(f"Nmap scan error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

@mcp.tool(title="Analyze NMAP Results")
async def analyze_nmap_results(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Analyze cached Nmap scan results for vulnerabilities using Shodan."""
    try:
        target = params.target
        scan_type = params.scan_type
        
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute("SELECT results FROM scans WHERE target = ? AND scan_type = ? ORDER BY created_at DESC LIMIT 1", (target, scan_type))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return [TextContent(type="text", text="No scan results found for this target and scan type.")]
        
        scan_results = result[0]
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for line in scan_results.split("\n"):
                if "Port" in line:
                    port = int(line.split()[1].split("/")[0])
                    service = line.split("(")[1].split(")")[0].split()[0] if "(" in line else "unknown"
                    version = " ".join(line.split("(")[1].split(")")[0].split()[1:]) if "(" in line and len(line.split("(")[1].split(")")[0].split()) > 1 else ""
                    
                    # Query Shodan for vulnerabilities
                    shodan_result = await query_shodan(target, port, service)
                    cve_ids = shodan_result.get("cve_ids", [])
                    shodan_details = shodan_result.get("details", "No Shodan data available")
                    vulnerability = f"{service} vulnerability on port {port} (Version: {version})"
                    
                    vulnerabilities.append(VulnerabilityOutput(
                        target=target,
                        port=port,
                        service=service,
                        vulnerability=vulnerability,
                        cve_id=",".join(cve_ids) if cve_ids else None,
                        shodan_data=shodan_details
                    ))
                    
                    conn = sqlite3.connect("server/cybersecurity.db")
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT OR REPLACE INTO vulnerabilities (target, port, service, vulnerability, cve_id, shodan_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (target, port, service, vulnerability, ",".join(cve_ids) if cve_ids else None, shodan_details, datetime.utcnow())
                    )
                    conn.commit()
                    conn.close()
        
        output = [f"Analysis for {target} ({scan_type}):"]
        for vuln in vulnerabilities:
            output.append(f"Port {vuln.port}: {vuln.service} - {vuln.vulnerability} (CVE: {vuln.cve_id or 'None'}, Shodan: {vuln.shodan_data})")
        
        return [TextContent(type="text", text="\n".join(output) or "No vulnerabilities found.")]
    
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

@mcp.tool(title="Run NSE Vulnerability Scan")
async def run_nse_vulnerability_scan(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Run an Nmap NSE vulnerability scan with specified scripts."""
    try:
        nm = ctx.request_context.lifespan_context["nmap"]
        target = params.target
        scan_type = "-sV"  # NSE requires version detection
        nse_scripts = params.nse_scripts or "vulners,http-vuln-cve2017-5638"
        
        arguments = f"{scan_type} --script {nse_scripts}"
        logger.info(f"Running NSE vulnerability scan: {arguments} on {target}")
        nm.scan(target, arguments=arguments)
        
        results = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                host_info = f"Host: {host} ({nm[host].state()})\n"
                ports_info = []
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]["state"]
                        service = nm[host][proto][port].get("name", "unknown")
                        version = nm[host][proto][port].get("product", "") + " " + nm[host][proto][port].get("version", "")
                        script_output = nm[host][proto][port].get("script", {})
                        script_results = "\n".join(f"Script {k}: {v}" for k, v in script_output.items()) if script_output else "No vulnerabilities found"
                        ports_info.append(f"Port {port}/{proto}: {state} ({service} {version})\nVulnerabilities:\n{script_results}")
                if ports_info:
                    host_info += "\n".join(ports_info)
                else:
                    host_info += "No open ports found."
                results.append(host_info)
        
        scan_id = f"nse_scan_{hash(target + arguments + str(datetime.utcnow()))}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (id, target, scan_type, arguments, results, created_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, scan_type, arguments, "\n".join(results), datetime.utcnow(), "none")
        )
        conn.commit()
        conn.close()
        
        return [TextContent(type="text", text="\n\n".join(results) or "No results found.")]
    
    except Exception as e:
        logger.error(f"NSE scan error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

@mcp.tool(title="Run OS Detection")
async def run_os_detection(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Run Nmap OS detection to identify operating system and version."""
    try:
        nm = ctx.request_context.lifespan_context["nmap"]
        target = params.target
        scan_type = "-O"
        extra_args = params.extra_args
        
        arguments = f"{scan_type} {extra_args}".strip()
        logger.info(f"Running OS detection: {arguments} on {target}")
        nm.scan(target, arguments=arguments)
        
        results = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                host_info = f"Host: {host} ({nm[host].state()})\n"
                os_info = nm[host].get("osmatch", [])
                if os_info:
                    for os in os_info:
                        os_name = os.get("name", "Unknown")
                        accuracy = float(os.get("accuracy", 0))
                        os_details = f"OS: {os_name} (Accuracy: {accuracy}%)"
                        host_info += os_details + "\n"
                        conn = sqlite3.connect("server/cybersecurity.db")
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT OR REPLACE INTO vulnerabilities (target, port, service, vulnerability, cve_id, shodan_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (host, 0, "os", os_details, None, None, datetime.utcnow())
                        )
                        conn.commit()
                        conn.close()
                else:
                    host_info += "No OS information found."
                results.append(host_info)
        
        scan_id = f"os_scan_{hash(target + arguments + str(datetime.utcnow()))}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (id, target, scan_type, arguments, results, created_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, scan_type, arguments, "\n".join(results), datetime.utcnow(), "none")
        )
        conn.commit()
        conn.close()
        
        return [TextContent(type="text", text="\n\n".join(results) or "No results found.")]
    
    except Exception as e:
        logger.error(f"OS detection error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

@mcp.tool(title="Enumerate Services")
async def enumerate_services(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Enumerate detailed service information using Nmap service detection."""
    try:
        nm = ctx.request_context.lifespan_context["nmap"]
        target = params.target
        scan_type = "-sV"
        extra_args = params.extra_args
        nse_scripts = params.nse_scripts or "ssl-cert,http-title"
        
        arguments = f"{scan_type} --version-intensity 9 {extra_args} --script {nse_scripts}".strip()
        logger.info(f"Running service enumeration: {arguments} on {target}")
        nm.scan(target, arguments=arguments)
        
        results = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                host_info = f"Host: {host} ({nm[host].state()})\n"
                ports_info = []
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]["state"]
                        service = nm[host][proto][port].get("name", "unknown")
                        version = nm[host][proto][port].get("product", "") + " " + nm[host][proto][port].get("version", "")
                        extra_info = nm[host][proto][port].get("extrainfo", "")
                        script_output = nm[host][proto][port].get("script", {})
                        script_results = "\n".join(f"Script {k}: {v}" for k, v in script_output.items()) if script_output else "No script output"
                        ports_info.append(f"Port {port}/{proto}: {state} ({service} {version} {extra_info})\n{script_results}")
                if ports_info:
                    host_info += "\n".join(ports_info)
                else:
                    host_info += "No services found."
                results.append(host_info)
        
        scan_id = f"service_scan_{hash(target + arguments + str(datetime.utcnow()))}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (id, target, scan_type, arguments, results, created_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, scan_type, arguments, "\n".join(results), datetime.utcnow(), "none")
        )
        conn.commit()
        conn.close()
        
        return [TextContent(type="text", text="\n\n".join(results) or "No results found.")]
    
    except Exception as e:
        logger.error(f"Service enumeration error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

@mcp.tool(title="Analyze Firewall")
async def analyze_firewall(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Analyze firewall/IDS configurations using Nmap techniques."""
    try:
        nm = ctx.request_context.lifespan_context["nmap"]
        target = params.target
        scan_type = "-sA"  # Use ACK scan for firewall analysis
        extra_args = params.extra_args or "--badsum"
        
        arguments = f"{scan_type} {extra_args}".strip()
        logger.info(f"Running firewall analysis: {arguments} on {target}")
        nm.scan(target, arguments=arguments)
        
        results = []
        for host in nm.all_hosts():
            host_info = f"Host: {host} ({nm[host].state()})\n"
            firewall_detected = False
            details = []
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    state = nm[host][proto][port]["state"]
                    if state == "filtered":
                        firewall_detected = True
                        details.append(f"Port {port}/{proto}: Filtered, indicating a firewall or IDS.")
                    elif state in ["open", "closed"]:
                        details.append(f"Port {port}/{proto}: {state}, suggesting no strict firewall.")
            if "--badsum" in arguments and nm[host].state() == "up":
                details.append("Host responded to bad checksum packets, suggesting relaxed firewall rules.")
            host_info += "\n".join(details) or "No firewall/IDS indicators found."
            results.append(host_info)
        
        scan_id = f"firewall_scan_{hash(target + arguments + str(datetime.utcnow()))}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (id, target, scan_type, arguments, results, created_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, scan_type, arguments, "\n".join(results), datetime.utcnow(), "none")
        )
        conn.commit()
        conn.close()
        
        return [TextContent(type="text", text="\n\n".join(results) or "No results found.")]
    
    except Exception as e:
        logger.error(f"Firewall analysis error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]
@mcp.tool(title="Run Full Pentest Scan")
async def run_full_pentest_scan(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Run a comprehensive pentesting scan combining multiple Nmap techniques and Shodan analysis."""
    try:
        nm = ctx.request_context.lifespan_context["nmap"]
        target = params.target
        nse_scripts = params.nse_scripts or "vulners,http-enum,ssl-cert,http-vuln-cve2017-5638"
        arguments = f"-sS -sV -O --script {nse_scripts} --version-intensity 9"
        
        logger.info(f"Running full pentest scan: {arguments} on {target}")
        nm.scan(target, arguments=arguments)
        
        results = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                host_info = f"Host: {host} ({nm[host].state()})\n"
                # Ports and services
                ports_info = []
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]["state"]
                        service = nm[host][proto][port].get("name", "unknown")
                        version = nm[host][proto][port].get("product", "") + " " + nm[host][proto][port].get("version", "")
                        script_output = nm[host][proto][port].get("script", {})
                        script_results = "\n".join(f"Script {k}: {v}" for k, v in script_output.items()) if script_output else "No script output"
                        
                        # Query Shodan for vulnerabilities
                        shodan_result = await query_shodan(host, port, service)
                        cve_ids = shodan_result.get("cve_ids", [])
                        shodan_details = shodan_result.get("details", "No Shodan data available")
                        
                        ports_info.append(f"Port {port}/{proto}: {state} ({service} {version})\n{script_results}\nShodan: {shodan_details}")
                        
                        conn = sqlite3.connect("server/cybersecurity.db")
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT OR REPLACE INTO vulnerabilities (target, port, service, vulnerability, cve_id, shodan_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (host, port, service, f"{service} on port {port}", ",".join(cve_ids) if cve_ids else None, shodan_details, datetime.utcnow())
                        )
                        conn.commit()
                        conn.close()
                
                if ports_info:
                    host_info += "Ports and Services:\n" + "\n".join(ports_info) + "\n"
                else:
                    host_info += "No open ports found.\n"
                
                # OS detection
                os_info = nm[host].get("osmatch", [])
                if os_info:
                    host_info += "OS Detection:\n"
                    for os in os_info:
                        os_name = os.get("name", "Unknown")
                        accuracy = float(os.get("accuracy", 0))
                        host_info += f"OS: {os_name} (Accuracy: {accuracy}%)\n"
                        conn = sqlite3.connect("server/cybersecurity.db")
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT OR REPLACE INTO vulnerabilities (target, port, service, vulnerability, cve_id, shodan_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (host, 0, "os", f"OS: {os_name}", None, None, datetime.utcnow())
                        )
                        conn.commit()
                        conn.close()
                else:
                    host_info += "No OS information found.\n"
                
                results.append(host_info)
        
        scan_id = f"pentest_scan_{hash(target + arguments + str(datetime.utcnow()))}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (id, target, scan_type, arguments, results, created_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, "pentest", arguments, "\n".join(results), datetime.utcnow(), "none")
        )
        conn.commit()
        conn.close()
        
        return [TextContent(type="text", text="\n\n".join(results) or "No results found.")]
    
    except Exception as e:
        logger.error(f"Full pentest scan error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

@mcp.tool(title="Run Host Discovery")
async def run_host_discovery(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Perform host discovery using Nmap ping scans."""
    try:
        nm = ctx.request_context.lifespan_context["nmap"]
        target = params.target
        scan_type = params.scan_type if params.scan_type in ["-PE", "-PP"] else "-PE"
        extra_args = params.extra_args
        
        arguments = f"{scan_type} {extra_args}".strip()
        logger.info(f"Running host discovery: {arguments} on {target}")
        nm.scan(target, arguments=arguments)
        
        results = []
        for host in nm.all_hosts():
            status = nm[host].state()
            details = f"Host: {host} is {status}"
            if status == "up":
                details += "\nAdditional Info: Host responded to ping scan."
            else:
                details += "\nAdditional Info: Host did not respond to ping scan."
            results.append(details)
            
            conn = sqlite3.connect("server/cybersecurity.db")
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO vulnerabilities (target, port, service, vulnerability, cve_id, shodan_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (host, 0, "host", f"Host status: {status}", None, None, datetime.utcnow())
            )
            conn.commit()
            conn.close()
        
        scan_id = f"host_scan_{hash(target + arguments + str(datetime.utcnow()))}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (id, target, scan_type, arguments, results, created_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, scan_type, arguments, "\n".join(results), datetime.utcnow(), "none")
        )
        conn.commit()
        conn.close()
        
        return [TextContent(type="text", text="\n\n".join(results) or "No hosts found.")]
    
    except Exception as e:
        logger.error(f"Host discovery error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]
@mcp.tool(title="Run Advanced NSE Scan")
async def run_advanced_nse_scan(params: ScanInput, ctx: Context) -> List[TextContent]:
    """Run an advanced Nmap NSE scan with multiple scripts for targeted vulnerability assessment."""
    try:
        nm = ctx.request_context.lifespan_context["nmap"]
        target = params.target
        scan_type = "-sV"  # NSE requires version detection
        nse_scripts = params.nse_scripts or "vulners,http-enum,ftp-anon,mysql-vuln-cve2012-2122"
        
        arguments = f"{scan_type} --script {nse_scripts} --script-args vulnscan=full"
        logger.info(f"Running advanced NSE scan: {arguments} on {target}")
        nm.scan(target, arguments=arguments)
        
        results = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                host_info = f"Host: {host} ({nm[host].state()})\n"
                ports_info = []
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]["state"]
                        service = nm[host][proto][port].get("name", "unknown")
                        version = nm[host][proto][port].get("product", "") + " " + nm[host][proto][port].get("version", "")
                        script_output = nm[host][proto][port].get("script", {})
                        script_results = "\n".join(f"Script {k}: {v}" for k, v in script_output.items()) if script_output else "No vulnerabilities found"
                        
                        # Query Shodan for vulnerabilities
                        shodan_result = await query_shodan(host, port, service)
                        cve_ids = shodan_result.get("cve_ids", [])
                        shodan_details = shodan_result.get("details", "No Shodan data available")
                        
                        ports_info.append(f"Port {port}/{proto}: {state} ({service} {version})\nVulnerabilities:\n{script_results}\nShodan: {shodan_details}")
                        
                        conn = sqlite3.connect("server/cybersecurity.db")
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT OR REPLACE INTO vulnerabilities (target, port, service, vulnerability, cve_id, shodan_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (host, port, service, f"{service} on port {port}", ",".join(cve_ids) if cve_ids else None, shodan_details, datetime.utcnow())
                        )
                        conn.commit()
                        conn.close()
                
                if ports_info:
                    host_info += "\n".join(ports_info)
                else:
                    host_info += "No open ports found."
                results.append(host_info)
        
        scan_id = f"advanced_nse_scan_{hash(target + arguments + str(datetime.utcnow()))}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (id, target, scan_type, arguments, results, created_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target, scan_type, arguments, "\n".join(results), datetime.utcnow(), "none")
        )
        conn.commit()
        conn.close()
        
        return [TextContent(type="text", text="\n\n".join(results) or "No results found.")]
    
    except Exception as e:
        logger.error(f"Advanced NSE scan error: {str(e)}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

if __name__ == "__main__":
    init_db()
    mcp.run()