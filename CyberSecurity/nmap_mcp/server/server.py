import os
import asyncio
import logging
import sqlite3
import nmap
from datetime import datetime
from contextlib import asynccontextmanager
from typing import List, Dict, Any
from pydantic import BaseModel, Field, filed_validator
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent
from mcp.server.auth.provider import TokenVerifier, TokenInfo
from mcp.server.auth.settings import AuthSettings
import aiohttp
from aiohttp import web
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
    conn = sqlite3.connect("server/cybersecurity.db")
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

# Rate limiting middleware
async def rate_limit_middleware(app, handler):
    async def middleware(request):
        client_ip = request.remote
        cache_key = f"rate_limit_{client_ip}"
        conn = sqlite3.connect("server/cybersecurity.db")
        cursor = conn.cursor()
        cursor.execute("SELECT count, last_reset FROM rate_limits WHERE ip = ?", (client_ip,))
        result = cursor.fetchone()
        
        current_time = datetime.utcnow().timestamp()
        if result:
            count, last_reset = result
            if current_time - last_reset > 60:
                count = 0
                cursor.execute("UPDATE rate_limits SET count = 0, last_reset = ? WHERE ip = ?", (current_time, client_ip))
            if count >= 15:
                conn.close()
                raise web.HTTPTooManyRequests(text="Rate limit exceeded. Try again in 60 seconds.")
            cursor.execute("UPDATE rate_limits SET count = count + 1 WHERE ip = ?", (client_ip,))
        else:
            cursor.execute("INSERT INTO rate_limits (ip, count, last_reset) VALUES (?, 1, ?)", (client_ip, current_time))
        
        conn.commit()
        conn.close()
        return await handler(request)
    return middleware

# OAuth Token Verifier
class SimpleTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> TokenInfo:
        if token == os.getenv("OAUTH_TOKEN"):
            return TokenInfo(
                active=True,
                scope=["cyber:scan", "cyber:analyze", "cyber:pentest"],
                client_id="mcp-client",
                exp=datetime.utcnow().timestamp() + 3600
            )
        raise ValueError("Invalid token")

# MCP Server
mcp = FastMCP(
    name="CybersecurityNMAP",
    token_verifier=SimpleTokenVerifier(),
    auth=AuthSettings(
        issuer_url="https://auth.example.com",
        resource_server_url="http://localhost:6027",
        required_scopes=["cyber:scan", "cyber:analyze", "cyber:pentest"]
    ),
    stateless_http=True
)

# Apply rate limiting middleware
mcp.streamable_http_app().middleware(rate_limit_middleware)

# Lifespan management
@asynccontextmanager
async def app_lifespan(server: FastMCP) -> Dict[str, Any]:
    logger.info("Starting CybersecurityNMAP server")
    nm = nmap.PortScanner()
    try:
        yield {"nmap": nm}
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
        nm = ctx.request_context.lifespan_context["nmap"]
        target = params.target
        scan_type = params.scan_type
        extra_args = params.extra_args
        nse_scripts = params.nse_scripts
        
        arguments = f"{scan_type} {extra_args}"
        if nse_scripts:
            arguments += f" --script {nse_scripts}"
        arguments = arguments.strip()
        
        logger.info(f"Running Nmap scan: {arguments} on {target}")
        nm.scan(target, arguments=arguments)
        
        results = []
        for host in nm.all_hosts():
            host_info = f"Host: {host} ({nm[host].state()})\n"
            ports_info = []
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]["state"]
                    service = nm[host][proto][port].get("name", "unknown")
                    version = nm[host][proto][port].get("product", "") + " " + nm[host][proto][port].get("version", "")
                    script_output = nm[host][proto][port].get("script", {})
                    script_results = "\n".join(f"Script {k}: {v}" for k, v in script_output.items()) if script_output else "No script output"
                    ports_info.append(f"Port {port}/{proto}: {state} ({service} {version})\n{script_results}")
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

