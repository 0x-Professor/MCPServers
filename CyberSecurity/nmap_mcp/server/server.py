import os
import asyncio
import logging
import sqlite3
import nmap
from datetime import datetime
from contextlib import asynccontextmanager
from typing import List, Dict, Any
from pydantic import BaseModel, Field, validator
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
    