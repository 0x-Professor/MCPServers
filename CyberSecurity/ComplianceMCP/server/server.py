from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
import sqlite3
import logging
import aiohttp
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent
import os
from dotenv import load_dotenv
import shodan
from datetime import datetime
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ComplianceMCP")

# Load environment variables
load_dotenv()

# Initialize MCP server (no authentication)
mcp = FastMCP(
    "ComplianceManager",
    stateless_http=True,
)

# Database setup
class ComplianceDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework TEXT,
                    status TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id TEXT,
                    framework TEXT,
                    content TEXT,
                    version INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS risk_register (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    risk_id TEXT,
                    description TEXT,
                    severity TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT,
                    description TEXT,
                    status TEXT,
                    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS training_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id TEXT,
                    training_name TEXT,
                    completion_date TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vendor_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vendor_id TEXT,
                    name TEXT,
                    compliance_status TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    system TEXT,
                    access_level TEXT,
                    review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    def log_action(self, action: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO audit_logs (action) VALUES (?)", (action,))

    def get_compliance_status(self, framework: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT status, last_updated FROM compliance_status WHERE framework = ?",
                (framework,)
            )
            result = cursor.fetchone()
            return {"status": result[0], "last_updated": result[1]} if result else None

    def get_policy(self, policy_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT framework, content, version FROM policies WHERE policy_id = ?",
                (policy_id,)
            )
            result = cursor.fetchone()
            return {"framework": result[0], "content": result[1], "version": result[2]} if result else None

    def get_risk(self, risk_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT description, severity FROM risk_register WHERE risk_id = ?",
                (risk_id,)
            )
            result = cursor.fetchone()
            return {"description": result[0], "severity": result[1]} if result else None

    def get_incident(self, incident_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT description, status FROM incidents WHERE incident_id = ?",
                (incident_id,)
            )
            result = cursor.fetchone()
            return {"description": result[0], "status": result[1]} if result else None

    def get_training_records(self, employee_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT training_name, completion_date FROM training_records WHERE employee_id = ?",
                (employee_id,)
            )
            result = cursor.fetchone()
            return {"training_name": result[0], "completion_date": result[1]} if result else None

    def get_vendor_assessment(self, vendor_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT name, compliance_status FROM vendor_assessments WHERE vendor_id = ?",
                (vendor_id,)
            )
            result = cursor.fetchone()
            return {"name": result[0], "compliance_status": result[1]} if result else None

    def get_access_review(self, user_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT system, access_level FROM access_reviews WHERE user_id = ?",
                (user_id,)
            )
            result = cursor.fetchone()
            return {"system": result[0], "access_level": result[1]} if result else None 

# Lifespan management
@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[Dict]:
    db = ComplianceDB("server/compliance.db")
    async with aiohttp.ClientSession() as session:
        shodan_api_key = os.getenv("SHODAN_API_KEY")
        shodan_api = shodan.Shodan(shodan_api_key) if shodan_api_key else None
        yield {"db": db, "http_session": session, "shodan": shodan_api}
    logger.info("Shutting down server")

# set lifespan
mcp.lifespan = app_lifespan

# Structured output models
class ComplianceStatus(BaseModel):
    framework: str = Field(description="Compliance framework (e.g., PCI-DSS, GDPR)")
    status: str = Field(description="Compliance status (Compliant, Non-Compliant, Pending)")
    last_updated: str = Field(description="Last update timestamp")

class PolicyUpdate(BaseModel):
    policy_id: str = Field(description = "Policy Identifier")
    suggestion: str = Field(description = "Suggested Policy update")
    severity: str = Field(description= "Severity level (Low, Medium, High)")

class RiskAssessment(BaseModel):
    risk_id: str = Field(description="Risk identifier")
    description: str = Field(description="Risk description")
    severity: str = Field(description="Severity level (Low, Medium, High)")
    mitigation: str = Field(description="Recommended mitigation")

class EvidenceRecord(BaseModel):
    evidence_id: str = Field(description= "Evidence Identifier")
    framework: str = Field(description= "Associated framework")
    description: str = Field(description= "Evidence description")
    collected_at: str = Field(description= "Collection timestamp")

class ControlValidation(BaseModel):
    control_id: str = Field(description="Control identifier")
    framework: str = Field(description="Associated framework")
    status: str = Field(description="Validation status (Pass, Fail, Pending)")
    details: str = Field(description="Validation details")

class IncidentReport(BaseModel):
    incident_id: str = Field(description="Incident identifier")
    description: str = Field(description="Incident description")
    status: str = Field(description="Incident status (Open, Resolved, In Progress)")
    reported_at: str = Field(description="Reported timestamp")

class GapAnalysis(BaseModel):
    framework: str = Field(description="Compliance framework")
    gaps: List[str] = Field(description="Identified compliance gaps")
    recommendations: List[str] = Field(description="Recommended actions")

class AccessReview(BaseModel):
    user_id: str = Field(description="User identifier")
    system: str = Field(description="System name")
    access_level: str = Field(description="Access level (e.g., Admin, Read-Only)")
    review_date: str = Field(description="Review timestamp")

    
