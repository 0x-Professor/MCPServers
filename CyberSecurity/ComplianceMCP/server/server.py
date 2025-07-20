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

    
# Resources
@mcp.resource("compliance://{framework}", title="Compliance Requirements")
async def get_compliance_requirements(framework: str) -> str:
    """Retrieve requirements for a compliance framework"""
    requirements = {
        "PCI-DSS": "PCI-DSS v4.0: Encryption, access control, regular audits",
        "GDPR": "GDPR: Data minimization, consent, right to erasure",
        "HIPAA": "HIPAA: Protected health information, risk analysis, security measures",
        "ISO27001": "ISO 27001: Information security management, risk assessment, controls"
    }
    return requirements.get(framework, "Unknown framework")

@mcp.resource("audit://logs", title="Audit Logs")
async def get_audit_logs() -> str:
    """Retrieve recent audit logs"""
    with sqlite3.connect("server/compliance.db") as conn:
        cursor = conn.execute("SELECT action, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 10")
        logs = [f"{row[0]} at {row[1]}" for row in cursor.fetchall()]
        return "\n".join(logs) if logs else "No audit logs found"

@mcp.resource("policy://{policy_id}", title = "Policy Document")
async def get_policy_document(ploicy_id: str, ctx: Context) -> str:
    """Retrieve a specific policy document"""
    db = ctx.request_context.lifespan_context["db"]
    policy = db.get_policy(policy_id)
    return policy["connect"] if policy else "Policy not found"

@mcp.resource("control://{framework}", title="Control Mappings")
async def get_control_mappings(framework: str) -> str:
    """Retrieve control mappings for a framework"""
    controls = {
        "PCI-DSS": "Requirement 1: Firewall configuration, Requirement 3: Data encryption",
        "GDPR": "Article 5: Principles, Article 32: Security of processing",
        "HIPAA": "164.308: Administrative safeguards, 164.312: Technical safeguards",
        "ISO27001": "A.12.4: Logging and monitoring, A.14.2: Security in development"
    }
    return controls.get(framework, "No controls found")

@mcp.resource("risk://register", title="Risk Register")
async def get_risk_register(ctx: Context) -> str:
    """Retrieve the risk register"""
    with sqlite3.connect("server/compliance.db") as conn:
        cursor = conn.execute("SELECT risk_id, description, severity FROM risk_register LIMIT 10")
        risks = [f"{row[0]}: {row[1]} (Severity: {row[2]})" for row in cursor.fetchall()]
        return "\n".join(risks) if risks else "No risks found"

@mcp.resource("incident://logs", title="Incident Logs")
async def get_incident_logs() -> str:
    """Retrieve recent incident logs"""
    with sqlite3.connect("server/compliance.db") as conn:
        cursor = conn.execute("SELECT incident_id, description, status, reported_at FROM incidents ORDER BY reported_at DESC LIMIT 10")
        incidents = [f"{row[0]}: {row[1]} ({row[2]}) at {row[3]}" for row in cursor.fetchall()]
        return "\n".join(incidents) if incidents else "No incidents found"

@mcp.resource("training://records", title="Training Records")
async def get_training_records() -> str:
    """Retrieve employee training records"""
    with sqlite3.connect("server/compliance.db") as conn:
        cursor = conn.execute("SELECT employee_id, training_name, completion_date FROM training_records ORDER BY completion_date DESC LIMIT 10")
        records = [f"{row[0]}: {row[1]} (Completed: {row[2]})" for row in cursor.fetchall()]
        return "\n".join(records) if records else "No training records found"

@mcp.resource("vendor://{vendor_id}", title="Vendor Profile")
async def get_vendor_profile(vendor_id: str, ctx: Context) -> str:
    """Retrieve a vendor's compliance profile"""
    with sqlite3.connect("server/compliance.db") as conn:
        cursor = conn.execute("SELECT name, compliance_status FROM vendor_assessments WHERE vendor_id = ?", (vendor_id,))
        result = cursor.fetchone()
        return f"{result[0]}: {result[1]}" if result else "Vendor not found"

@mcp.resource("data://flows", title="Data Flows")
async def get_data_flows() -> str:
    """Retrieve data flow mappings"""
    return "Data Flow: CRM -> Database -> Analytics (GDPR-compliant)"

@mcp.resource("encryption://standards", title="Encryption Standards")
async def get_encryption_standards() -> str:
    """Retrieve encryption standards for compliance"""
    return "Standards: AES-256, RSA-2048, TLS 1.3"

# Tools
@mcp.tool(title="Check Compliance Status")
async def check_compliance_status(framework: str, ctx: Context) -> ComplianceStatus:
    """Check compliance status for a framework using Eramba API"""
    http_session = ctx.request_context.lifespan_context["http_session"]
    db = ctx.request_context.lifespan_context["db"]
    eramba_api_key = os.getenv("ERAMBA_API_KEY")
    
    if not eramba_api_key:
        logger.warning("ERAMBA_API_KEY not set, using local data")
        status = db.get_compliance_status(framework)
        return ComplianceStatus(
            framework=framework,
            status=status["status"] if status else "Pending",
            last_updated=status["last_updated"] if status else str(datetime.utcnow())
        )
    
    try:
        async with http_session.get(
            f"http://localhost:8080/api/compliance/{framework}",
            headers={"X-API-Key": eramba_api_key}
        ) as response:
            data = await response.json()
            status = data.get("status", "Pending")
            db.log_action(f"Checked {framework} compliance: {status}")
            return ComplianceStatus(
                framework=framework,
                status=status,
                last_updated=data.get("last_updated", str(datetime.utcnow()))
            )
    except Exception as e:
        logger.error(f"Eramba API error: {str(e)}")
        return ComplianceStatus(
            framework=framework,
            status=f"Error: {str(e)}",
            last_updated=str(datetime.utcnow())
        )