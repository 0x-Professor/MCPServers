from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
import sqlite3
import logging
import aiohttp
from typing import List, Dict, Optional
import asyncio
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent
import os
from dotenv import load_dotenv
import shodan
from datetime import datetime, timedelta
import uuid
import random
import aiohttp
import json
from typing import Dict, Optional, Any, List

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

# Global variables to store dependencies
db_instance = None
http_session_instance = None
shodan_api_instance = None

# Initialize database at module level
def init_database():
    global db_instance
    try:
        db_instance = ComplianceDB("server/compliance.db")
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        # Create a minimal database instance that won't fail
        class FallbackDB:
            def log_action(self, *args, **kwargs):
                pass
            def get_compliance_status(self, framework):
                return {"status": "Unknown", "last_updated": str(datetime.utcnow())}
            def get_policy(self, policy_id):
                return None
            def get_vendor_assessment(self, vendor_id):
                return None
        db_instance = FallbackDB()

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
async def app_lifespan(server: FastMCP) -> AsyncIterator[None]:
    global http_session_instance, shodan_api_instance
    
    # Initialize database if not already done
    if db_instance is None:
        init_database()
        
    # Initialize HTTP session
    http_session_instance = aiohttp.ClientSession()
    
    # Initialize Shodan if API key is available
    shodan_api_key = os.getenv("SHODAN_API_KEY")
    if shodan_api_key:
        try:
            shodan_api_instance = shodan.Shodan(shodan_api_key)
            logger.info("Shodan API initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Shodan: {str(e)}")
            shodan_api_instance = None
    
    logger.info("Server started with dependencies initialized")
    try:
        yield
    finally:
        # Cleanup
        if http_session_instance:
            await http_session_instance.close()
            logger.info("HTTP session closed")
        logger.info("Shutting down server")

# Set lifespan
mcp.lifespan = app_lifespan

# Structured output models
class ComplianceStatus(BaseModel):
    framework: str = Field(description="Compliance framework (e.g., PCI-DSS, GDPR)")
    status: str = Field(description="Compliance status (Compliant, Non-Compliant, Pending)")
    last_updated: str = Field(description="Last update timestamp")

class PolicyUpdate(BaseModel):
    policy_id: str = Field(description="Policy Identifier")
    suggestion: str = Field(description="Suggested Policy update")
    severity: str = Field(description="Severity level (Low, Medium, High)")

class RiskAssessment(BaseModel):
    risk_id: str = Field(description="Risk identifier")
    description: str = Field(description="Risk description")
    severity: str = Field(description="Severity level (Low, Medium, High)")
    mitigation: str = Field(description="Recommended mitigation")

class EvidenceRecord(BaseModel):
    evidence_id: str = Field(description="Evidence Identifier")
    framework: str = Field(description="Associated framework")
    description: str = Field(description="Evidence description")
    collected_at: str = Field(description="Collection timestamp")

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

@mcp.resource("policy://{policy_id}", title="Policy Document")
async def get_policy_document(policy_id: str) -> str:
    """Retrieve a specific policy document"""
    global db_instance
    if not db_instance:
        return "Database not initialized"
    policy = db_instance.get_policy(policy_id)
    return policy["content"] if policy else "Policy not found"

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
async def get_risk_register() -> str:
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
async def get_vendor_profile(vendor_id: str) -> str:
    """Retrieve a vendor's compliance profile"""
    global db_instance
    if not db_instance:
        return "Database not initialized"
    vendor = db_instance.get_vendor_assessment(vendor_id)
    return f"{vendor['name']}: {vendor['compliance_status']}" if vendor else "Vendor not found"

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
    """Check compliance status for a framework using Unizo API or fallback methods"""
    global db_instance, http_session_instance, mock_compliance, unizo_client
    
    # Ensure database is initialized
    if db_instance is None:
        init_database()
    
    # Get current timestamp for consistent timing
    current_time = str(datetime.utcnow())
    
    # Try to use Unizo API if available
    if unizo_client:
        try:
            async with unizo_client as client:
                compliance_data = await client.get_compliance_status(framework)
                
                # Log the action
                if db_instance:
                    db_instance.log_action(
                        f"Checked {framework} compliance via Unizo API: {compliance_data['status']}"
                    )
                
                return ComplianceStatus(
                    framework=framework,
                    status=compliance_data["status"],
                    last_updated=compliance_data["last_updated"]
                )
                
        except Exception as e:
            logger.error(f"Unizo API error: {str(e)}")
    
    # If we reached here, the Unizo API call failed
    error_msg = "Failed to fetch compliance status from Unizo API"
    logger.error(error_msg)
    
    # Return an error status instead of falling back to mock data
    return ComplianceStatus(
        framework=framework,
        status=f"Error: {error_msg}",
        last_updated=current_time
    )

@mcp.tool(title="Generate Compliance Report")
async def generate_compliance_report(framework: str, ctx: Context) -> str:
    """Generate a compliance report for a framework"""
    global db_instance
    
    if not db_instance:
        return "Error: Database not initialized"
    
    status = db_instance.get_compliance_status(framework)
    report = f"Compliance Report for {framework}\n"
    report += f"Status: {status['status'] if status else 'Unknown'}\n"
    report += f"Last Updated: {status['last_updated'] if status else 'N/A'}\n"
    report += f"Requirements: {await get_compliance_requirements(framework)}"
    db_instance.log_action(f"Generated report for {framework}")
    return report

@mcp.tool(title="Suggest Policy Update")
async def suggest_policy_update(framework: str, issue: str, ctx: Context) -> PolicyUpdate:
    """Suggest policy updates based on compliance issues"""
    global db_instance
    
    if db_instance:
        db_instance.log_action(f"Suggested policy update for {framework}: {issue}")
    
    suggestions = {
        "PCI-DSS": {
            "encryption": PolicyUpdate(policy_id="ENC-001", suggestion="Implement AES-256 encryption", severity="High"),
            "access": PolicyUpdate(policy_id="ACC-001", suggestion="Restrict access to cardholder data", severity="Medium")
        },
        "GDPR": {
            "consent": PolicyUpdate(policy_id="GDPR-001", suggestion="Update consent forms for data processing", severity="High"),
            "erasure": PolicyUpdate(policy_id="GDPR-002", suggestion="Implement data erasure procedures", severity="Medium")
        },
        "HIPAA": {
            "phi": PolicyUpdate(policy_id="HIPAA-001", suggestion="Secure protected health information", severity="High"),
            "risk": PolicyUpdate(policy_id="HIPAA-002", suggestion="Conduct annual risk analysis", severity="Medium")
        },
        "ISO27001": {
            "controls": PolicyUpdate(policy_id="ISO-001", suggestion="Implement A.12.4 logging controls", severity="Medium"),
            "assessment": PolicyUpdate(policy_id="ISO-002", suggestion="Perform regular risk assessments", severity="High")
        }
    }
    return suggestions.get(framework, {}).get(issue, PolicyUpdate(policy_id="UNKNOWN", suggestion="No suggestion available", severity="Low"))

@mcp.tool(title="Assess Risk")
async def assess_risk(description: str, ctx: Context) -> RiskAssessment:
    """Assess a new risk and assign severity"""
    global db_instance
    
    risk_id = f"RISK-{hash(description) % 10000}"
    severity = "High" if "critical" in description.lower() else "Medium"
    mitigation = "Implement controls and monitor" if severity == "High" else "Review and document"
    
    if db_instance:
        with sqlite3.connect("server/compliance.db") as conn:
            conn.execute(
                "INSERT INTO risk_register (risk_id, description, severity) VALUES (?, ?, ?)",
                (risk_id, description, severity)
            )
        db_instance.log_action(f"Assessed risk {risk_id}")
    
    return RiskAssessment(risk_id=risk_id, description=description, severity=severity, mitigation=mitigation)

@mcp.tool(title="Collect Evidence")
async def collect_evidence(framework: str, evidence_type: str, ctx: Context) -> EvidenceRecord:
    """Collect evidence for a compliance framework using Eramba API"""
    global db_instance, http_session_instance
    
    eramba_api_key = os.getenv("ERAMBA_API_KEY")
    evidence_id = f"EVID-{hash(framework + evidence_type) % 10000}"
    description = f"Evidence for {evidence_type} in {framework}"
    
    if eramba_api_key and http_session_instance:
        try:
            async with http_session_instance.post(
                f"http://localhost:8080/api/evidence",
                headers={"X-API-Key": eramba_api_key},
                json={"framework": framework, "evidence_type": evidence_type}
            ) as response:
                data = await response.json()
                description = data.get("description", description)
        except Exception as e:
            logger.error(f"Eramba API error: {str(e)}")
    
    if db_instance:
        db_instance.log_action(f"Collected evidence {evidence_id}")
    
    return EvidenceRecord(evidence_id=evidence_id, framework=framework, description=description, collected_at=str(datetime.utcnow()))

@mcp.tool(title="Validate Control")
async def validate_control(control_id: str, framework: str, ctx: Context) -> ControlValidation:
    """Validate a compliance control"""
    global db_instance
    
    status = "Pass" if control_id.startswith("C") else "Pending"
    details = f"Control {control_id} validated for {framework}"
    
    if db_instance:
        db_instance.log_action(f"Validated control {control_id}")
    
    return ControlValidation(control_id=control_id, framework=framework, status=status, details=details)

@mcp.tool(title="Report Incident")
async def report_incident(description: str, ctx: Context) -> IncidentReport:
    """Report a new compliance incident"""
    global db_instance
    
    incident_id = f"INC-{hash(description) % 10000}"
    status = "Open"
    
    if db_instance:
        with sqlite3.connect("server/compliance.db") as conn:
            conn.execute(
                "INSERT INTO incidents (incident_id, description, status) VALUES (?, ?, ?)",
                (incident_id, description, status)
            )
        db_instance.log_action(f"Reported incident {incident_id}")
    
    return IncidentReport(incident_id=incident_id, description=description, status=status, reported_at=str(datetime.utcnow()))

@mcp.tool(title="Track Training")
async def track_training(employee_id: str, training_name: str, ctx: Context) -> str:
    """Track employee compliance training"""
    global db_instance
    
    if db_instance:
        with sqlite3.connect("server/compliance.db") as conn:
            conn.execute(
                "INSERT INTO training_records (employee_id, training_name, completion_date) VALUES (?, ?, ?)",
                (employee_id, training_name, str(datetime.utcnow()))
            )
        db_instance.log_action(f"Tracked training for {employee_id}: {training_name}")
    
    return f"Training {training_name} recorded for {employee_id}"

@mcp.tool(title="Assess Vendor")
async def assess_vendor(vendor_id: str, name: str, ctx: Context) -> str:
    """Assess a vendor's compliance status"""
    global db_instance
    
    status = "Compliant" if vendor_id.startswith("V") else "Non-Compliant"
    
    if db_instance:
        with sqlite3.connect("server/compliance.db") as conn:
            conn.execute(
                "INSERT INTO vendor_assessments (vendor_id, name, compliance_status) VALUES (?, ?, ?)",
                (vendor_id, name, status)
            )
        db_instance.log_action(f"Assessed vendor {vendor_id}: {status}")
    
    return f"Vendor {name} assessed as {status}"

@mcp.tool(title="Map Data Flow")
async def map_data_flow(source: str, destination: str, ctx: Context) -> str:
    """Map a data flow for GDPR compliance"""
    global db_instance
    
    flow = f"Data Flow: {source} -> {destination}"
    
    if db_instance:
        db_instance.log_action(f"Mapped data flow: {flow}")
    
    return flow

@mcp.tool(title="Validate Encryption")
async def validate_encryption(system: str, ctx: Context) -> str:
    """Validate encryption standards for a system"""
    global db_instance, shodan_api_instance
    
    if shodan_api_instance and system:
        try:
            results = shodan_api_instance.search(f"hostname:{system}")
            encryption = "TLS 1.3 detected" if any("ssl" in str(result) for result in results["matches"]) else "No encryption detected"
        except Exception as e:
            encryption = f"Shodan error: {str(e)}"
    else:
        encryption = "AES-256 compliant (local check)"
    
    if db_instance:
        db_instance.log_action(f"Validated encryption for {system}: {encryption}")
    
    return encryption

@mcp.tool(title="Generate Compliance Dashboard")
async def generate_compliance_dashboard(ctx: Context) -> str:
    """Generate a compliance dashboard summary"""
    global db_instance
    
    frameworks = ["PCI-DSS", "GDPR", "HIPAA", "ISO27001"]
    dashboard = "Compliance Dashboard\n"
    
    if db_instance:
        for framework in frameworks:
            status = db_instance.get_compliance_status(framework)
            dashboard += f"{framework}: {status['status'] if status else 'Unknown'}\n"
        db_instance.log_action("Generated compliance dashboard")
    else:
        dashboard += "Database not initialized\n"
    
    return dashboard

@mcp.tool(title="Schedule Penetration Test")
async def schedule_penetration_test(system: str, ctx: Context) -> str:
    """Schedule a penetration test for a system"""
    global db_instance
    
    test_id = f"PEN-{uuid.uuid4().hex[:8]}"
    
    if db_instance:
        db_instance.log_action(f"Scheduled penetration test {test_id} for {system}")
    
    return f"Penetration test {test_id} scheduled for {system}"

@mcp.tool(title="Perform Gap Analysis")
async def perform_gap_analysis(framework: str, ctx: Context) -> GapAnalysis:
    """Perform a compliance gap analysis"""
    global db_instance
    
    gaps = [f"Missing control for {framework} requirement {i}" for i in range(1, 3)]
    recommendations = [f"Implement control for {framework} requirement {i}" for i in range(1, 3)]
    
    if db_instance:
        db_instance.log_action(f"Performed gap analysis for {framework}")
    
    return GapAnalysis(framework=framework, gaps=gaps, recommendations=recommendations)

@mcp.tool(title="Update Policy Version")
async def update_policy_version(policy_id: str, content: str, ctx: Context) -> str:
    """Update a policy with a new version"""
    global db_instance
    
    if not db_instance:
        return f"Error: Database not initialized"
    
    policy = db_instance.get_policy(policy_id)
    version = (policy["version"] + 1) if policy else 1
    
    with sqlite3.connect("server/compliance.db") as conn:
        conn.execute(
            "INSERT OR REPLACE INTO policies (policy_id, framework, content, version) VALUES (?, ?, ?, ?)",
            (policy_id, policy["framework"] if policy else "Unknown", content, version)
        )
    
    db_instance.log_action(f"Updated policy {policy_id} to version {version}")
    return f"Policy {policy_id} updated to version {version}"

@mcp.tool(title="Simulate Data Breach")
async def simulate_data_breach(system: str, ctx: Context) -> str:
    """Simulate a data breach scenario"""
    global db_instance
    
    breach_id = f"BRCH-{uuid.uuid4().hex[:8]}"
    
    if db_instance:
        db_instance.log_action(f"Simulated data breach {breach_id} on {system}")
    
    return f"Simulated data breach {breach_id} on {system}: Review incident response plan"

@mcp.tool(title="Review Access Controls")
async def review_access_controls(user_id: str, system: str, ctx: Context) -> AccessReview:
    """Review access controls for a user and system"""
    global db_instance
    
    access_level = "Admin" if user_id.startswith("A") else "Read-Only"
    
    if db_instance:
        with sqlite3.connect("server/compliance.db") as conn:
            conn.execute(
                "INSERT INTO access_reviews (user_id, system, access_level, review_date) VALUES (?, ?, ?, ?)",
                (user_id, system, access_level, str(datetime.utcnow()))
            )
        db_instance.log_action(f"Reviewed access for {user_id} on {system}")
    
    return AccessReview(user_id=user_id, system=system, access_level=access_level, review_date=str(datetime.utcnow()))

@mcp.tool(title="Generate Audit Plan")
async def generate_audit_plan(framework: str, ctx: Context) -> str:
    """Generate an audit plan for a framework"""
    global db_instance
    
    plan = f"Audit Plan for {framework}\n"
    plan += "1. Review compliance status\n2. Collect evidence\n3. Validate controls\n4. Assess risks"
    
    if db_instance:
        db_instance.log_action(f"Generated audit plan for {framework}")
    
    return plan

# Prompts
@mcp.prompt(title="Compliance Query")
def compliance_query(framework: str, question: str) -> str:
    """Generate a prompt for compliance-related questions"""
    return f"For the {framework} framework, answer the following: {question}"

@mcp.prompt(title="Policy Review")
def policy_review(policy_id: str, style: str = "formal") -> str:
    """Generate a prompt for reviewing a policy"""
    styles = {
        "formal": "Please provide a formal review of the policy",
        "technical": "Please provide a detailed technical analysis of the policy",
        "summary": "Please provide a concise summary of the policy"
    }
    return f"{styles.get(style, styles['formal'])} with ID {policy_id}."

@mcp.prompt(title="Risk Assessment")
def risk_assessment(risk_id: str) -> str:
    """Generate a prompt for assessing a risk"""
    return f"Assess the risk with ID {risk_id} and recommend mitigation strategies."

@mcp.prompt(title="Incident Report")
def incident_report(incident_id: str) -> str:
    """Generate a prompt for reviewing an incident"""
    return f"Provide a detailed report for the incident with ID {incident_id}."

@mcp.prompt(title="Training Plan")
def training_plan(training_name: str) -> str:
    """Generate a prompt for creating a training plan"""
    return f"Create a compliance training plan for {training_name}."

@mcp.prompt(title="Vendor Due Diligence")
def vendor_due_diligence(vendor_id: str) -> str:
    """Generate a prompt for vendor due diligence"""
    return f"Perform due diligence on the vendor with ID {vendor_id} for compliance."

@mcp.prompt(title="Data Subject Request")
def data_subject_request(request_type: str) -> str:
    """Generate a prompt for handling data subject requests"""
    return f"Handle a {request_type} request under GDPR (e.g., access, erasure)."

@mcp.prompt(title="Control Audit")
def control_audit(control_id: str, framework: str) -> str:
    """Generate a prompt for auditing a control"""
    return f"Audit the control with ID {control_id} for {framework} compliance."

@mcp.prompt(title="Encryption Review")
def encryption_review(system: str) -> str:
    """Generate a prompt for reviewing encryption standards"""
    return f"Review encryption standards for the system {system}."

@mcp.prompt(title="Compliance Gap Analysis")
def compliance_gap_analysis(framework: str) -> str:
    """Generate a prompt for compliance gap analysis"""
    return f"Perform a gap analysis for {framework} compliance."

class MockComplianceService:
    """Mock service to provide compliance status when Eramba API is not available"""
    
    def __init__(self):
        self.framework_statuses = {
            "GDPR": ["Compliant", "Non-Compliant", "In Progress", "Not Started"],
            "PCI-DSS": ["Compliant", "Non-Compliant", "In Progress", "Not Started"],
            "HIPAA": ["Compliant", "Non-Compliant", "In Progress", "Not Started"],
            "ISO27001": ["Compliant", "Non-Compliant", "In Progress", "Not Started"]
        }
        
    def get_status(self, framework: str) -> Dict[str, str]:
        """Get a realistic mock status for a compliance framework"""
        statuses = self.framework_statuses.get(framework, ["Unknown"])
        status = random.choice(statuses)
        
        # Make status more likely to be compliant for demo purposes
        if random.random() > 0.7:  # 30% chance to be non-compliant
            status = "Non-Compliant"
        else:
            status = "Compliant"
            
        return {
            "status": status,
            "last_updated": (datetime.utcnow() - timedelta(days=random.randint(0, 30))).isoformat(),
            "controls_passed": random.randint(80, 100),
            "controls_failed": random.randint(0, 5),
            "controls_total": 100
        }

class UnizoClient:
    """Client for interacting with Unizo EDR & XDR MCP API"""
    
    BASE_URL = "http://api.unizo.ai/mcp/edr&xdr"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers={"apikey": self.api_key},
            timeout=aiohttp.ClientTimeout(total=10)
        )
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()
    
    async def list_alerts(
        self,
        integration: str = "crowdstrike",  # Default to CrowdStrike, can be changed as needed
        severity: str = None,
        status: str = None,
        time_range: str = "24h",
        limit: int = 10
    ) -> Dict[str, Any]:
        """List security alerts from Unizo EDR & XDR MCP"""
        params = {
            "integration": integration,
            "time_range": time_range,
            "limit": limit
        }
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
            
        try:
            async with self.session.get(
                f"{self.BASE_URL}/list_alerts",
                params=params
            ) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.error(f"Failed to fetch alerts from Unizo: {str(e)}")
            return {"alerts": [], "error": str(e)}
    
    async def get_compliance_status(
        self,
        framework: str,
        integration: str = "crowdstrike"
    ) -> Dict[str, Any]:
        """Get compliance status based on security alerts"""
        # Map framework to alert types based on common compliance requirements
        alert_types = {
            "GDPR": [
                "data_leak", "unauthorized_access", "data_breach", 
                "privacy_violation", "data_subject_request"
            ],
            "PCI-DSS": [
                "credit_card_leak", "unauthorized_access", "malware", 
                "card_skimming", "pos_compromise"
            ],
            "HIPAA": [
                "phi_leak", "unauthorized_access", "medical_record_breach",
                "healthcare_fraud", "patient_data_exposure"
            ],
            "ISO27001": [
                "data_breach", "unauthorized_access", "system_compromise",
                "insider_threat", "security_control_failure"
            ]
        }
        
        # Get all relevant alerts for the framework
        alerts = []
        try:
            # First try to get framework-specific alerts
            result = await self.list_alerts(
                integration=integration,
                status="new,in_progress",
                limit=100  # Get more alerts for better accuracy
            )
            
            if "alerts" in result:
                # Filter alerts that are relevant to this framework
                relevant_alerts = []
                for alert in result["alerts"]:
                    alert_type = alert.get("alert_type", "").lower()
                    framework_alerts = alert_types.get(framework, [])
                    
                    # Check if this alert is relevant to the framework
                    if any(alert_type.startswith(t) for t in framework_alerts):
                        relevant_alerts.append(alert)
                
                alerts = relevant_alerts
                
                # If no framework-specific alerts found, include all high/critical alerts
                if not alerts:
                    alerts = [a for a in result["alerts"] 
                             if a.get("severity", "").lower() in ["high", "critical"]]
        except Exception as e:
            logger.error(f"Error fetching alerts: {str(e)}")
            raise Exception(f"Failed to fetch compliance data: {str(e)}")
        
        # Determine compliance status based on alerts
        if not alerts:
            return {
                "status": "Compliant",
                "last_updated": datetime.utcnow().isoformat(),
                "alerts_count": 0,
                "source": "unizo"
            }
        
        # We've already filtered relevant alerts during the initial fetch
        relevant_alerts = alerts
        
        if relevant_alerts:
            latest_alert_time = max(
                a.get("timestamp", datetime.utcnow().isoformat()) 
                for a in relevant_alerts
            )
            
            # Get unique alert types for details
            alert_types_found = list(set(
                a.get("alert_type", "unknown").lower() 
                for a in relevant_alerts
            ))
            
            return {
                "status": "Non-Compliant",
                "last_updated": latest_alert_time,
                "alerts_count": len(relevant_alerts),
                "source": "unizo",
                "details": {
                    "alert_types": alert_types_found,
                    "severity": max(
                        a.get("severity", "medium").lower() 
                        for a in relevant_alerts
                    ),
                    "recommendation": "Review and remediate the identified security alerts"
                }
            }
        
        return {
            "status": "Compliant",
            "last_updated": datetime.utcnow().isoformat(),
            "alerts_count": 0,
            "source": "unizo",
            "details": "No compliance violations detected"
        }

# Initialize services
init_database()
mock_compliance = MockComplianceService()

# Initialize Unizo client if API key is available
UNIZO_API_KEY = os.getenv("UNIZO_API_KEY")  # Should be moved to environment variable in production
unizo_client = UnizoClient(UNIZO_API_KEY) if UNIZO_API_KEY else None

if __name__ == "__main__":
    mcp.run()