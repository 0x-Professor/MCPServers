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

    