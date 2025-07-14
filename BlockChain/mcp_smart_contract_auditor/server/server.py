from mcp.server.fastmcp import FastMCP
import json
import re
import asyncio
import hashlib
import time
import logging
from dotenv import load_dotenv
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import httpx
from web3 import Web3, HTTPProvider

load_dotenv()
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "YOUR_ETHERSCAN_API_KEY")
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID", "YOUR_INFURA_PROJECT_ID")
SUPPORTED_CHAINS = {
    "ethereum": {"rpc": f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}", "explorer": "https://api.etherscan.io/api"},
    "polygon": {"rpc": "https://polygon-rpc.com", "explorer": "https://api.polygonscan.com/api"},
    "bsc": {"rpc": "https://bsc-dataseed.binance.org", "explorer": "https://api.bscscan.com/api"},
    "arbitrum": {"rpc": "https://arb1.arbitrum.io/rpc", "explorer": "https://api.arbiscan.io/api"},
    "optimism": {"rpc": "https://mainnet.optimism.io", "explorer": "https://api-optimistic.etherscan.io/api"}
}

mcp = FastMCP("Smart_contract_auditor")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    REENTRANCY = "Reentrancy"
    INTEGER_OVERFLOW = "Integer Overflow"
    ACCESS_CONTROL = "Access Control"
    UNCHECKED_EXTERNAL_CALL = "Unchecked External Call"
    TIMESTAMP_DEPENDENCY = "Timestamp Dependency"
    DELEGATECALL = "DelegateCall"
    UNINITIALIZED_STORAGE = "Uninitialized Storage"
    FRONT_RUNNING = "Front Running"
    DENIAL_OF_SERVICE = "Denial of Service"
    WEAK_RANDOMNESS = "Weak Randomness"
    FLASH_LOAN_ATTACK = "Flash Loan Attack"
    SANDWICH_ATTACK = "Sandwich Attack"
    MEV_VULNERABILITY = "MEV Vulnerability"
    GOVERNANCE_ATTACK = "Governance Attack"
    ORACLE_MANIPULATION = "Oracle Manipulation"
    
class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    INFO = "Info"
    
@dataclass
class Vulnerability:
    type: VulnerabilityType
    severity: Severity
    title: str
    description: str
    code_snippet: str
    impact: str
    remediation: str
    location: str
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None
    references: List[str] = None
    
@dataclass
class AuditReport:
    contract_address: str
    contract_name: str
    chain: str
    audit_timestamp: str
    vulnerabilities: List[Vulnerability]
    gas_analysis: Optional[Dict[str, Any]] = None
    code_quality: Optional[Dict[str, Any]] = None
    summary: Dict[str, Any] = None
    recommendations: List[str] = None

class SmartContractAuditor:
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.gas_patterns = self._load_gas_patterns()
        self.best_practices = self._load_best_practices()
    
    def _load_vulnerability_patterns(self) -> Dict[str, List[Dict]]:
        """Load vulnerability detection patterns ."""
        
    