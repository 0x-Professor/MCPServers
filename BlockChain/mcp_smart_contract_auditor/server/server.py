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
        return {
            "reentrancy": [
                {"pattern": r"\.call\s*\(\s*[^)]*\)\s*;\s*[^;]*balance\s*=", "description": "Potential reentrancy: external call before state change"},
                {"pattern": r"\.transfer\s*\(\s*[^)]*\)\s*;\s*[^;]*balance\s*=", "description": "Potential reentrancy: transfer before state change"}
            ],
            "integer_overflow": [
                {"pattern": r"(?<!SafeMath\.)\+\s*(?!\s*1\s*;)", "description": "Potential integer overflow: unchecked addition"},
                {"pattern": r"(?<!SafeMath\.)\*\s*", "description": "Potential integer overflow: unchecked multiplication"}
            ],
            "access_control": [
                {"pattern": r"function\s+\w+\s*\([^)]*\)\s*public\s*(?!view|pure)", "description": "Public function without access control"},
                {"pattern": r"selfdestruct\s*\(", "description": "Selfdestruct function without proper access control"}
            ],
            "unchecked_external_call": [
                {"pattern": r"\.call\s*\([^)]*\)\s*;(?!\s*require)", "description": "Unchecked external call"},
                {"pattern": r"\.send\s*\([^)]*\)\s*;(?!\s*require)", "description": "Unchecked send call"}
            ],
            "timestamp_dependence": [
                {"pattern": r"block\.timestamp", "description": "Block timestamp usage - potential manipulation"},
                {"pattern": r"now\s*[<>=]", "description": "Block timestamp comparison - potential manipulation"}
            ]
        }
    def _load_gas_patterns(self) -> Dict[str, List[Dict]]:
        """Load gas optimization patterns."""
        return {
            "storage_optimization": [
                {"pattern": r"uint256\s+public\s+\w+\s*=\s*0;", "description": "Unnecessary zero initialization"},
                {"pattern": r"for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length\s*;", "description": "Array length in loop condition"}
            ],
            "function_optimization": [
                {"pattern": r"function\s+\w+\s*\([^)]*\)\s*public\s*view", "description": "Consider making function external if not called internally"}
            ]
        }
    def _load_best_practices(self) -> Dict[str, List[str]]:
        """Load best Practices Checklist"""
        return {
            "security": [
                "Use OpenZeppelin's security contracts",
                "Implement proper access control",
                "Use SafeMath for arithmetic operations",
                "Implement circuit breakers",
                "Use pull payment pattern"
            ],
            "gas_optimization": [
                "Use appropriate data types",
                "Minimize storage operations",
                "Use events for cheap storage",
                "Optimize loops",
                "Use libraries for common functions"
            ],
            "code_quality": [
                "Follow naming conventions",
                "Add comprehensive comments",
                "Use NatSpec documentation",
                "Implement proper error handling",
                "Write comprehensive tests"
            ]
        }
auditor = SmartContractAuditor()
async def make_api_requrst(url: str, params: Dict = None) ->Any:
    """Make an API request and return the JSON response."""
    async with httpx.AsyncClient() as client:
       try:
           response  = await client.get(url, params=params, timeout = 10.0)
           response.raise_for_status()
           return response.json()
       except httpx.HTTPStatusError as e:
           logger.error(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
           return None
    
async def make_web3_request(chain: str, func, *args, **kwargs) -> Any:
    """Make a Web3 request to the specified chain."""
    if chain not in SUPPORTED_CHAINS:
        return None
    w3 = Web3(HTTPProvider(SUPPORTED_CHAINS[chain]["rpc"]))
    try:
        result = await func(*args, **kwargs) if func.__name__.startswith("async") else func(*args, **kwargs)
        return result
    except Exception as e:
        logger.error(f"Web3 request failed: {str(e)}")
        return None

@mcp.tool()
async def fetch_contract_code(address: str, chain: str = "ethereum") -> str:
    """Fetch smart contract source code and byte code from the blockchain."""
    if chain not in SUPPORTED_CHAINS:
        return f"Unsupported chain: {chain}"
    
    try:
        explorer_url = SUPPORTED_CHAINS[chain]["explorer"]
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": ETHERSCAN_API_KEY
        }
        data = await make_api_requrst(explorer_url, params)
        if data and data["status"] == "1" and data["result"]:
            contract_info = data["result"][0]
            w3 = Web3(HTTPProvider(SUPPORTED_CHAINS[chain]["rpc"]))
            bytecode = await make_web3_request(chain, w3.eth.get_code, address)
            result = {
                "address": address,
                "chain": chain,
                "contract_name": contract_info.get("ContractName", "Unknown"),
                "source_code": contract_info.get("SourceCode", ""),
                "abi": contract_info.get("ABI", ""),
                "compiler_version": contract_info.get("CompilerVersion", ""),
                "optimization_used": contract_info.get("OptimizationUsed", ""),
                "bytecode": bytecode.hex() if bytecode else "",
                "verification_status": "verified" if contract_info.get("SourceCode") else "unverified"
            }
            return json.dumps(result, indent=2)
        else:
            return f"Error: Failed to fetch contract code: {data.get('message', 'Unknown error') if data else 'No response'}"
    except Exception as e:
        logger.error(f"Error fetching contract code: {str(e)}")
        return f"Error: {str(e)}"
