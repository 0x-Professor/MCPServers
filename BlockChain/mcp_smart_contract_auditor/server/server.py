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
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "3NK7D3FBF2AQ23RBEDPX9BVZH4DD4E3DHZ") # Default key for testing purposes
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID", "7464fe4568974a00b5cf20e94ebc4833")  # Default key for testing purposes
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
async def make_api_request(url: str, params: Dict = None) ->Any:
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
        # Check if the function is a coroutine function
        import inspect
        if inspect.iscoroutinefunction(func):
            result = await func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)
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
        logger.info(f"Etherscan request URL: {explorer_url}")
        logger.info(f"Etherscan params: {params}")
        logger.info(f"Etherscan API key (first 6 chars): {ETHERSCAN_API_KEY[:6]}")
        data = await make_api_request(explorer_url, params)
        logger.info(f"Etherscan raw response: {data}")
        if data and data.get("status") == "1" and data.get("result"):
            contract_info = data["result"][0]
            w3 = Web3(HTTPProvider(SUPPORTED_CHAINS[chain]["rpc"]))
            bytecode = await make_web3_request(chain, w3.eth.get_code, address)
            logger.info(f"Bytecode type: {type(bytecode)}, value: {bytecode}")
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
            logger.error(f"Etherscan API error. Full response: {data}")
            logger.error(f"Error: Failed to fetch contract code: {data.get('message', 'Unknown error') if data else 'No response'}")
            return f"Error: Failed to fetch contract code: {data.get('message', 'Unknown error') if data else 'No response'}\nRaw response: {data}"
    except Exception as e:
        logger.error(f"Error fetching contract code: {str(e)}")
        return f"Error: {str(e)}"

def handle_contract_result(result_str: str):
    """
    Parse and display the contract result in a user-friendly way.
    Usage:
        result_str = await fetch_contract_code(address, chain)
        handle_contract_result(result_str)
    """
    import json
    try:
        # Parse the JSON string
        result = json.loads(result_str)
        # Check verification status
        if result.get("verification_status") == "verified":
            print("\n✅ Contract is verified!")
            print("Contract Name:", result.get("contract_name"))
            print("Chain:", result.get("chain"))
            print("Address:", result.get("address"))
            print("Compiler Version:", result.get("compiler_version"))
            print("Optimization Used:", result.get("optimization_used"))
            print("\nSource Code (first 20 lines):")
            source_lines = result.get("source_code", "").splitlines()
            for line in source_lines[:20]:
                print(line)
            if len(source_lines) > 20:
                print("... (truncated)")
            print("\nABI (first 200 chars):", result.get("abi", "")[:200], "...")
            print("Bytecode (first 60 chars):", result.get("bytecode", "")[:60], "...")
        else:
            print("\n❌ Contract is not verified or could not fetch code.")
            print("Details:", result)
    except Exception as e:
        print("\nError parsing contract result:", str(e))
        print("Raw result:", result_str)

# Example usage (uncomment to use in script):
# result_str = await fetch_contract_code(address, chain)
# handle_contract_result(result_str)
# Mapping from string keys to VulnerabilityType enum members
# ------------------------ VULNERABILITY TYPE MAPPING ------------------------
VULN_TYPE_MAP = {
    "reentrancy": VulnerabilityType.REENTRANCY,
    "integer_overflow": VulnerabilityType.INTEGER_OVERFLOW,
    "access_control": VulnerabilityType.ACCESS_CONTROL,
    "unchecked_external_call": VulnerabilityType.UNCHECKED_EXTERNAL_CALL,
    "timestamp_dependence": VulnerabilityType.TIMESTAMP_DEPENDENCY,
    "front_running": VulnerabilityType.FRONT_RUNNING,
    "weak_randomness": VulnerabilityType.WEAK_RANDOMNESS,
    # Add more as needed
}

# ------------------------ ENUM SERIALIZER ------------------------
def serialize_for_json(obj):
    if isinstance(obj, Enum):
        return obj.value
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_for_json(i) for i in obj]
    else:
        return obj

# ------------------------ ANALYSIS TOOL ENTRY ------------------------
@mcp.tool()
async def analyze_contract_vulnerabilities(code: str, contract_name: str = "Unknown", analysis_depth: str = "standard") -> str:
    vulnerabilities = []

    is_solidity_08_or_above = re.search(r"pragma\s+solidity\s+\^?0\.8", code)

    for vuln_type, patterns in auditor.vulnerability_patterns.items():
        vt_enum = VULN_TYPE_MAP.get(vuln_type)
        if not vt_enum:
            continue

        for pattern_info in patterns:
            matches = re.finditer(pattern_info["pattern"], code, re.IGNORECASE)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1

                # ✅ False positive control for Solidity >= 0.8 integer overflow
                if vuln_type == "integer_overflow" and is_solidity_08_or_above:
                    surrounding_code = code[max(0, match.start() - 100): match.end() + 100]
                    if "unchecked" not in surrounding_code:
                        continue  # skip if not truly vulnerable

                vulnerabilities.append(Vulnerability(
                    type=vt_enum,
                    severity=_get_severity(vuln_type),
                    title=f"{vuln_type.replace('_', ' ').title()} Vulnerability",
                    description=pattern_info["description"],
                    location=f"Line {line_number}",
                    code_snippet=match.group(0).strip(),
                    impact=_get_impact_message(vuln_type),
                    remediation=_get_remediation_message(vuln_type)
                ))

    if analysis_depth == "deep":
        vulnerabilities += await _analyze_complex_patterns(code)

    result = {
        "contract_name": contract_name,
        "analysis_depth": analysis_depth,
        "vulnerabilities_found": len(vulnerabilities),
        "vulnerabilities": [serialize_for_json(asdict(v)) for v in vulnerabilities],
        "risk_score": _calculate_risk_score(vulnerabilities),
        "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    return json.dumps(result, indent=2)

# ------------------------ DEEP PATTERN CHECKS ------------------------
async def _analyze_complex_patterns(code: str) -> List[Vulnerability]:
    vulnerabilities = []

    # 🟡 tx.origin based authorization (Front-running)
    if re.search(r"\btx\.origin\b", code):
        vulnerabilities.append(Vulnerability(
            type=VulnerabilityType.FRONT_RUNNING,
            severity=Severity.HIGH,
            title="tx.origin Misuse",
            description="Using tx.origin for access control can be exploited by phishing attacks.",
            location="Multiple occurrences",
            code_snippet="tx.origin",
            impact="Attackers can trick users into executing malicious contracts.",
            remediation="Use msg.sender instead of tx.origin for authentication."
        ))

    # 🟡 Weak randomness based on block parameters
    if re.search(r"(block\.timestamp|block\.difficulty|blockhash).*random", code):
        vulnerabilities.append(Vulnerability(
            type=VulnerabilityType.WEAK_RANDOMNESS,
            severity=Severity.MEDIUM,
            title="Weak Randomness Detected",
            description="Block parameters are predictable and can be manipulated.",
            location="Random number generation code",
            code_snippet="block.timestamp/difficulty/hash used in randomness",
            impact="Malicious actors may predict or influence outcomes.",
            remediation="Use Chainlink VRF or commit-reveal schemes instead."
        ))

    return vulnerabilities

# ------------------------ SEVERITY WEIGHTING ------------------------
def _get_severity(vuln_type: str) -> Severity:
    critical = ["reentrancy"]
    high = ["integer_overflow", "unchecked_external_call", "front_running"]
    medium = ["timestamp_dependence", "weak_randomness", "access_control"]

    if vuln_type in critical:
        return Severity.CRITICAL
    elif vuln_type in high:
        return Severity.HIGH
    elif vuln_type in medium:
        return Severity.MEDIUM
    else:
        return Severity.LOW

# ------------------------ IMPACT/REMEDIATION HELPERS ------------------------
def _get_impact_message(vuln_type: str) -> str:
    return f"Potential impact due to {vuln_type.replace('_', ' ')} vulnerability."

def _get_remediation_message(vuln_type: str) -> str:
    return f"Review contract logic and mitigate {vuln_type.replace('_', ' ')} issue."

# ------------------------ RISK SCORE CALCULATOR ------------------------
def _calculate_risk_score(vulnerabilities: List[Vulnerability]) -> int:
    score = 0
    for v in vulnerabilities:
        if v.severity == Severity.CRITICAL:
            score += 10
        elif v.severity == Severity.HIGH:
            score += 7
        elif v.severity == Severity.MEDIUM:
            score += 4
        elif v.severity == Severity.LOW:
            score += 2
    return min(score, 100)
