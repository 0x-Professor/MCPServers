from mcp.server.fastmcp import FastMCP
import json
import re
import asyncio
import hashlib
import uuid
import time
import logging
from dotenv import load_dotenv
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import httpx
from web3 import Web3, HTTPProvider
# Constants
HIGH_IMPACT_SAVINGS = 5000
MEDIUM_IMPACT_SAVINGS = 2000
LOW_IMPACT_SAVINGS = 500
MAX_EVENT_THRESHOLD = 5


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

VULN_TYPE_MAP = {
    "reentrancy": VulnerabilityType.REENTRANCY,
    "integer_overflow": VulnerabilityType.INTEGER_OVERFLOW,
    "access_control": VulnerabilityType.ACCESS_CONTROL,
    "unchecked_external_call": VulnerabilityType.UNCHECKED_EXTERNAL_CALL,
    "timestamp_dependency": VulnerabilityType.TIMESTAMP_DEPENDENCY,
    "front_running": VulnerabilityType.FRONT_RUNNING,
    "weak_randomness": VulnerabilityType.WEAK_RANDOMNESS,
    "delegatecall": VulnerabilityType.DELEGATECALL,
    "uninitialized_storage": VulnerabilityType.UNINITIALIZED_STORAGE,
    "denial_of_service": VulnerabilityType.DENIAL_OF_SERVICE,
    "flash_loan_attack": VulnerabilityType.FLASH_LOAN_ATTACK,
    "sandwich_attack": VulnerabilityType.SANDWICH_ATTACK,
    "mev_vulnerability": VulnerabilityType.MEV_VULNERABILITY,
    "governance_attack": VulnerabilityType.GOVERNANCE_ATTACK,
    "oracle_manipulation": VulnerabilityType.ORACLE_MANIPULATION
}

class SmartContractAuditor:
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.gas_patterns = self._load_gas_patterns()
        self.best_practices = self._load_best_practices()
        self.compiled_patterns = self._compile_patterns(self.vulnerability_patterns)
    
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
            "timestamp_dependency": [
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
    def _compile_patterns(self, patterns: Dict[str, List[Dict]]) -> Dict[str, List[tuple]]:
        """
        Compile all regex patterns for efficiency.
        Args:
            patterns (Dict[str, List[Dict]]): Vulnerability patterns.
        Returns:
            Dict[str, List[tuple]]: {vuln_type: [(compiled_pattern, description), ...]}
        """
        compiled = {}
        for vuln_type, pattern_list in patterns.items():
            compiled[vuln_type] = []
            for pat in pattern_list:
                compiled[vuln_type].append((re.compile(pat["pattern"], re.IGNORECASE), pat["description"]))
        return compiled
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

@mcp.tool()
async def analyze_contract_vulnerabilities(code: str, contract_name: str = "Unknown", analysis_depth: str = "standard") -> str:
    """
    Analyze smart contract code for security vulnerabilities.
    
    Args:
        code (str): The Solidity contract source code.
        contract_name (str): Name of the contract (default: "Unknown").
        analysis_depth (str): Analysis depth ("standard" or "deep").
    
    Returns:
        str: JSON-formatted analysis results.
    """
    vulnerabilities = []
    
    try:
        # Check Solidity version
        is_solidity_08_or_above = bool(re.search(r"pragma\s+solidity\s+\^?0\.8", code))
        
        # Track matches to avoid duplicates
        seen_matches = set()
        
        for vuln_type, patterns in auditor.compiled_patterns.items():
            vt_enum = VULN_TYPE_MAP.get(vuln_type)
            if not vt_enum:
                logger.warning(f"Unknown vulnerability type: {vuln_type}")
                continue
            
            for pattern, description in patterns:
                matches = pattern.finditer(code)
                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    code_snippet = match.group(0).strip()
                    match_key = f"{vuln_type}:{line_number}:{code_snippet}"
                    
                    # Skip duplicates
                    if match_key in seen_matches:
                        continue
                    seen_matches.add(match_key)
                    
                    # False positive control for integer overflow
                    if vuln_type == "integer_overflow" and is_solidity_08_or_above:
                        surrounding_code = code[max(0, match.start() - 100): match.end() + 100]
                        if "unchecked" not in surrounding_code:
                            continue
                    
                    # False positive control for timestamp dependency
                    if vuln_type == "timestamp_dependency":
                        surrounding_code = code[max(0, match.start() - 200): match.end() + 200]
                        # Skip if timestamp is used only for logging (events or storage)
                        if re.search(r"event\s+\w+\s*\([^)]*block\.timestamp[^)]*\)|memos?\[\w*\]\.timestamp\s*=", surrounding_code):
                            continue
                    
                    # False positive control for access control
                    if vuln_type == "access_control":
                        function_context = _get_function_context(code, match.start())
                        if "onlyOwner" in function_context or "nonReentrant" in function_context:
                            continue
                    
                    vulnerabilities.append(Vulnerability(
                        type=vt_enum,
                        severity=_get_severity(vuln_type, code, match.start()),
                        title=f"{vuln_type.replace('_', ' ').title()} Vulnerability",
                        description=description,
                        location=f"Line {line_number}",
                        code_snippet=code_snippet,
                        impact=_get_impact_message(vuln_type),
                        remediation=_get_remediation_message(vuln_type),
                        cwe_id=_get_cwe_id(vuln_type),
                        swc_id=_get_swc_id(vuln_type),
                        references=_get_references(vuln_type)
                    ))
        
        if analysis_depth == "deep":
            deep_vulns = await _analyze_complex_patterns(code)
            for vuln in deep_vulns:
                match_key = f"{vuln.type.value}:{vuln.location}:{vuln.code_snippet}"
                if match_key not in seen_matches:
                    vulnerabilities.append(vuln)
                    seen_matches.add(match_key)
        
        result = {
            "contract_name": contract_name,
            "analysis_depth": analysis_depth,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [serialize_for_json(asdict(v)) for v in vulnerabilities],
            "risk_score": _calculate_risk_score(vulnerabilities),
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "solidity_version_detected": "0.8.0 or above" if is_solidity_08_or_above else "Below 0.8.0"
        }
        logger.info(f"Analyzed contract {contract_name}: {len(vulnerabilities)} vulnerabilities found")
        return json.dumps(result, indent=2)
    
    except Exception as e:
        logger.error(f"Error analyzing contract {contract_name}: {str(e)}")
        return json.dumps({
            "error": f"Analysis failed: {str(e)}",
            "contract_name": contract_name,
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }, indent=2)
def serialize_for_json(obj):
    """Serialize Enum and complex objects for JSON output."""
    if isinstance(obj, Enum):
        return obj.value
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_for_json(i) for i in obj]
    else:
        return obj

def _get_function_context(code: str, match_start: int) -> str:
    """Extract the function context for a given match position."""
    lines = code[:match_start].split('\n')
    line_number = len(lines)
    # Look backward to find function declaration
    for i in range(line_number - 1, -1, -1):
        if re.match(r"function\s+\w+\s*\([^)]*\)\s*(public|external|internal|private)", lines[i]):
            return lines[i]
    return ""

async def _analyze_complex_patterns(code: str) -> List[Vulnerability]:
    """Analyze complex vulnerability patterns."""
    vulnerabilities = []
    
    # tx.origin misuse
    if re.search(r"\btx\.origin\b", code):
        vulnerabilities.append(Vulnerability(
            type=VulnerabilityType.FRONT_RUNNING,
            severity=Severity.HIGH,
            title="tx.origin Misuse",
            description="Using tx.origin for access control can be exploited by phishing attacks.",
            location="Multiple occurrences",
            code_snippet="tx.origin",
            impact="Attackers can trick users into executing malicious contracts.",
            remediation="Use msg.sender instead of tx.origin for authentication.",
            cwe_id="CWE-284",
            swc_id="SWC-115",
            references=["https://swcregistry.io/docs/SWC-115"]
        ))
    
    # Weak randomness
    if re.search(r"(block\.timestamp|block\.difficulty|blockhash)\s*.*\brandom\b", code, re.IGNORECASE):
        vulnerabilities.append(Vulnerability(
            type=VulnerabilityType.WEAK_RANDOMNESS,
            severity=Severity.MEDIUM,
            title="Weak Randomness Detected",
            description="Block parameters are predictable and can be manipulated.",
            location="Random number generation code",
            code_snippet="block.timestamp/difficulty/hash used in randomness",
            impact="Malicious actors may predict or influence outcomes.",
            remediation="Use Chainlink VRF or commit-reveal schemes instead.",
            cwe_id="CWE-338",
            swc_id="SWC-120",
            references=["https://swcregistry.io/docs/SWC-120"]
        ))
    
    # Unchecked delegatecall
    if re.search(r"\.delegatecall\s*\(", code):
        vulnerabilities.append(Vulnerability(
            type=VulnerabilityType.DELEGATECALL,
            severity=Severity.CRITICAL,
            title="Unsecure Delegatecall",
            description="Use of delegatecall can allow malicious code execution.",
            location="Delegatecall usage",
            code_snippet=".delegatecall",
            impact="Attackers can execute arbitrary code in contract's context.",
            remediation="Avoid delegatecall or use only with trusted contracts.",
            cwe_id="CWE-610",
            swc_id="SWC-112",
            references=["https://swcregistry.io/docs/SWC-112"]
        ))
    
    return vulnerabilities

def _get_severity(vuln_type: str, code: str, match_start: int) -> Severity:
    """Determine vulnerability severity with context."""
    critical = ["reentrancy", "delegatecall"]
    high = ["integer_overflow", "unchecked_external_call", "front_running"]
    medium = ["weak_randomness", "access_control", "uninitialized_storage"]
    low = ["timestamp_dependency"]
    
    if vuln_type in critical:
        return Severity.CRITICAL
    elif vuln_type in high:
        return Severity.HIGH
    elif vuln_type in medium:
        return Severity.MEDIUM
    elif vuln_type == "timestamp_dependency":
        # Downgrade to LOW if used only for logging
        surrounding_code = code[max(0, match_start - 200): match_start + 200]
        if re.search(r"event\s+\w+\s*\([^)]*block\.timestamp[^)]*\)|memos?\[\w*\]\.timestamp\s*=", surrounding_code):
            return Severity.LOW
        return Severity.MEDIUM
    else:
        return Severity.LOW

def _get_impact_message(vuln_type: str) -> str:
    """Get impact message for vulnerability."""
    impacts = {
        "reentrancy": "Could allow attackers to drain contract funds through recursive calls.",
        "integer_overflow": "Could cause incorrect calculations or unexpected behavior.",
        "access_control": "Could allow unauthorized access to sensitive functions.",
        "unchecked_external_call": "Could lead to failed transactions or loss of funds.",
        "timestamp_dependency": "Could be manipulated by miners within a small window.",
        "front_running": "Could allow attackers to manipulate transaction ordering.",
        "weak_randomness": "Could allow prediction or manipulation of random outcomes.",
        "delegatecall": "Could allow execution of malicious code in contract's context.",
        "uninitialized_storage": "Could lead to data corruption or unexpected behavior."
    }
    return impacts.get(vuln_type, f"Potential impact due to {vuln_type.replace('_', ' ')} vulnerability.")

def _get_remediation_message(vuln_type: str) -> str:
    """Get remediation message for vulnerability."""
    remediations = {
        "reentrancy": "Use OpenZeppelin's ReentrancyGuard or checks-effects-interactions pattern.",
        "integer_overflow": "Remove unchecked blocks or use SafeMath for Solidity <0.8.0.",
        "access_control": "Add appropriate access control modifiers like onlyOwner.",
        "unchecked_external_call": "Check return values of external calls or use try-catch.",
        "timestamp_dependency": "Use block.number or external oracles for critical timing logic.",
        "front_running": "Use msg.sender instead of tx.origin for authentication.",
        "weak_randomness": "Use Chainlink VRF or commit-reveal schemes for randomness.",
        "delegatecall": "Avoid delegatecall or use only with trusted contracts.",
        "uninitialized_storage": "Initialize all storage variables explicitly."
    }
    return remediations.get(vuln_type, f"Review contract logic and mitigate {vuln_type.replace('_', ' ')} issue.")

def _get_cwe_id(vuln_type: str) -> Optional[str]:
    """Get CWE ID for vulnerability."""
    cwe_ids = {
        "reentrancy": "CWE-841",
        "integer_overflow": "CWE-190",
        "access_control": "CWE-284",
        "unchecked_external_call": "CWE-252",
        "timestamp_dependency": "CWE-829",
        "front_running": "CWE-284",
        "weak_randomness": "CWE-338",
        "delegatecall": "CWE-610",
        "uninitialized_storage": "CWE-824"
    }
    return cwe_ids.get(vuln_type)

def _get_swc_id(vuln_type: str) -> Optional[str]:
    """Get SWC ID for vulnerability."""
    swc_ids = {
        "reentrancy": "SWC-107",
        "integer_overflow": "SWC-101",
        "access_control": "SWC-100",
        "unchecked_external_call": "SWC-104",
        "timestamp_dependency": "SWC-116",
        "front_running": "SWC-115",
        "weak_randomness": "SWC-120",
        "delegatecall": "SWC-112",
        "uninitialized_storage": "SWC-109"
    }
    return swc_ids.get(vuln_type)

def _get_references(vuln_type: str) -> List[str]:
    """Get references for vulnerability."""
    swc_id = _get_swc_id(vuln_type)
    base_refs = ["https://consensys.github.io/smart-contract-best-practices/"]
    if swc_id:
        base_refs.append(f"https://swcregistry.io/docs/{swc_id}")
    return base_refs

def _calculate_risk_score(vulnerabilities: List[Vulnerability]) -> int:
    """
    Calculate an overall risk score for a contract based on detected vulnerabilities.
    The score is weighted by severity and capped at 100.

    Args:
        vulnerabilities (List[Vulnerability]): List of detected vulnerabilities.

    Returns:
        int: Risk score (0-100).
    """
    severity_weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2,
        "INFO": 1
    }
    score = 0
    for vuln in vulnerabilities:
        sev = vuln.severity.value if isinstance(vuln.severity, Enum) else str(vuln.severity)
        score += severity_weights.get(sev.upper(), 1)
    return min(score, 100)

@mcp.tool()
async def suggest_fixes(vulnerability: Dict[str, Any], context: str = "", fix_type: str = "comprehensive") -> str:
    """Suggest fixes for identified vulnerabilities."""
    vuln_type = vulnerability.get("type", "")
    fixes = {
        "reentrancy": {
            "quick": "Add ReentrancyGuard modifier from OpenZeppelin",
            "comprehensive": """
// Use OpenZeppelin's ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract MyContract is ReentrancyGuard {
    function vulnerableFunction() external nonReentrant {
        // Your code here
        // External calls should be at the end
    }
}

// Alternative: Manual reentrancy protection
bool private locked;
modifier noReentrancy() {
    require(!locked, "Reentrant call");
    locked = true;
    _;
    locked = false;
}
"""
        },
        "integer_overflow": {
            "quick": "Use SafeMath library or Solidity 0.8+",
            "comprehensive": """
// For Solidity < 0.8.0
import "@openzeppelin/contracts/math/SafeMath.sol";

contract MyContract {
    using SafeMath for uint256;
    
    function safeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a.add(b); // Will revert on overflow
    }
}

// For Solidity >= 0.8.0 (built-in overflow protection)
contract MyContract {
    function safeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // Automatically reverts on overflow
    }
}
"""
        },
        "access_control": {
            "quick": "Add access control modifiers",
            "comprehensive": """
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract MyContract is Ownable, AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);
    }
    
    function adminFunction() external onlyRole(ADMIN_ROLE) {
        // Admin only functionality
    }
    
    function operatorFunction() external onlyRole(OPERATOR_ROLE) {
        // Operator only functionality
    }
}
"""
        },
        "unchecked_external_call": {
            "quick": "Check return values of external calls",
            "comprehensive": """
// Bad: Unchecked external call
// someContract.call(data);

// Good: Check return value
(bool success, bytes memory data) = someContract.call(callData);
require(success, "External call failed");

// Alternative: Use try-catch (Solidity 0.6+)
try someContract.someFunction() {
    // Success handling
} catch Error(string memory reason) {
    // Handle revert with reason
} catch (bytes memory lowLevelData) {
    // Handle low-level errors
}
"""
        },
        "timestamp_dependence": {
            "quick": "Use block.number instead of block.timestamp for timing",
            "comprehensive": """
// Bad: Direct timestamp comparison
// require(block.timestamp > deadline);

// Good: Use time windows instead of exact timestamps
uint256 constant TIME_WINDOW = 1 hours;
require(block.timestamp >= startTime + TIME_WINDOW, "Too early");

// Alternative: Use block numbers for more predictable timing
uint256 constant BLOCKS_PER_HOUR = 240; // Approximate
require(block.number >= startBlock + BLOCKS_PER_HOUR, "Too early");
"""
        }
    }
    
    fix_suggestion = fixes.get(vuln_type, {}).get(fix_type, "No specific fix available")
    result = {
        "vulnerability_type": vuln_type,
        "fix_type": fix_type,
        "recommendation": fix_suggestion,
        "additional_resources": [
            "https://consensys.github.io/smart-contract-best-practices/",
            "https://swcregistry.io/",
            "https://docs.openzeppelin.com/contracts/security"
        ],
        "testing_recommendations": [
            "Write comprehensive unit tests",
            "Perform integration testing",
            "Use fuzzing tools like Echidna",
            "Consider formal verification"
        ]
    }
    return json.dumps(result, indent=2)

@mcp.tool()
async def analyze_gas_efficiency(code: str, function_name: str = "") -> str:
    """
    Analyze a smart contract for gas inefficiencies and optimization suggestions.

    Args:
        code (str): The Solidity source code of the contract.
        function_name (str, optional): Specific function name to narrow the analysis.

    Returns:
        str: JSON-formatted result with issues, locations, and recommendations.
    """
    gas_issues: List[Dict[str, Any]] = []

    # Pattern Matching
    for issue_type, patterns in auditor.gas_patterns.items():
        for pattern_info in patterns:
            try:
                matches = re.finditer(pattern_info["pattern"], code, re.IGNORECASE)
                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    gas_issues.append({
                        "type": issue_type,
                        "description": pattern_info["description"],
                        "location": f"Line {line_number}",
                        "code_snippet": match.group(0).strip(),
                        "potential_savings": "Medium"
                    })
            except re.error as e:
                gas_issues.append({
                    "type": "pattern_error",
                    "description": f"Regex error for pattern '{pattern_info['pattern']}': {str(e)}",
                    "location": "N/A",
                    "code_snippet": "",
                    "potential_savings": "Low"
                })

    # Additional Heuristics
    if "uint256" in code and not re.search(r"\buint(8|16|32|64|128)\b", code):
        gas_issues.append({
            "type": "data_type_optimization",
            "description": "Consider using smaller integer types (e.g., uint8, uint16) where possible",
            "location": "Throughout contract",
            "code_snippet": "uint256 declarations",
            "potential_savings": "Low"
        })

    if code.count("emit") > MAX_EVENT_THRESHOLD:
        gas_issues.append({
            "type": "event_optimization",
            "description": "Consider consolidating events to reduce gas costs",
            "location": "Multiple locations",
            "code_snippet": "Multiple emit statements",
            "potential_savings": "Medium"
        })

    # Assemble results
    result: Dict[str, Any] = {
        "function_analyzed": function_name or "Entire contract",
        "gas_optimization_opportunities": len(gas_issues),
        "issues": gas_issues,
        "estimated_gas_savings": _calculate_gas_savings(gas_issues),
        "recommendations": [
            "Use appropriate data types (e.g., uint8 instead of uint256 when range allows)",
            "Minimize redundant storage operations (SSTORE)",
            "Use '++i' instead of 'i++' in loops for micro-savings",
            "Avoid default visibility; declare visibility explicitly",
            "Optimize event logging and loop conditions",
            "Consider inline assembly for performance-critical paths (with care)",
            "Leverage constant/immutable variables when possible"
        ]
    }

    return json.dumps(result, indent=2)


def _calculate_gas_savings(issues: List[Dict[str, Any]]) -> str:
    """
    Estimate gas savings based on severity of optimization issues.

    Args:
        issues (List[Dict[str, Any]]): List of identified gas-related issues.

    Returns:
        str: Approximate gas saved.
    """
    high = sum(1 for i in issues if i["potential_savings"] == "High")
    med = sum(1 for i in issues if i["potential_savings"] == "Medium")
    low = sum(1 for i in issues if i["potential_savings"] == "Low")

    estimated = (high * HIGH_IMPACT_SAVINGS) + (med * MEDIUM_IMPACT_SAVINGS) + (low * LOW_IMPACT_SAVINGS)
    return f"Approximately {estimated} gas units"

@mcp.tool()
async def check_compliance(code: str, standards: List[str] = [], jurisdiction: str = "general") -> str:
    """
    Check smart contract code against token standards (ERC-20/721/1155), general best practices,
    and regulatory jurisdictions like EU (GDPR) and US (SEC).

    Args:
        code (str): Solidity source code
        standards (List[str]): List of standards to validate against
        jurisdiction (str): Regulatory jurisdiction ("general", "EU", "US")

    Returns:
        str: JSON-formatted result containing compliance status, recommendations, and score
    """
    compliance_results: Dict[str, Any] = {}

    # Standards checks
    if "ERC-20" in standards:
        compliance_results["ERC-20"] = _check_erc20_compliance(code)
    if "ERC-721" in standards:
        compliance_results["ERC-721"] = _check_erc721_compliance(code)
    if "ERC-1155" in standards:
        compliance_results["ERC-1155"] = _check_erc1155_compliance(code)

    # General best practices
    general_compliance = {
        "has_license": bool(re.search(r"SPDX-License-Identifier:\s*[A-Za-z\-]+", code)),
        "has_pragma": "pragma solidity" in code,
        "has_natspec": "///" in code or "/**" in code,
        "follows_naming_conventions": _check_naming_conventions(code),
        "has_error_handling": "require(" in code or "revert(" in code,
        "has_events": "event " in code and "emit " in code
    }
    compliance_results["general"] = general_compliance

    # Jurisdiction-specific compliance
    if jurisdiction == "EU":
        compliance_results["GDPR"] = _check_gdpr_compliance(code)
    elif jurisdiction == "US":
        compliance_results["SEC"] = _check_sec_compliance(code)

    result: Dict[str, Any] = {
        "standards_checked": standards,
        "jurisdiction": jurisdiction,
        "compliance_results": compliance_results,
        "overall_compliance_score": _calculate_compliance_score(compliance_results),
        "recommendations": _generate_compliance_recommendations(compliance_results)
    }

    return json.dumps(result, indent=2)


# --- Standard Checks --- #

def _check_erc20_compliance(code: str) -> Dict[str, bool]:
    required_functions = [
        "totalSupply", "balanceOf", "transfer", "transferFrom", "approve", "allowance"
    ]
    required_events = ["Transfer", "Approval"]
    return _match_signatures(code, required_functions, required_events)


def _check_erc721_compliance(code: str) -> Dict[str, bool]:
    required_functions = [
        "balanceOf", "ownerOf", "safeTransferFrom", "transferFrom",
        "approve", "getApproved", "setApprovalForAll", "isApprovedForAll"
    ]
    required_events = ["Transfer", "Approval", "ApprovalForAll"]
    return _match_signatures(code, required_functions, required_events)


def _check_erc1155_compliance(code: str) -> Dict[str, bool]:
    required_functions = [
        "balanceOf", "balanceOfBatch", "safeTransferFrom",
        "safeBatchTransferFrom", "setApprovalForAll", "isApprovedForAll"
    ]
    required_events = ["TransferSingle", "TransferBatch", "ApprovalForAll", "URI"]
    return _match_signatures(code, required_functions, required_events)


def _match_signatures(code: str, functions: List[str], events: List[str]) -> Dict[str, bool]:
    """Helper to check presence of required functions and events."""
    result = {}
    for func in functions:
        result[f"has_{func}"] = re.search(rf"function\s+{func}\s*\(", code) is not None
    for evt in events:
        result[f"has_{evt}_event"] = re.search(rf"event\s+{evt}\s*\(", code) is not None
    return result


# --- General Checks --- #

def _check_naming_conventions(code: str) -> bool:
    """Verify contract and function naming style."""
    function_pattern = r"function\s+([a-z][a-zA-Z0-9]*)\s*\("
    contract_pattern = r"contract\s+([A-Z][a-zA-Z0-9]*)\s*"
    functions = re.findall(function_pattern, code)
    contracts = re.findall(contract_pattern, code)
    return bool(functions) and bool(contracts)


# --- Jurisdictional Checks --- #

def _check_gdpr_compliance(code: str) -> Dict[str, bool]:
    return {
        "has_data_deletion": "delete" in code.lower() or "remove" in code.lower(),
        "has_access_control": "onlyOwner" in code or "AccessControl" in code,
        "has_consent_mechanism": "consent" in code.lower() or "approve" in code.lower(),
        "has_data_portability": "export" in code.lower() or "getData" in code.lower()
    }


def _check_sec_compliance(code: str) -> Dict[str, bool]:
    return {
        "has_transfer_restrictions": "transfer" in code and "require" in code,
        "has_kyc_integration": "kyc" in code.lower() or "whitelist" in code.lower(),
        "has_accredited_investor_check": "accredited" in code.lower() or "qualified" in code.lower(),
        "has_lock_up_periods": "lockup" in code.lower() or "vesting" in code.lower()
    }


# --- Scoring & Feedback --- #

def _calculate_compliance_score(results: Dict[str, Any]) -> int:
    total = 0
    passed = 0
    for section in results.values():
        if isinstance(section, dict):
            total += len(section)
            passed += sum(1 for status in section.values() if status is True)
    return round((passed / total) * 100) if total else 0


def _generate_compliance_recommendations(results: Dict[str, Any]) -> List[str]:
    recommendations: List[str] = []
    for label, checks in results.items():
        if isinstance(checks, dict):
            failed = [k for k, v in checks.items() if not v]
            if failed:
                suggestions = ", ".join(failed)
                recommendations.append(f"Improve {label} compliance: {suggestions}")
    return recommendations

@mcp.tool()
async def generate_audit_report(
    contract_address: str,
    vulnerabilities: List[Dict[str, Any]],
    gas_analysis: Dict[str, Any] = {},
    include_recommendations: bool = True
) -> str:
    """
    Generate a comprehensive smart contract audit report.

    Args:
        contract_address (str): Target smart contract address.
        vulnerabilities (List[Dict[str, Any]]): List of vulnerability dicts with severity info.
        gas_analysis (Dict[str, Any], optional): Gas efficiency findings.
        include_recommendations (bool, optional): Whether to include actionable recommendations.

    Returns:
        str: JSON-formatted audit report.
    """
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    risk_rating = _determine_risk_rating(vulnerabilities)
    vuln_summary = _summarize_vulnerabilities(vulnerabilities)

    report: Dict[str, Any] = {
        "audit_report": {
            "report_id": str(uuid.uuid4()),
            "tool_version": "1.0.0",
            "contract_address": contract_address,
            "audit_date": timestamp,
            "auditor": {
                "name": "AI Smart Contract Auditor",
                "engine": "GPT-4o",
                "methodology": [
                    "Static code analysis",
                    "Pattern-based vulnerability scanning",
                    "Best practice enforcement",
                    "Gas usage profiling",
                    "Automated test simulation"
                ]
            },
            "executive_summary": {
                **vuln_summary,
                "overall_risk_rating": risk_rating
            },
            "detailed_findings": vulnerabilities,
            "gas_analysis": gas_analysis
        }
    }

    if include_recommendations:
        report["audit_report"]["recommendations"] = _generate_recommendations(vulnerabilities)

    return json.dumps(report, indent=2)


def _summarize_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Summarize vulnerabilities by severity."""
    severity_levels = ["critical", "high", "medium", "low", "informational"]
    summary = {f"{level}_vulnerabilities": 0 for level in severity_levels}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").lower()
        if severity in summary:
            summary[f"{severity}_vulnerabilities"] += 1
    summary["total_vulnerabilities"] = sum(summary.values())
    return summary


def _determine_risk_rating(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Determine overall risk based on severity weights."""
    score = 0
    weights = {
        "critical": 5,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0
    }
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").lower()
        score += weights.get(severity, 0)

    if score >= 10:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def _generate_recommendations(vulnerabilities: List[Dict[str, Any]]) -> List[str]:
    """Generate actionable recommendations based on vulnerabilities."""
    if not vulnerabilities:
        return ["No vulnerabilities detected. Maintain regular audits and testing."]

    recommendations = [
        "Patch all critical and high-severity issues before deployment.",
        "Add unit tests to cover vulnerable or unverified logic paths.",
        "Consider formal verification for core logic functions.",
        "Avoid custom security logic—use vetted libraries like OpenZeppelin.",
        "Implement pause/freeze mechanisms for emergency mitigation.",
        "Strengthen access control and privilege separation.",
        "Conduct manual review for business logic consistency.",
        "Use real-time monitoring tools after deployment (e.g., Forta)."
    ]
    return recommendations