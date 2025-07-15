"""
Cross-Chain Bridge Assistant MCP Server

A comprehensive MCP server for cross-chain asset transfers with support for multiple bridges,
fee estimation, transaction execution, monitoring, and analytics.

Features:
- Multi-bridge support (Polygon Bridge, Arbitrum Bridge, Optimism Bridge)
- Real-time fee estimation with gas optimization
- Secure transaction execution with HMAC signatures
- Event monitoring using Web3 filters
- Bridge health monitoring
- Historical transaction tracking via Etherscan
- OAuth 2.1 authentication support
- Structured output with Pydantic models
- Streamable HTTP transport for production
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from enum import Enum
from dataclasses import dataclass
import hashlib
import hmac
import os
from dotenv import load_dotenv
import aiohttp
import requests
from web3 import Web3
from web3.exceptions import TransactionNotFound
from eth_account import Account
from eth_utils import to_checksum_address, is_address
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from mcp.types import Completion, CompletionArgument, CompletionContext, ResourceTemplateReference
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
import sqlite3
from cachetools import TTLCache

load_dotenv()
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID", "7464fe4568974a00b5cf20e94ebc4833")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "3NK7D3FBF2AQ23RBEDPX9BVZH4DD4E3DHZ")
HMAC_SECRET = os.getenv("HMAC_SECRET", "your-secret-key")
AUTH_ISSUER_URL = os.getenv("AUTH_ISSUER_URL", "https://auth.example.com")
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:3001")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

#constants
SUPPORTED_CHAINS = {
    "ethereum": {
        "chain_id": 1,
        "name": "Ethereum Mainnet",
        "rpc_url": f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}",
        "explorer": "https://api.etherscan.io/api",
        "native_token": "ETH",
        "decimals": 18
    },
    "polygon": {
        "chain_id": 137,
        "name": "Polygon",
        "rpc_url": "https://polygon-rpc.com",
        "explorer": "https://api.polygonscan.com/api",
        "native_token": "MATIC",
        "decimals": 18
    },
    "arbitrum": {
        "chain_id": 42161,
        "name": "Arbitrum One",
        "rpc_url": "https://arb1.arbitrum.io/rpc",
        "explorer": "https://api.arbiscan.io/api",
        "native_token": "ETH",
        "decimals": 18
    },
    "optimism": {
        "chain_id": 10,
        "name": "Optimism",
        "rpc_url": "https://mainnet.optimism.io",
        "explorer": "https://api-optimistic.etherscan.io/api",
        "native_token": "ETH",
        "decimals": 18
    }
}
BRIDGE_CONTRACTS = {
    "polygon_bridge": {
        "ethereum_address": "0xA0c68C638235ee32657e8f720a23ceC1bFc77C77",
        "polygon_address": "0x8484Ef722627bf18ca5Ae6BcF031c23E6e922B30",
        "supported_pairs": [("ethereum", "polygon"), ("polygon", "ethereum")],
        "fee_structure": {"base_fee": "0.001", "percentage_fee": "0.001"},
        "abi": [...]  # Full ABI (fetch from Etherscan)
    },
    "arbitrum_bridge": {
        "ethereum_address": "0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a",
        "arbitrum_address": "0x0000000000000000000000000000000000000064",
        "supported_pairs": [("ethereum", "arbitrum"), ("arbitrum", "ethereum")],
        "fee_structure": {"base_fee": "0.0005", "percentage_fee": "0.0005"},
        "abi": [...]  # Full ABI
    },
    "optimism_bridge": {
        "ethereum_address": "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1",
        "optimism_address": "0x4200000000000000000000000000000000000010",
        "supported_pairs": [("ethereum", "optimism"), ("optimism", "ethereum")],
        "fee_structure": {"base_fee": "0.0005", "percentage_fee": "0.0005"},
        "abi": [...]  # Full ABI
    }
}

class TransactionStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    CONFIRMED = "confirmed"
    CANCELED = "canceled"

class FeeEstimate(BaseModel):
    source_chain_fee: str = Field(..., description="Estimated fee for the source chain")
    destination_chain_fee: str = Field(..., description="Estimated fee for the destination chain")
    bridge_fee: str = Field(..., description="Estimated bridge fee")
    total_fee: str = Field(..., description="Total estimated fee for the transaction")
    estimated_time: int = Field(..., description="Estimated time in seconds for the transaction to complete")
    gas_price: str = Field(..., description="Estimated gas price in Gwei")
    gas_limit: int = Field(..., description="Estimated gas limit for the transaction")

class BridgeTransaction(BaseModel):
    id: str = Field(..., description="Unique transaction ID")
    source_chain: str = Field(..., description="Source blockchain name")
    destination_chain: str = Field(..., description="Destination blockchain name")
    asset: str = Field(..., description="Asset being transferred")
    amount: Decimal = Field(..., description="Amount of asset being transferred")
    sender: str = Field(..., description="Sender's wallet address")
    recipient: str = Field(..., description="Recipient's wallet address")
    status: TransactionStatus = Field(..., description="Current status of the transaction")
    source_tx_hash: Optional[str] = Field(default=None, description="Transaction hash on the source chain")
    destination_tx_hash: Optional[str] = Field(default=None, description="Transaction hash on the destination chain")
    created_at: Optional[str] = Field(default=None, description="Transaction creation timestamp")
    completed_at: Optional[str] = Field(default=None, description="Transaction completion timestamp")
    estimated_completion: Optional[str] = Field(default=None, description="Estimated completion timestamp")
    fee: Optional[FeeEstimate] = Field(default=None, description="Estimated fees for the transaction")
    bridge_contract: Optional[str] = Field(default=None, description="Bridge contract address used for the transaction")
    signature: Optional[str] = Field(default=None, description="HMAC signature for transaction verification")
    
class BridgeEvent(BaseModel):
   event_type: str = Field(..., description="Type of the event (e.g., 'transaction_created', 'transaction_completed')")
   transaction_hash: str = Field(..., description="Transaction hash associated with the event")
   block_number: int = Field(..., description="Block number where the event was recorded")
   timestamp: str = Field(..., description="Timestamp of the event")
   data: Dict[str, str] = Field(..., description="Additional data related to the event")

class BridgeStatus(BaseModel):
   name: str = Field(..., description="Name of the bridge")
   supported_pairs: List[tuple[str, str]] = Field(..., description="List of supported source-destination chain pairs")
   fee_structure: Dict[str, str] = Field(..., description="Fee structure for the bridge")
   operational: bool = Field(..., description="Indicates if the bridge is operational")
   last_updated: str = Field(..., description="Timestamp of the last status update")
   liquidity: Optional[Dict[str, Dict[str, str]]] = Field(default=None, description="Current liquidity available in the bridge")
   
class SimpleTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> TokenInfo:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{AUTH_ISSUER_URL}/introspect",
                    json={"token": token}
                ) as response:
                    data = await response.json()
                    if data.get("active", False):
                        return TokenInfo(
                            sub=data.get("sub", ""),
                            scopes=data.get("scope", "").split(),
                            expires_at=datetime.fromtimestamp(data.get("exp", 0))
                        )
                    raise ValueError("Invalid token")
            except Exception as e:
                raise ValueError(f"Token verification failed: {str(e)}")

@dataclass
class TokenInfo(BaseModel):
    sub: str = Field(description="Subject identifier of the token")
    scopes: List[str] = Field(description="List of scopes granted by the token")
    expires_at: datetime = Field(description="Token expiration timestamp")

@dataclass
class AppContext:
    web3_connections: Dict[str, Web3]
    db_connection: sqlite3.Connection
    abi_cache: TTLCache
    gas_price_cache: TTLCache
    
class CrossChainBridgeServer:
    """MCP server for cross-chain bridge operations."""
    def __init__(self):
        self.mcp = FastMCP(
            name = "CrossChainBridge",
            stateless_http = True,
            dependencies = ["web3", "httpx", "python-dotenv", "cachetools", "aiohttp", "requests", "pydantic", "sqlalchemy"],
            auth = AuthSettings(
                issuer_url=AUTH_ISSUER_URL,
                resource_server_url=AUTH_SERVER_URL,
                required_scopes = ["bridge:read", "bridge:write"],
                ),
            token_verifier = SimpleTokenVerifier(),
            lifespan = self._app_lifespan,
            
            )
        self.transactions: Dict[str, BridgeTransaction] = {}
        self._setup_handlers()
    
    @asynccontextmanager
    async def _app_lifespan(self, server: FastMCP) -> AsyncIterator[AppContext]:
        """Manage server lifecycle"""
        web3_connections = {}
        db_connection = self._initialize_db()
        abi_cache = TTLCache(maxsize=100, ttl=3600)
        gas_price_cache = TTLCache(maxsize=50, ttl=300)
        
        try:
            # Initialize Web3 connections
            for chain_name, chain_config in SUPPORTED_CHAINS.items():
                try:
                    w3 = Web3(Web3.HTTPProvider(chain_config["rpc_url"]))
                    if chain_name == "polygon":
                        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
                    if w3.is_connected():
                        web3_connections[chain_name] = w3
                        logger.info(f"Connected to {chain_name} network")
                    else:
                        logger.warning(f"Failed to connect to {chain_name} network")
                except Exception as e:
                    logger.error(f"Error connecting to {chain_name}: {e}")
            
            yield AppContext(
                web3_connections=web3_connections,
                db_connection=db_connection,
                abi_cache=abi_cache,
                gas_price_cache=gas_price_cache
            )
        finally:
            db_connection.close()
            logger.info("Server shutdown: Closed database connection")
    
    def _initialize_db(self) -> sqlite3.Connection:
        """Initialize SQLite database for transaction tracking"""
        conn = sqlite3.connect("bridge_transactions.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                source_chain TEXT,
                destination_chain TEXT,
                asset TEXT,
                amount TEXT,
                sender TEXT,
                recipient TEXT,
                status TEXT,
                source_tx_hash TEXT,
                destination_tx_hash TEXT,
                created_at TEXT,
                completed_at TEXT,
                estimated_completion TEXT,
                fee TEXT,
                bridge_contract TEXT,
                signature TEXT
            )
        """)
        conn.commit()
        return conn
    def _setup_handlers(self):
        """Setup MCP handlers for various operations"""
        @self.mcp.resource("bridge://config/chains")
        async def get_chain_config() -> str:
            """Get supported chain configurations"""
            return json.dumps(SUPPORTED_CHAINS, indent=2)
        @self.mcp.resource("bridge://config/contracts")
        async def get_contracts_config() -> str:
            """Get bridge contract configurations"""
            return json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "abi"} for k, v in BRIDGE_CONTRACTS.items()}, indent=2)
        
        @self.mcp.resource("bridge://status/networks")
        async def get_network_status() -> str:
            """Get real-time network status"""
            return json.dumps(await self._get_network_status(), indent=2)
        
        @self.mcp.resource("bridge://analytics/overview")
        async def get_analytics_overview() -> str:
            """Get bridge analytics overview"""
            return json.dumps(await self._get_analytics_overview(), indent=2)
        
        @self.mcp.resource("bridge://documentation/api")
        async def get_api_documentation() -> str:
            """Get API documentation"""
            return self._get_api_documentation()
        
        @self.mcp.tool()
        async def estimate_bridge_fees(
            source_chain: str,
            destination_chain: str,
            asset: str,
            amount: str,
            priority: str = "medium"
        ) -> FeeEstimate:
            """Estimate fees for cross-chain transfer"""
            result = await self._estimate_bridge_fees(source_chain, destination_chain, asset, amount, priority)
            if "error" in result:
                raise ValueError(result["error"])
            return FeeEstimate(**result["fees"], estimated_time=result["estimated_completion_time"],
                            gas_price=result["gas_estimates"]["source_gas_price"],
                            gas_limit=result["gas_estimates"]["source_gas_limit"])
        
        @self.mcp.tool()
        async def execute_bridge_transaction(
            source_chain: str,
            destination_chain: str,
            asset: str,
            amount: str,
            recipient: str,
            private_key: str,
            max_fee: str = "0.01",
            deadline: str = ""
        ) -> BridgeTransaction:
            """Execute cross-chain transfer"""
            result = await self._execute_bridge_transfer(source_chain, destination_chain, asset, amount,
                                                      recipient, private_key, max_fee, deadline)
            if "error" in result:
                raise ValueError(result["error"])
            return BridgeTransaction(**result, status="pending")
        
        @self.mcp.tool()
        async def monitor_bridge_events(
            bridge_contract: str,
            event_types: List[str] = None,
            from_block: str = "latest",
            duration: int = 300
        ) -> List[BridgeEvent]:
            """Monitor bridge contract events"""
            result = await self._monitor_bridge_events(bridge_contract, event_types, from_block, duration)
            if "error" in result:
                raise ValueError(result["error"])
            return [BridgeEvent(**event) for event in result["events"]]
        
        @self.mcp.tool()
        async def get_bridge_status(
            bridge_contract: Optional[str] = None,
            include_liquidity: bool = True
        ) -> Dict[str, BridgeStatus]:
            """Get bridge status"""
            result = await self._get_bridge_status(bridge_contract, include_liquidity)
            if "error" in result:
                raise ValueError(result["error"])
            return {k: BridgeStatus(**v) for k, v in result["bridge_status"].items()}
        
        @self.mcp.tool()
        async def get_transaction_history(
            address: Optional[str] = None,
            source_chain: Optional[str] = None,
            destination_chain: Optional[str] = None,
            status: Optional[str] = None,
            limit: int = 50,
            offset: int = 0
        ) -> List[BridgeTransaction]:
            """Get transaction history"""
            result = await self._get_transaction_history(address, source_chain, destination_chain, status, limit, offset)
            if "error" in result:
                raise ValueError(result["error"])
            return [BridgeTransaction(**tx) for tx in result["transactions"]]
        
        @self.mcp.tool()
        async def validate_bridge_transaction(
            source_chain: str,
            destination_chain: str,
            asset: str,
            amount: str,
            sender: str,
            recipient: str
        ) -> Dict[str, Any]:
            """Validate bridge transaction"""
            return await self._validate_bridge_transaction(source_chain, destination_chain, asset, amount, sender, recipient)
           
        @self.mcp.tool()
        async def get_supported_assets(
            source_chain: Optional[str] = None,
            destination_chain: Optional[str] = None
        ) -> Dict[str, Any]:
            """Get supported assets"""
            return await self._get_supported_assets(source_chain, destination_chain)
        
        @self.mcp.tool()
        async def cancel_bridge_transaction(
            transaction_id: str,
            private_key: str
        ) -> Dict[str, Any]:
            """Cancel pending transaction"""
            return await self._cancel_bridge_transaction(transaction_id, private_key)
        
        
        @self.mcp.tool()
        async def get_bridge_analytics(
            time_range: str = "24h",
            bridge_contract: Optional[str] = None,
            metric_type: str = "volume"
        ) -> Dict[str, Any]:
            """Get bridge analytics"""
            return await self._get_bridge_analytics(time_range, bridge_contract, metric_type)
        
        @self.mcp.tool()
        async def optimize_bridge_route(
            source_chain: str,
            destination_chain: str,
            asset: str,
            amount: str,
            optimization_goal: str = "lowest_cost"
        ) -> Dict[str, Any]:
            """Optimize bridge route"""
            return await self._optimize_bridge_route(source_chain, destination_chain, asset, amount, optimization_goal)
        
        
        @self.mcp.completion()
        async def handle_completion(
            ref: ResourceTemplateReference,
            argument: CompletionArgument,
            context: Optional[CompletionContext]
        ) -> Optional[Completion]:
            """Provide completion suggestions"""
            if ref.uri == "bridge://chains/{chain}":
                if argument.name == "chain":
                    chains = list(SUPPORTED_CHAINS.keys())
                    filtered = [c for c in chains if c.startswith(argument.value)]
                    return Completion(values=filtered)
            elif ref.uri == "bridge://assets/{asset}":
                if argument.name == "asset":
                    assets = await self._get_supported_assets(context.arguments.get("source_chain") if context else None,
                                                            context.arguments.get("destination_chain") if context else None)
                    symbols = [a["symbol"] for a in assets["assets"]]
                    filtered = [s for s in symbols if s.startswith(argument.value)]
                    return Completion(values=filtered)
            return None
    
    async def _estimate_bridge_fees(self, source_chain: str, destination_chain: str, 
                                   asset: str, amount: str, priority: str = "medium") -> Dict[str, Any]:
        """Estimate fees for cross-chain transfer"""
        ctx = self.mcp.get_context()
        w3_connections = ctx.request_context.lifespan_context["web3_connections"]
        async with aiohttp.ClientSession() as session:
            try:
                if source_chain not in SUPPORTED_CHAINS or destination_chain not in SUPPORTED_CHAINS:
                    return {"error": f"Unsupported chain: {source_chain} or {destination_chain}"}
                
                bridge_name = self._find_bridge(source_chain, destination_chain)
                if not bridge_name:
                    return {"error": f"No bridge available for {source_chain} -> {destination_chain}"}
                
                bridge_config = BRIDGE_CONTRACTS[bridge_name]
                source_w3 = w3_connections.get(source_chain)
                dest_w3 = w3_connections.get(destination_chain)
                
                if not source_w3 or not dest_w3:
                    return {"error": "Web3 connection not available"}
                
                abi_cache = ctx.request_context.lifespan_context["abi_cache"]
                gas_price_cache = ctx.request_context.lifespan_context["gas_price_cache"]
                
                source_gas_price = await self._get_cached_gas_price(source_chain, source_w3, priority, gas_price_cache)
                dest_gas_price = await self._get_cached_gas_price(destination_chain, dest_w3, priority, gas_price_cache)
                
                source_contract = source_w3.eth.contract(
                    address=to_checksum_address(bridge_config[f"{source_chain}_address"]),
                    abi=await self._get_contract_abi(bridge_name, source_chain, abi_cache)
                )
                source_gas_limit = source_contract.functions.depositFor(
                    to_checksum_address("0x" + "0" * 40),
                    Web3.to_wei(Decimal(amount), "ether") if asset.upper() == SUPPORTED_CHAINS[source_chain]["native_token"] else 0
                ).estimate_gas({"from": to_checksum_address("0x" + "0" * 40)})
                
                dest_contract = dest_w3.eth.contract(
                    address=to_checksum_address(bridge_config[f"{destination_chain}_address"]),
                    abi=await self._get_contract_abi(bridge_name, destination_chain, abi_cache)
                )
                dest_gas_limit = dest_contract.functions.release(
                    to_checksum_address("0x" + "0" * 40),
                    Web3.to_wei(Decimal(amount), "ether") if asset.upper() == SUPPORTED_CHAINS[destination_chain]["native_token"] else 0
                ).estimate_gas({"from": to_checksum_address("0x" + "0" * 40)}) if "release" in [f["name"] for f in bridge_config["abi"]] else 80000
                
                source_fee = str(Web3.from_wei(source_gas_price * source_gas_limit, "ether"))
                dest_fee = str(Web3.from_wei(dest_gas_price * dest_gas_limit, "ether"))
                bridge_base_fee = float(bridge_config["fee_structure"]["base_fee"])
                bridge_percentage = float(bridge_config["fee_structure"]["percentage_fee"])
                bridge_fee = bridge_base_fee + (float(amount) * bridge_percentage)
                total_fee = float(source_fee) + float(dest_fee) + bridge_fee
                
                return {
                    "fees": {
                        "source_chain_fee": source_fee,
                        "destination_chain_fee": dest_fee,
                        "bridge_fee": str(bridge_fee),
                        "total_fee": str(total_fee)
                    },
                    "gas_estimates": {
                        "source_gas_price": str(source_gas_price),
                        "source_gas_limit": str(source_gas_limit),
                        "dest_gas_price": str(dest_gas_price),
                        "dest_gas_limit": str(dest_gas_limit)
                    },
                    "estimated_completion_time": self._estimate_completion_time(source_chain, destination_chain),
                    "bridge_contract": bridge_name,
                    "priority": priority
                }
            except Exception as e:
                logger.error(f"Error estimating fees: {e}")
                return {"error": str(e)}
    
    async def _execute_bridge_transfer(self, source_chain: str, destination_chain: str,
                                     asset: str, amount: str, recipient: str,
                                     private_key: str, max_fee: str, deadline: str) -> Dict[str, Any]:
        """Execute cross-chain transfer"""
        ctx = self.mcp.get_context()
        w3_connections = ctx.request_context.lifespan_context["web3_connections"]
        async with aiohttp.ClientSession() as session:
            try:
                validation_result = await self._validate_bridge_transaction(
                    source_chain, destination_chain, asset, amount,
                    Account.from_key(private_key).address, recipient
                )
                if "error" in validation_result:
                    return validation_result
                
                fee_estimate = await self._estimate_bridge_fees(source_chain, destination_chain, asset, amount)
                if "error" in fee_estimate:
                    return fee_estimate
                
                if float(fee_estimate["fees"]["total_fee"]) > float(max_fee):
                    return {
                        "error": "Transaction fee exceeds maximum allowed",
                        "estimated_fee": fee_estimate["fees"]["total_fee"],
                        "max_fee": max_fee
                    }
                
                tx_id = self._generate_transaction_id()
                signature = self._generate_hmac_signature(tx_id, source_chain, destination_chain, amount, recipient)
                
                transaction = BridgeTransaction(
                    id=tx_id,
                    source_chain=source_chain,
                    destination_chain=destination_chain,
                    asset=asset,
                    amount=amount,
                    sender=Account.from_key(private_key).address,
                    recipient=recipient,
                    status=TransactionStatus.PENDING.value,
                    created_at=datetime.now().isoformat(),
                    fees=FeeEstimate(**fee_estimate["fees"],
                                  estimated_time=fee_estimate["estimated_completion_time"],
                                  gas_price=fee_estimate["gas_estimates"]["source_gas_price"],
                                  gas_limit=fee_estimate["gas_estimates"]["source_gas_limit"]),
                    bridge_contract=fee_estimate["bridge_contract"],
                    signature=signature
                )
                self._save_transaction(transaction)
                
                max_attempts = 3
                for attempt in range(max_attempts):
                    try:
                        bridge_result = await self._execute_bridge_contract(
                            transaction, private_key, fee_estimate, w3_connections
                        )
                        if bridge_result["success"]:
                            transaction.source_tx_hash = bridge_result["transaction_hash"]
                            transaction.status = TransactionStatus.PENDING.value
                            transaction.estimated_completion = (datetime.now() + timedelta(
                                seconds=self._parse_completion_time(fee_estimate["estimated_completion_time"])
                            )).isoformat()
                            self._save_transaction(transaction)
                            
                            asyncio.create_task(self._monitor_transaction_completion(transaction))
                            
                            return asdict(transaction)
                    except Exception as e:
                        if attempt < max_attempts - 1:
                            logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying...")
                            await asyncio.sleep(5)
                        else:
                            transaction.status = TransactionStatus.FAILED.value
                            self._save_transaction(transaction)
                            return {"error": str(e), "transaction_id": tx_id, "status": "failed"}
                
                return {"error": "All attempts failed", "transaction_id": tx_id, "status": "failed"}
            
            except Exception as e:
                logger.error(f"Error executing bridge transfer: {e}")
                return {"error": str(e)}
    
    
    async def _monitor_bridge_events(self, bridge_contract: str, event_types: List[str] = None,
                                   from_block: str = "latest", duration: int = 300) -> Dict[str, Any]:
        """Monitor bridge contract events"""
        ctx = self.mcp.get_context()
        w3_connections = ctx.request_context.lifespan_context["web3_connections"]
        async with aiohttp.ClientSession() as session:
            try:
                if bridge_contract not in BRIDGE_CONTRACTS:
                    return {"error": "Unknown bridge contract"}
                
                if event_types is None:
                    event_types = ["TransferInitiated", "TransferCompleted"]
                
                bridge_config = BRIDGE_CONTRACTS[bridge_contract]
                events = []
                
                for chain_pair in bridge_config["supported_pairs"]:
                    source_chain, dest_chain = chain_pair
                    source_w3 = w3_connections.get(source_chain)
                    dest_w3 = w3_connections.get(dest_chain)
                    
                    if not source_w3 or not dest_w3:
                        return {"error": f"Web3 connection not available for {source_chain} or {dest_chain}"}
                    
                    abi_cache = ctx.request_context.lifespan_context["abi_cache"]
                    source_contract = source_w3.eth.contract(
                        address=to_checksum_address(bridge_config[f"{source_chain}_address"]),
                        abi=await self._get_contract_abi(bridge_contract, source_chain, abi_cache)
                    )
                    dest_contract = dest_w3.eth.contract(
                        address=to_checksum_address(bridge_config[f"{dest_chain}_address"]),
                        abi=await self._get_contract_abi(bridge_contract, dest_chain, abi_cache)
                    )
                    
                    for event_type in event_types:
                        try:
                            event_filter = source_contract.events[event_type].create_filter(fromBlock=from_block)
                            dest_filter = dest_contract.events[event_type].create_filter(fromBlock=from_block)
                            
                            start_time = time.time()
                            while time.time() - start_time < duration:
                                for event in event_filter.get_new_entries() + dest_filter.get_new_entries():
                                    events.append({
                                        "event_type": event["event"],
                                        "transaction_hash": event["transactionHash"].hex(),
                                        "block_number": event["blockNumber"],
                                        "timestamp": datetime.fromtimestamp(source_w3.eth.get_block(event["blockNumber"]).timestamp).isoformat(),
                                        "data": {k: str(v) for k, v in event["args"].items()}
                                    })
                                await asyncio.sleep(10)
                        except Exception as e:
                            logger.warning(f"Error monitoring {event_type}: {e}")
                
                return {
                    "bridge_contract": bridge_contract,
                    "monitoring_duration": duration,
                    "events_found": len(events),
                    "events": events,
                    "status": "completed",
                    "timestamp": datetime.now().isoformat()
                }
            
            except Exception as e:
                logger.error(f"Error monitoring bridge events: {e}")
                return {"error": str(e)}
            
    async def _get_bridge_status(self, bridge_contract: Optional[str] = None, 
                               include_liquidity: bool = True) -> Dict[str, Any]:
        """Get bridge status"""
        ctx = self.mcp.get_context()
        w3_connections = ctx.request_context.lifespan_context["web3_connections"]
        async with aiohttp.ClientSession() as session:
            try:
                status_data = {}
                
                if bridge_contract:
                    if bridge_contract not in BRIDGE_CONTRACTS:
                        return {"error": "Unknown bridge contract"}
                    bridge_config = BRIDGE_CONTRACTS[bridge_contract]
                    status_data[bridge_contract] = await self._get_single_bridge_status(
                        bridge_contract, bridge_config, include_liquidity, w3_connections
                    )
                else:
                    for bridge_name, bridge_config in BRIDGE_CONTRACTS.items():
                        status_data[bridge_name] = await self._get_single_bridge_status(
                            bridge_name, bridge_config, include_liquidity, w3_connections
                        )
                
                return {
                    "timestamp": datetime.now().isoformat(),
                    "bridge_status": status_data,
                    "network_status": await self._get_network_status()
                }
            
            except Exception as e:
                logger.error(f"Error getting bridge status: {e}")
                return {"error": str(e)}
    
    async def _get_single_bridge_status(self, bridge_name: str, bridge_config: Dict[str, Any],
                                      include_liquidity: bool, w3_connections: Dict[str, Web3]) -> Dict[str, Any]:
        """Get status for a single bridge"""
        async with aiohttp.ClientSession() as session:
            try:
                abi_cache = self.mcp.get_context().request_context.lifespan_context["abi_cache"]
                status = {
                    "name": bridge_name,
                    "supported_pairs": bridge_config["supported_pairs"],
                    "fee_structure": bridge_config["fee_structure"],
                    "operational": True,
                    "last_updated": datetime.now().isoformat()
                }
                
                if include_liquidity:
                    liquidity = {}
                    for chain_pair in bridge_config["supported_pairs"]:
                        chain = chain_pair[0]
                        w3 = w3_connections.get(chain)
                        if w3:
                            contract = w3.eth.contract(
                                address=to_checksum_address(bridge_config[f"{chain}_address"]),
                                abi=await self._get_contract_abi(bridge_name, chain, abi_cache)
                            )
                            try:
                                tvl = contract.functions.totalSupply().call() if "totalSupply" in [f["name"] for f in bridge_config["abi"]] else 0
                                liquidity[chain] = {
                                    "total_value_locked": str(Web3.from_wei(tvl, "ether")),
                                    "available_liquidity": str(Web3.from_wei(tvl * 0.9, "ether")),
                                    "utilization_rate": "0.1"
                                }
                            except Exception as e:
                                liquidity[chain] = {"error": str(e)}
                    status["liquidity"] = liquidity
                
                return status
            
            except Exception as e:
                logger.error(f"Error getting single bridge status: {e}")
                return {"error": str(e)}
    
    async def _get_transaction_history(self, address: Optional[str] = None, source_chain: Optional[str] = None,
                                     destination_chain: Optional[str] = None, status: Optional[str] = None,
                                     limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Get transaction history"""
        ctx = self.mcp.get_context()
        db_connection = ctx.request_context.lifespan_context["db_connection"]
        async with aiohttp.ClientSession() as session:
            try:
                cursor = db_connection.cursor()
                query = "SELECT * FROM transactions WHERE 1=1"
                params = []
                
                if address:
                    query += " AND (sender = ? OR recipient = ?)"
                    params.extend([address, address])
                if source_chain:
                    query += " AND source_chain = ?"
                    params.append(source_chain)
                if destination_chain:
                    query += " AND destination_chain = ?"
                    params.append(destination_chain)
                if status:
                    query += " AND status = ?"
                    params.append(status)
                
                query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                transactions = [dict(zip([c[0] for c in cursor.description], row)) for row in cursor.fetchall()]
                
                if address and source_chain:
                    etherscan_txs = await self._fetch_etherscan_history(address, source_chain, limit)
                    for tx in etherscan_txs:
                        tx_id = f"etherscan_{tx['hash']}"
                        if tx_id not in self.transactions:
                            transaction = BridgeTransaction(
                                id=tx_id,
                                source_chain=source_chain,
                                destination_chain="unknown",
                                asset="ETH",
                                amount=str(Web3.from_wei(int(tx["value"]), "ether")),
                                sender=tx["from"],
                                recipient=tx["to"],
                                status=TransactionStatus.CONFIRMED.value,
                                source_tx_hash=tx["hash"],
                                created_at=datetime.fromtimestamp(int(tx["timeStamp"])).isoformat()
                            )
                            self._save_transaction(transaction, db_connection)
                            transactions.append(asdict(transaction))
                
                transactions.sort(key=lambda x: x["created_at"] or "", reverse=True)
                paginated_transactions = transactions[offset:offset + limit]
                
                return {
                    "transactions": paginated_transactions,
                    "total_count": len(transactions),
                    "limit": limit,
                    "offset": offset,
                    "has_more": len(transactions) > offset + limit
                }
            
            except Exception as e:
                logger.error(f"Error getting transaction history: {e}")
                return {"error": str(e)}
    
    async def _validate_bridge_transaction(self, source_chain: str, destination_chain: str,
                                         asset: str, amount: str, sender: str,
                                         recipient: str) -> Dict[str, Any]:
        """Validate bridge transaction"""
        async with aiohttp.ClientSession() as session:
            try:
                validation_errors = []
                warnings = []
                
                if source_chain not in SUPPORTED_CHAINS:
                    validation_errors.append(f"Unsupported source chain: {source_chain}")
                if destination_chain not in SUPPORTED_CHAINS:
                    validation_errors.append(f"Unsupported destination chain: {destination_chain}")
                
                if not self._find_bridge(source_chain, destination_chain):
                    validation_errors.append(f"No bridge available for {source_chain} -> {destination_chain}")
                
                if not is_address(sender):
                    validation_errors.append("Invalid sender address")
                if not is_address(recipient):
                    validation_errors.append("Invalid recipient address")
                
                try:
                    amount_decimal = Decimal(amount)
                    if amount_decimal <= 0:
                        validation_errors.append("Amount must be positive")
                    if amount_decimal < Decimal("0.001"):
                        warnings.append("Amount is very small, consider gas fees")
                except:
                    validation_errors.append("Invalid amount format")
                
                asset_validation = await self._validate_asset_support(asset, source_chain, destination_chain)
                if not asset_validation["supported"]:
                    validation_errors.append(asset_validation["error"])
                
                w3_connections = self.mcp.get_context().request_context.lifespan_context["web3_connections"]
                if source_chain in w3_connections:
                    balance_check = await self._check_balance(sender, asset, amount, source_chain, w3_connections)
                    if not balance_check["sufficient"]:
                        validation_errors.append(balance_check["error"])
                
                congestion_check = await self._check_network_congestion(source_chain, destination_chain, w3_connections)
                if congestion_check["high_congestion"]:
                    warnings.append(f"High network congestion on {congestion_check['congested_chain']}")
                
                return {
                    "valid": len(validation_errors) == 0,
                    "errors": validation_errors,
                    "warnings": warnings,
                    "estimated_fee": await self._estimate_bridge_fees(source_chain, destination_chain, asset, amount) if len(validation_errors) == 0 else None
                }
            
            except Exception as e:
                logger.error(f"Error validating transaction: {e}")
                return {"error": str(e)}
            
    
    async def _get_supported_assets(self, source_chain: Optional[str] = None, 
                                  destination_chain: Optional[str] = None) -> Dict[str, Any]:
        """Get supported assets"""
        async with aiohttp.ClientSession() as session:
            try:
                common_assets = [
                    {
                        "symbol": "ETH",
                        "name": "Ethereum",
                        "decimals": 18,
                        "type": "native",
                        "supported_chains": ["ethereum", "arbitrum", "optimism"]
                    },
                    {
                        "symbol": "USDC",
                        "name": "USD Coin",
                        "decimals": 6,
                        "type": "erc20",
                        "addresses": {
                            "ethereum": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                            "polygon": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
                            "arbitrum": "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8"
                        }
                    },
                    {
                        "symbol": "USDT",
                        "name": "Tether USD",
                        "decimals": 6,
                        "type": "erc20",
                        "addresses": {
                            "ethereum": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                            "polygon": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
                            "arbitrum": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
                        }
                    },
                    {
                        "symbol": "DAI",
                        "name": "Dai Stablecoin",
                        "decimals": 18,
                        "type": "erc20",
                        "addresses": {
                            "ethereum": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                            "polygon": "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063"
                        }
                    }
                ]
                
                if source_chain or destination_chain:
                    filtered_assets = []
                    for asset in common_assets:
                        if asset["type"] == "native":
                            if source_chain and SUPPORTED_CHAINS.get(source_chain, {}).get("native_token") != asset["symbol"]:
                                continue
                            if destination_chain and SUPPORTED_CHAINS.get(destination_chain, {}).get("native_token") != asset["symbol"]:
                                continue
                        elif asset["type"] == "erc20":
                            if source_chain and source_chain not in asset.get("addresses", {}):
                                continue
                            if destination_chain and destination_chain not in asset.get("addresses", {}):
                                continue
                        filtered_assets.append(asset)
                    return {
                        "assets": filtered_assets,
                        "source_chain": source_chain,
                        "destination_chain": destination_chain
                    }
                
                return {"assets": common_assets}
            
            except Exception as e:
                logger.error(f"Error getting supported assets: {e}")
                return {"error": str(e)}
    
    
    async def _cancel_bridge_transaction(self, transaction_id: str, private_key: str) -> Dict[str, Any]:
        """Cancel pending transaction"""
        ctx = self.mcp.get_context()
        db_connection = ctx.request_context.lifespan_context["db_connection"]
        async with aiohttp.ClientSession() as session:
            try:
                if transaction_id not in self.transactions:
                    return {"error": "Transaction not found"}
                
                transaction = self.transactions[transaction_id]
                sender_address = Account.from_key(private_key).address
                if transaction.sender != sender_address:
                    return {"error": "Unauthorized to cancel this transaction"}
                
                if transaction.status != TransactionStatus.PENDING.value:
                    return {"error": f"Cannot cancel transaction with status: {transaction.status}"}
                
                w3_connections = ctx.request_context.lifespan_context["web3_connections"]
                if transaction.source_tx_hash:
                    w3 = w3_connections.get(transaction.source_chain)
                    if w3:
                        try:
                            tx = w3.eth.get_transaction(transaction.source_tx_hash)
                            if tx["blockNumber"]:
                                return {"error": "Transaction already confirmed on-chain, cannot cancel"}
                        except TransactionNotFound:
                            pass
                
                transaction.status = TransactionStatus.CANCELLED.value
                transaction.completed_at = datetime.now().isoformat()
                self._save_transaction(transaction, db_connection)
                
                return {
                    "success": True,
                    "transaction_id": transaction_id,
                    "status": "cancelled",
                    "cancelled_at": transaction.completed_at
                }
            
            except Exception as e:
                logger.error(f"Error cancelling transaction: {e}")
                return {"error": str(e)}
    
    
    async def _get_bridge_analytics(self, time_range: str = "24h", bridge_contract: Optional[str] = None,
                                  metric_type: str = "volume") -> Dict[str, Any]:
        """Get bridge analytics"""
        ctx = self.mcp.get_context()
        db_connection = ctx.request_context.lifespan_context["db_connection"]
        async with aiohttp.ClientSession() as session:
            try:
                now = datetime.now()
                time_deltas = {
                    "24h": timedelta(hours=24),
                    "7d": timedelta(days=7),
                    "30d": timedelta(days=30),
                    "90d": timedelta(days=90)
                }
                start_time = now - time_deltas[time_range]
                
                cursor = db_connection.cursor()
                query = "SELECT * FROM transactions WHERE created_at >= ?"
                params = [start_time.isoformat()]
                if bridge_contract:
                    query += " AND bridge_contract = ?"
                    params.append(bridge_contract)
                
                cursor.execute(query, params)
                transactions = [BridgeTransaction(**dict(zip([c[0] for c in cursor.description], row))) for row in cursor.fetchall()]
                
                if metric_type == "volume":
                    analytics = self._calculate_volume_analytics(transactions)
                elif metric_type == "transactions":
                    analytics = self._calculate_transaction_analytics(transactions)
                elif metric_type == "fees":
                    analytics = self._calculate_fee_analytics(transactions)
                elif metric_type == "success_rate":
                    analytics = self._calculate_success_rate_analytics(transactions)
                else:
                    return {"error": "Invalid metric type"}
                
                return {
                    "time_range": time_range,
                    "bridge_contract": bridge_contract,
                    "metric_type": metric_type,
                    "period": {
                        "start": start_time.isoformat(),
                        "end": now.isoformat()
                    },
                    "analytics": analytics
                }
            
            except Exception as e:
                logger.error(f"Error getting bridge analytics: {e}")
                return {"error": str(e)}
    
    async def _optimize_bridge_route(self, source_chain: str, destination_chain: str,
                                   asset: str, amount: str, 
                                   optimization_goal: str = "lowest_cost") -> Dict[str, Any]:
        """Optimize bridge route"""
        async with aiohttp.ClientSession() as session:
            try:
                routes = await self._find_all_routes(source_chain, destination_chain, asset, amount)
                if not routes:
                    return {"error": "No routes available for this transfer"}
                
                if optimization_goal == "lowest_cost":
                    optimal_route = min(routes, key=lambda r: float(r["total_cost"]))
                elif optimization_goal == "fastest_time":
                    optimal_route = min(routes, key=lambda r: r["estimated_time_seconds"])
                elif optimization_goal == "best_route":
                    optimal_route = min(routes, key=lambda r: 
                        float(r["total_cost"]) * 0.6 + r["estimated_time_seconds"] / 3600 * 0.4)
                else:
                    return {"error": "Invalid optimization goal"}
                
                return {
                    "optimization_goal": optimization_goal,
                    "optimal_route": optimal_route,
                    "alternative_routes": [r for r in routes if r != optimal_route][:3],
                    "route_comparison": {
                        "total_routes_found": len(routes),
                        "cost_range": {
                            "min": min(float(r["total_cost"]) for r in routes),
                            "max": max(float(r["total_cost"]) for r in routes)
                        },
                        "time_range": {
                            "min": min(r["estimated_time_seconds"] for r in routes),
                            "max": max(r["estimated_time_seconds"] for r in routes)
                        }
                    }
                }
            
            except Exception as e:
                logger.error(f"Error optimizing bridge route: {e}")
                return {"error": str(e)}
    
    async def _get_contract_abi(self, bridge_name: str, chain: str, abi_cache: TTLCache) -> List:
        """Fetch contract ABI from Etherscan"""
        cache_key = f"{bridge_name}_{chain}"
        if cache_key in abi_cache:
            return abi_cache[cache_key]
        
        async with aiohttp.ClientSession() as session:
            try:
                url = SUPPORTED_CHAINS[chain]["explorer"]
                params = {
                    "module": "contract",
                    "action": "getabi",
                    "address": BRIDGE_CONTRACTS[bridge_name][f"{chain}_address"],
                    "apikey": ETHERSCAN_API_KEY
                }
                async with session.get(url, params=params) as response:
                    data = await response.json()
                    if data["status"] == "1":
                        abi = json.loads(data["result"])
                        abi_cache[cache_key] = abi
                        return abi
                    else:
                        raise ValueError(f"Failed to fetch ABI: {data['message']}")
            except Exception as e:
                logger.error(f"Error fetching ABI for {bridge_name} on {chain}: {e}")
                return BRIDGE_CONTRACTS[bridge_name]["abi"]
    
    async def _get_cached_gas_price(self, chain: str, w3: Web3, priority: str, gas_price_cache: TTLCache) -> int:
        """Get cached gas price"""
        cache_key = f"{chain}_{priority}"
        if cache_key in gas_price_cache:
            return gas_price_cache[cache_key]
        
        gas_price = w3.eth.gas_price
        multiplier = {"low": 0.8, "medium": 1.0, "high": 1.2}[priority]
        adjusted_gas_price = int(gas_price * multiplier)
        gas_price_cache[cache_key] = adjusted_gas_price
        return adjusted_gas_price
    
    async def _fetch_etherscan_history(self, address: str, chain: str, limit: int) -> List[Dict]:
        """Fetch transaction history from Etherscan"""
        async with aiohttp.ClientSession() as session:
            try:
                url = SUPPORTED_CHAINS[chain]["explorer"]
                params = {
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "sort": "desc",
                    "apikey": ETHERSCAN_API_KEY
                }
                async with session.get(url, params=params) as response:
                    data = await response.json()
                    if data["status"] == "1":
                        return data["result"][:limit]
                    return []
            except Exception as e:
                logger.error(f"Error fetching Etherscan history: {e}")
                return []
    
    def _save_transaction(self, transaction: BridgeTransaction, db_connection: sqlite3.Connection):
        """Save transaction to database"""
        try:
            cursor = db_connection.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO transactions (
                    id, source_chain, destination_chain, asset, amount, sender, recipient,
                    status, source_tx_hash, destination_tx_hash, created_at, completed_at,
                    estimated_completion, fees, bridge_contract, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                transaction.id, transaction.source_chain, transaction.destination_chain,
                transaction.asset, transaction.amount, transaction.sender, transaction.recipient,
                transaction.status, transaction.source_tx_hash, transaction.destination_tx_hash,
                transaction.created_at, transaction.completed_at,
                transaction.estimated_completion,
                json.dumps(transaction.fees.dict() if transaction.fees else None),
                transaction.bridge_contract, transaction.signature
            ))
            db_connection.commit()
            self.transactions[transaction.id] = transaction
        except Exception as e:
            logger.error(f"Error saving transaction: {e}")
    
    def _generate_hmac_signature(self, tx_id: str, source_chain: str, destination_chain: str,
                               amount: str, recipient: str) -> str:
        """Generate HMAC signature"""
        message = f"{tx_id}:{source_chain}:{destination_chain}:{amount}:{recipient}"
        return hmac.new(
            HMAC_SECRET.encode(), message.encode(), hashlib.sha256
        ).hexdigest()
        
    
    async def _execute_bridge_contract(self, transaction: BridgeTransaction, 
                                     private_key: str, fee_estimate: Dict[str, Any],
                                     w3_connections: Dict[str, Web3]) -> Dict[str, Any]:
        """Execute bridge contract"""
        async with aiohttp.ClientSession() as session:
            try:
                source_w3 = w3_connections.get(transaction.source_chain)
                if not source_w3:
                    return {"success": False, "error": "Web3 connection not available"}
                
                abi_cache = self.mcp.get_context().request_context.lifespan_context["abi_cache"]
                bridge_config = BRIDGE_CONTRACTS[transaction.bridge_contract]
                contract = source_w3.eth.contract(
                    address=to_checksum_address(bridge_config[f"{transaction.source_chain}_address"]),
                    abi=await self._get_contract_abi(transaction.bridge_contract, transaction.source_chain, abi_cache)
                )
                
                amount_wei = Web3.to_wei(Decimal(transaction.amount), "ether") if transaction.asset.upper() == SUPPORTED_CHAINS[transaction.source_chain]["native_token"] else int(transaction.amount)
                tx_data = contract.functions.depositFor(
                    to_checksum_address(transaction.recipient),
                    amount_wei
                ).build_transaction({
                    "from": to_checksum_address(transaction.sender),
                    "value": amount_wei if transaction.asset.upper() == SUPPORTED_CHAINS[transaction.source_chain]["native_token"] else 0,
                    "gas": int(fee_estimate["gas_estimates"]["source_gas_limit"]),
                    "gasPrice": int(fee_estimate["gas_estimates"]["source_gas_price"]),
                    "nonce": source_w3.eth.get_transaction_count(transaction.sender)
                })
                
                signed_tx = source_w3.eth.account.sign_transaction(tx_data, private_key)
                tx_hash = source_w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = source_w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                
                return {
                    "success": receipt.status == 1,
                    "transaction_hash": tx_hash.hex(),
                    "block_number": receipt.blockNumber,
                    "gas_used": str(receipt.gasUsed)
                }
            
            except Exception as e:
                logger.error(f"Error executing bridge contract: {e}")
                return {"success": False, "error": str(e)}
    
    async def _monitor_transaction_completion(self, transaction: BridgeTransaction):
        """Monitor transaction completion"""
        ctx = self.mcp.get_context()
        w3_connections = ctx.request_context.lifespan_context["web3_connections"]
        db_connection = ctx.request_context.lifespan_context["db_connection"]
        try:
            dest_w3 = w3_connections.get(transaction.destination_chain)
            if not dest_w3:
                return
            
            abi_cache = ctx.request_context.lifespan_context["abi_cache"]
            bridge_config = BRIDGE_CONTRACTS[transaction.bridge_contract]
            contract = dest_w3.eth.contract(
                address=to_checksum_address(bridge_config[f"{transaction.destination_chain}_address"]),
                abi=await self._get_contract_abi(transaction.bridge_contract, transaction.destination_chain, abi_cache)
            )
            
            event_filter = contract.events.TransferCompleted.create_filter(fromBlock="latest")
            start_time = time.time()
            
            while time.time() - start_time < 3600:
                for event in event_filter.get_new_entries():
                    if event["args"]["recipient"] == to_checksum_address(transaction.recipient):
                        transaction.destination_tx_hash = event["transactionHash"].hex()
                        transaction.status = TransactionStatus.CONFIRMED.value
                        transaction.completed_at = datetime.now().isoformat()
                        self._save_transaction(transaction, db_connection)
                        return
                await asyncio.sleep(10)
            
            transaction.status = TransactionStatus.FAILED.value
            transaction.completed_at = datetime.now().isoformat()
            self._save_transaction(transaction, db_connection)
        
        except Exception as e:
            logger.error(f"Error monitoring transaction completion: {e}")
            transaction.status = TransactionStatus.FAILED.value
            transaction.completed_at = datetime.now().isoformat()
            self._save_transaction(transaction, db_connection)
    
    async def _get_network_status(self) -> Dict[str, Any]:
        """Get network status"""
        ctx = self.mcp.get_context()
        w3_connections = ctx.request_context.lifespan_context["web3_connections"]
        network_status = {}
        async with aiohttp.ClientSession() as session:
            for chain_name, chain_config in SUPPORTED_CHAINS.items():
                w3 = w3_connections.get(chain_name)
                if w3:
                    try:
                        latest_block = w3.eth.block_number
                        gas_price = w3.eth.gas_price
                        network_status[chain_name] = {
                            "online": True,
                            "latest_block": latest_block,
                            "gas_price": str(Web3.from_wei(gas_price, "gwei")),
                            "chain_id": chain_config["chain_id"],
                            "last_updated": datetime.now().isoformat()
                        }
                    except Exception as e:
                        network_status[chain_name] = {
                            "online": False,
                            "error": str(e),
                            "last_updated": datetime.now().isoformat()
                        }
                else:
                    network_status[chain_name] = {
                        "online": False,
                        "error": "Web3 connection not available",
                        "last_updated": datetime.now().isoformat()
                    }
        return network_status
    
    async def _get_analytics_overview(self) -> Dict[str, Any]:
        """Get analytics overview"""
        ctx = self.mcp.get_context()
        db_connection = ctx.request_context.lifespan_context["db_connection"]
        cursor = db_connection.cursor()
        cursor.execute("SELECT COUNT(*) as total, SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END) as completed FROM transactions")
        result = cursor.fetchone()
        
        return {
            "total_transactions": result[0],
            "completed_transactions": result[1],
            "success_rate": result[1] / result[0] if result[0] > 0 else 0,
            "supported_chains": len(SUPPORTED_CHAINS),
            "supported_bridges": len(BRIDGE_CONTRACTS),
            "last_updated": datetime.now().isoformat()
        }
    
    def _calculate_volume_analytics(self, transactions: List[BridgeTransaction]) -> Dict[str, Any]:
        """Calculate volume analytics"""
        total_volume = sum(float(tx.amount) for tx in transactions)
        volume_by_source = {}
        volume_by_destination = {}
        
        for tx in transactions:
            volume_by_source[tx.source_chain] = volume_by_source.get(tx.source_chain, 0) + float(tx.amount)
            volume_by_destination[tx.destination_chain] = volume_by_destination.get(tx.destination_chain, 0) + float(tx.amount)
        
        return {
            "total_volume": total_volume,
            "transaction_count": len(transactions),
            "average_transaction_size": total_volume / len(transactions) if transactions else 0,
            "volume_by_source_chain": volume_by_source,
            "volume_by_destination_chain": volume_by_destination
        }
    
    def _calculate_transaction_analytics(self, transactions: List[BridgeTransaction]) -> Dict[str, Any]:
        """Calculate transaction analytics"""
        status_counts = {}
        for tx in transactions:
            status_counts[tx.status] = status_counts.get(tx.status, 0) + 1
        
        return {
            "total_transactions": len(transactions),
            "status_breakdown": status_counts,
            "success_rate": status_counts.get(TransactionStatus.CONFIRMED.value, 0) / len(transactions) if transactions else 0
        }
    
    def _calculate_fee_analytics(self, transactions: List[BridgeTransaction]) -> Dict[str, Any]:
        """Calculate fee analytics"""
        total_fees = 0
        fee_breakdown = {"source_chain_fees": 0, "destination_chain_fees": 0, "bridge_fees": 0}
        
        for tx in transactions:
            if tx.fees:
                total_fees += float(tx.fees.total_fee)
                fee_breakdown["source_chain_fees"] += float(tx.fees.source_chain_fee)
                fee_breakdown["destination_chain_fees"] += float(tx.fees.destination_chain_fee)
                fee_breakdown["bridge_fees"] += float(tx.fees.bridge_fee)
        
        return {
            "total_fees_collected": total_fees,
            "average_fee_per_transaction": total_fees / len(transactions) if transactions else 0,
            "fee_breakdown": fee_breakdown
        }
    
    def _calculate_success_rate_analytics(self, transactions: List[BridgeTransaction]) -> Dict[str, Any]:
        """Calculate success rate analytics"""
        total = len(transactions)
        successful = sum(1 for tx in transactions if tx.status == TransactionStatus.CONFIRMED.value)
        failed = sum(1 for tx in transactions if tx.status == TransactionStatus.FAILED.value)
        pending = sum(1 for tx in transactions if tx.status == TransactionStatus.PENDING.value)
        
        return {
            "total_transactions": total,
            "successful_transactions": successful,
            "failed_transactions": failed,
            "pending_transactions": pending,
            "success_rate": successful / total if total > 0 else 0,
            "failure_rate": failed / total if total > 0 else 0
        }
    
    async def _find_all_routes(self, source_chain: str, destination_chain: str,
                             asset: str, amount: str) -> List[Dict[str, Any]]:
        """Find all possible routes"""
        async with aiohttp.ClientSession() as session:
            routes = []
            direct_bridge = self._find_bridge(source_chain, destination_chain)
            if direct_bridge:
                fee_estimate = await self._estimate_bridge_fees(source_chain, destination_chain, asset, amount)
                if "error" not in fee_estimate:
                    routes.append({
                        "type": "direct",
                        "path": [source_chain, destination_chain],
                        "bridges": [direct_bridge],
                        "total_cost": fee_estimate["fees"]["total_fee"],
                        "estimated_time_seconds": self._parse_completion_time(fee_estimate["estimated_completion_time"]),
                        "steps": 1
                    })
            
            for intermediate_chain in SUPPORTED_CHAINS.keys():
                if intermediate_chain not in [source_chain, destination_chain]:
                    bridge1 = self._find_bridge(source_chain, intermediate_chain)
                    bridge2 = self._find_bridge(intermediate_chain, destination_chain)
                    
                    if bridge1 and bridge2:
                        fee1 = await self._estimate_bridge_fees(source_chain, intermediate_chain, asset, amount)
                        fee2 = await self._estimate_bridge_fees(intermediate_chain, destination_chain, asset, amount)
                        
                        if "error" not in fee1 and "error" not in fee2:
                            total_cost = float(fee1["fees"]["total_fee"]) + float(fee2["fees"]["total_fee"])
                            total_time = (self._parse_completion_time(fee1["estimated_completion_time"]) + 
                                        self._parse_completion_time(fee2["estimated_completion_time"]))
                            
                            routes.append({
                                "type": "multi_hop",
                                "path": [source_chain, intermediate_chain, destination_chain],
                                "bridges": [bridge1, bridge2],
                                "total_cost": str(total_cost),
                                "estimated_time_seconds": total_time,
                                "steps": 2
                            })
            
            return routes
    
    def _find_bridge(self, source_chain: str, destination_chain: str) -> Optional[str]:
        """Find bridge contract"""
        for bridge_name, bridge_config in BRIDGE_CONTRACTS.items():
            if (source_chain, destination_chain) in bridge_config["supported_pairs"]:
                return bridge_name
        return None
    
    def _estimate_completion_time(self, source_chain: str, destination_chain: str) -> str:
        """Estimate completion time"""
        base_times = {
            ("ethereum", "polygon"): 10,
            ("polygon", "ethereum"): 30,
            ("ethereum", "arbitrum"): 7,
            ("arbitrum", "ethereum"): 7,
            ("ethereum", "optimism"): 5,
            ("optimism", "ethereum"): 20
        }
        estimated_minutes = base_times.get((source_chain, destination_chain), 15)
        return f"{estimated_minutes} minutes"
    
    def _parse_completion_time(self, time_str: str) -> int:
        """Parse completion time"""
        if "minute" in time_str:
            return int(time_str.split()[0]) * 60
        elif "hour" in time_str:
            return int(time_str.split()[0]) * 3600
        return 900
    
    def _generate_transaction_id(self) -> str:
        """Generate transaction ID"""
        return f"bridge_{int(time.time())}_{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
    
    async def _validate_asset_support(self, asset: str, source_chain: str, 
                                    destination_chain: str) -> Dict[str, Any]:
        """Validate asset support"""
        supported_assets = await self._get_supported_assets(source_chain, destination_chain)
        for supported_asset in supported_assets["assets"]:
            if (asset.upper() == supported_asset["symbol"] or 
                asset.lower() in supported_asset.get("addresses", {}).values()):
                return {"supported": True}
        return {"supported": False, "error": f"Asset {asset} not supported for this bridge"}
    
    async def _check_balance(self, address: str, asset: str, amount: str, 
                           chain: str, w3_connections: Dict[str, Web3]) -> Dict[str, Any]:
        """Check balance"""
        async with aiohttp.ClientSession() as session:
            try:
                w3 = w3_connections.get(chain)
                if not w3:
                    return {"sufficient": False, "error": "Web3 connection not available"}
                
                amount_wei = Web3.to_wei(Decimal(amount), "ether") if asset.upper() == SUPPORTED_CHAINS[chain]["native_token"] else int(amount)
                
                if asset.upper() == SUPPORTED_CHAINS[chain]["native_token"]:
                    balance = w3.eth.get_balance(to_checksum_address(address))
                else:
                    assets = await self._get_supported_assets(chain)
                    token_address = next((a["addresses"][chain] for a in assets["assets"] if a["symbol"] == asset.upper()), None)
                    if not token_address:
                        return {"sufficient": False, "error": f"Token {asset} not supported on {chain}"}
                    
                    contract = w3.eth.contract(
                        address=to_checksum_address(token_address),
                        abi=[{"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"}]
                    )
                    balance = contract.functions.balanceOf(to_checksum_address(address)).call()
                
                return {
                    "sufficient": balance >= amount_wei,
                    "balance": str(Web3.from_wei(balance, "ether") if asset.upper() == SUPPORTED_CHAINS[chain]["native_token"] else balance),
                    "required": str(amount)
                }
            
            except Exception as e:
                return {"sufficient": False, "error": str(e)}
    
    async def _check_network_congestion(self, source_chain: str, 
                                      destination_chain: str, w3_connections: Dict[str, Web3]) -> Dict[str, Any]:
        """Check network congestion"""
        async with aiohttp.ClientSession() as session:
            try:
                source_w3 = w3_connections.get(source_chain)
                dest_w3 = w3_connections.get(destination_chain)
                
                source_congestion = 0.5
                dest_congestion = 0.5
                
                if source_w3:
                    gas_price = source_w3.eth.gas_price
                    source_congestion = min(gas_price / (100 * 10**9), 1.0)
                if dest_w3:
                    gas_price = dest_w3.eth.gas_price
                    dest_congestion = min(gas_price / (100 * 10**9), 1.0)
                
                high_congestion = source_congestion > 0.6 or dest_congestion > 0.6
                congested_chain = source_chain if source_congestion > dest_congestion else destination_chain
                
                return {
                    "high_congestion": high_congestion,
                    "congested_chain": congested_chain if high_congestion else None,
                    "source_congestion": source_congestion,
                    "destination_congestion": dest_congestion
                }
            
            except Exception as e:
                return {"high_congestion": False, "error": str(e)}
    
    def _get_api_documentation(self) -> str:
        """Get API documentation"""
        return """# Cross-Chain Bridge Assistant API Documentation

## Overview
The Cross-Chain Bridge Assistant provides a secure platform for managing cross-chain asset transfers.

## Supported Networks
- Ethereum Mainnet (chain_id: 1)
- Polygon (chain_id: 137)
- Arbitrum One (chain_id: 42161)
- Optimism (chain_id: 10)

## Supported Bridges
- Polygon Bridge
- Arbitrum Bridge
- Optimism Bridge

## Tools
### estimate_bridge_fees
Estimate fees for cross-chain transfer.
- **Parameters**: source_chain, destination_chain, asset, amount, priority
- **Returns**: FeeEstimate (Pydantic model with fee breakdown)

### execute_bridge_transfer
Execute a cross-chain transfer.
- **Parameters**: source_chain, destination_chain, asset, amount, recipient, private_key, max_fee, deadline
- **Returns**: BridgeTransaction (Pydantic model with transaction details)

### monitor_bridge_events
Monitor bridge contract events.
- **Parameters**: bridge_contract, event_types, from_block, duration
- **Returns**: List[BridgeEvent] (Pydantic model with event details)

### get_bridge_status
Get bridge status.
- **Parameters**: bridge_contract, include_liquidity
- **Returns**: Dict[str, BridgeStatus] (Pydantic model with status details)

### get_transaction_history
Get transaction history.
- **Parameters**: address, source_chain, destination_chain, status, limit, offset
- **Returns**: List[BridgeTransaction]

### validate_bridge_transaction
Validate a transaction.
- **Parameters**: source_chain, destination_chain, asset, amount, sender, recipient
- **Returns**: Dict with validation results

### get_supported_assets
Get supported assets.
- **Parameters**: source_chain, destination_chain
- **Returns**: Dict with asset details

### cancel_bridge_transaction
Cancel a pending transaction.
- **Parameters**: transaction_id, private_key
- **Returns**: Dict with cancellation status

### get_bridge_analytics
Get bridge analytics.
- **Parameters**: time_range, bridge_contract, metric_type
- **Returns**: Dict with analytics data

### optimize_bridge_route
Optimize bridge route.
- **Parameters**: source_chain, destination_chain, asset, amount, optimization_goal
- **Returns**: Dict with route details

## Security
- OAuth 2.1 authentication with required scopes: bridge:read, bridge:write
- HMAC signature verification
- Balance and congestion checks
- Persistent storage with SQLite

## Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Set environment variables in `.env`:
   - INFURA_PROJECT_ID
   - ETHERSCAN_API_KEY
   - HMAC_SECRET
   - AUTH_ISSUER_URL
   - AUTH_SERVER_URL
3. Run the server: `mcp run cross_chain_bridge_assistant.py`
"""

if __name__ == "__main__":
    server = CrossChainBridgeServer()
    server.mcp.run(transport="streamable-http")