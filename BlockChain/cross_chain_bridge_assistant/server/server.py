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
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound
from eth_account import Account
from eth_utils import to_checksum_address, is_address
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from mcp.types import Completion, CompletionArgument, CompletionContext, Resource, ResourceTemplateReference
from mcp.server.auth.provider import TokenVerifier, TokenInfo
from mcp.server.auth.settings import AuthSettings
import sqlite3
from cachetools import TTLCache

load_dotenv()
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID", "YOUR_PROJECT_ID")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "YOUR_ETHERSCAN_API_KEY")
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
    
     