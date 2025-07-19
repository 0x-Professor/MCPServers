"""
NFT Marketplace Assistant MCP Server

An MCP server for interacting with NFT marketplaces (e.g., OpenSea, Rarible), providing tools to retrieve NFT metadata,
place bids, mint NFTs, list assets for sale, analyze market trends, and monitor transactions.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union, AsyncIterator
from contextlib import asynccontextmanager
#from collections.abc import AsyncIterator
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

# Load environment variables
load_dotenv()
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID", "your_infura_project_id")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "your_etherscan_api_key")
ALCHEMY_API_KEY = os.getenv("ALCHEMY_API_KEY", "your_alchemy_api_key")
HMAC_SECRET = os.getenv("HMAC_SECRET", "your-secret-key")
AUTH_ISSUER_URL = os.getenv("AUTH_ISSUER_URL", "https://auth.example.com")
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:3001")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# Supported chains
SUPPORTED_CHAINS = {
    "ethereum": {
        "chain_id": 1,
        "name": "Ethereum Mainnet",
        "rpc_url": f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}",
        "explorer": "https://api.etherscan.io/api",
        "native_token": "ETH",
        "decimals": 18
    },
    "polygon": {
        "chain_id": 137,
        "name": "Polygon",
        "rpc_url": f"https://polygon-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}",
        "explorer": "https://api.polygonscan.com/api",
        "native_token": "MATIC",
        "decimals": 18
    }
}

# Marketplace contract addresses 
MARKETPLACE_CONTRACTS = {
    "opensea": {
        "ethereum": "0x7f268357A8c2552623316e2562D90e642bB538E5",  # OpenSea Wyvern Exchange V2
        "abi": [
            {
                "inputs": [],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "constructor"
            },
            {
                "anonymous": False,
                "inputs": [
                    {
                        "indexed": True,
                        "name": "hash",
                        "type": "bytes32"
                    },
                    {
                        "indexed": True,
                        "name": "exchange",
                        "type": "address"
                    },
                    {
                        "indexed": True,
                        "name": "maker",
                        "type": "address"
                    },
                    {
                        "indexed": False,
                        "name": "taker",
                        "type": "address"
                    },
                    {
                        "indexed": False,
                        "name": "makerRelayerFee",
                        "type": "uint256"
                    },
                    {
                        "indexed": False,
                        "name": "takerRelayerFee",
                        "type": "uint256"
                    },
                    {
                        "indexed": False,
                        "name": "makerProtocolFee",
                        "type": "uint256"
                    },
                    {
                        "indexed": False,
                        "name": "takerProtocolFee",
                        "type": "uint256"
                    },
                    {
                        "indexed": False,
                        "name": "feeRecipient",
                        "type": "address"
                    },
                    {
                        "indexed": False,
                        "name": "feeMethod",
                        "type": "uint8"
                    },
                    {
                        "indexed": False,
                        "name": "side",
                        "type": "uint8"
                    },
                    {
                        "indexed": False,
                        "name": "saleKind",
                        "type": "uint8"
                    },
                    {
                        "indexed": False,
                        "name": "target",
                        "type": "address"
                    }
                ],
                "name": "OrderApprovedPartOne",
                "type": "event"
            }
        ]
    },
    "rarible": {
        "ethereum": "0x9757F2d2b135150BBeb65308D4a91804107cd8D6",  # Rarible Exchange V2
        "abi": [
            {
                "inputs": [
                    {
                        "internalType": "contract IERC20Upgradeable",
                        "name": "_token",
                        "type": "address"
                    }
                ],
                "name": "deposit",
                "outputs": [],
                "stateMutability": "payable",
                "type": "function"
            },
            {
                "inputs": [
                    {
                        "internalType": "contract IERC20Upgradeable",
                        "name": "_token",
                        "type": "address"
                    },
                    {
                        "internalType": "uint256",
                        "name": "amount",
                        "type": "uint256"
                    }
                ],
                "name": "withdraw",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {
                        "indexed": True,
                        "internalType": "bytes32",
                        "name": "orderHash",
                        "type": "bytes32"
                    },
                    {
                        "indexed": True,
                        "internalType": "address",
                        "name": "maker",
                        "type": "address"
                    },
                    {
                        "indexed": False,
                        "internalType": "address",
                        "name": "taker",
                        "type": "address"
                    },
                    {
                        "indexed": False,
                        "internalType": "uint256",
                        "name": "makerValue",
                        "type": "uint256"
                    },
                    {
                        "indexed": False,
                        "internalType": "uint256",
                        "name": "takerValue",
                        "type": "uint256"
                    }
                ],
                "name": "Match",
                "type": "event"
            }
        ]
    }
}

# Enums
class TransactionStatus(Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# Pydantic Models
class NFTMetadata(BaseModel):
    contract_address: str = Field(description="NFT contract address")
    token_id: str = Field(description="NFT token ID")
    name: Optional[str] = Field(default=None, description="NFT name")
    description: Optional[str] = Field(default=None, description="NFT description")
    image_url: Optional[str] = Field(default=None, description="NFT image URL")
    attributes: Optional[List[Dict[str, Any]]] = Field(default=None, description="NFT attributes")
    chain: str = Field(description="Blockchain network")

class BidTransaction(BaseModel):
    id: str = Field(description="Unique transaction ID")
    collection: str = Field(description="NFT collection address")
    token_id: Optional[str] = Field(default=None, description="NFT token ID")
    amount: str = Field(description="Bid amount in native token")
    bidder: str = Field(description="Bidder address")
    status: str = Field(description="Transaction status")
    tx_hash: Optional[str] = Field(default=None, description="Transaction hash")
    created_at: str = Field(description="Transaction creation time")
    marketplace: str = Field(description="Marketplace name")

class MintTransaction(BaseModel):
    id: str = Field(description="Unique transaction ID")
    contract_address: str = Field(description="NFT contract address")
    token_id: Optional[str] = Field(default=None, description="Minted token ID")
    minter: str = Field(description="Minter address")
    metadata: Dict[str, Any] = Field(description="NFT metadata")
    status: str = Field(description="Transaction status")
    tx_hash: Optional[str] = Field(default=None, description="Transaction hash")
    created_at: str = Field(description="Transaction creation time")

class SaleListing(BaseModel):
    id: str = Field(description="Unique listing ID")
    contract_address: str = Field(description="NFT contract address")
    token_id: str = Field(description="NFT token ID")
    price: str = Field(description="Sale price in native token")
    seller: str = Field(description="Seller address")
    status: str = Field(description="Listing status")
    created_at: str = Field(description="Listing creation time")
    marketplace: str = Field(description="Marketplace name")

class MarketTrend(BaseModel):
    collection: str = Field(description="NFT collection address")
    floor_price: Optional[str] = Field(default=None, description="Floor price in native token")
    volume_24h: Optional[str] = Field(default=None, description="24-hour trading volume")
    sales_24h: Optional[int] = Field(default=None, description="Number of sales in 24 hours")
    chain: str = Field(description="Blockchain network")

class TokenInfo(BaseModel):
    sub: str = Field(description="Subject identifier of the token")
    scopes: List[str] = Field(description="List of scopes granted by the token")
    expires_at: datetime = Field(description="Token expiration timestamp")

# Authentication
class SimpleTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> TokenInfo:
        """Verify OAuth 2.1 token"""
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
                    raise ValueError("Invalid or inactive token")
            except Exception as e:
                logger.error(f"Token verification failed: {str(e)}")
                raise ValueError(f"Token verification failed: {str(e)}")

# Server Context
@dataclass
class AppContext:
    web3_connections: Dict[str, Web3]
    db_connection: sqlite3.Connection
    abi_cache: TTLCache
    gas_price_cache: TTLCache

class NFTMarketplaceServer:
    """MCP server for NFT marketplace operations"""

    def __init__(self):
        self.mcp = FastMCP(
            name="NFTMarketplace",
            stateless_http=True,
            dependencies=["web3", "aiohttp", "python-dotenv", "cachetools", "pydantic"],
            auth=AuthSettings(
                issuer_url=AUTH_ISSUER_URL,
                resource_server_url=AUTH_SERVER_URL,
                required_scopes=["nft:read", "nft:write"],
            ),
            token_verifier=SimpleTokenVerifier(),
            lifespan=self._app_lifespan
        )
        self.transactions: Dict[str, Union[BidTransaction, MintTransaction, SaleListing]] = {}
        self._setup_handlers()

    def _initialize_db(self) -> sqlite3.Connection:
        """Initialize SQLite database with proper schema and error handling"""
        try:
            db_path = os.path.join(os.path.dirname(__file__), "nft_marketplace.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Enable foreign key support
            cursor.execute("PRAGMA foreign_keys = ON;")
        
            # Create transactions table with proper schema
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                contract_address TEXT NOT NULL,
                token_id TEXT,
                amount TEXT,
                bidder TEXT,
                minter TEXT,
                collection TEXT,
                metadata TEXT,
                status TEXT NOT NULL,
                tx_hash TEXT UNIQUE,
                created_at TEXT NOT NULL,
                marketplace TEXT,
                chain TEXT,
                error_message TEXT,
                updated_at TEXT NOT NULL
            )
            """)
        
        # Create listings table with proper schema
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS listings (
                id TEXT PRIMARY KEY,
                contract_address TEXT NOT NULL,
                token_id TEXT NOT NULL,
                collection TEXT,
                price TEXT NOT NULL,
                seller TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                marketplace TEXT NOT NULL,
                chain TEXT NOT NULL,
                raw_data TEXT,
                FOREIGN KEY (contract_address, token_id) 
                REFERENCES nfts(contract_address, token_id) ON DELETE CASCADE
            )
            """)
        
        # Create indexes for better query performance
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_contract_token 
            ON transactions(contract_address, token_id)
            """)
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_listings_contract_token 
            ON listings(contract_address, token_id)
            """)
        
            conn.commit()
            return conn
        
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
            raise

    @asynccontextmanager
    async def _app_lifespan(self, server: FastMCP) -> AsyncIterator[AppContext]:
        """Manage server lifecycle"""
        web3_connections = {}
        db_connection = self._initialize_db()
        abi_cache = TTLCache(maxsize=100, ttl=3600)
        gas_price_cache = TTLCache(maxsize=50, ttl=300)
        try:
            for chain_name, chain_config in SUPPORTED_CHAINS.items():
                max_retries = 5
                for attempt in range(max_retries):
                    try:
                        logger.info(f"Attempting to connect to {chain_name} at {chain_config['rpc_url']}")
                        w3 = Web3(Web3.HTTPProvider(chain_config["rpc_url"]))
                        if w3.is_connected():
                            web3_connections[chain_name] = w3
                            logger.info(f"Connected to {chain_name} network on attempt {attempt + 1}")
                            break
                        else:
                            logger.warning(f"Failed to connect to {chain_name} network on attempt {attempt + 1}")
                            if attempt < max_retries - 1:
                                await asyncio.sleep(5)
                    except Exception as e:
                        logger.error(f"Error connecting to {chain_name} on attempt {attempt + 1}: {e}")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(5)
                else:
                    logger.error(f"Failed to connect to {chain_name} after {max_retries} attempts")

            yield AppContext(
                web3_connections=web3_connections,
                db_connection=db_connection,
                abi_cache=abi_cache,
                gas_price_cache=gas_price_cache
            )
        finally:
            db_connection.close()
            logger.info("Server shutdown: Closed database connection")

    def _setup_handlers(self):
        """Setup MCP handlers for NFT operations"""
        self.mcp.register_tool(
            "get_nft_metadata",
            self.get_nft_metadata,
            description="Retrieve metadata for an NFT",
            arguments=[
                CompletionArgument(name="contract_address", type="string", description="NFT contract address"),
                CompletionArgument(name="token_id", type="string", description="NFT token ID"),
                CompletionArgument(name="chain", type="string", description="Blockchain network (default: ethereum)", default="ethereum")
            ]
        )
        self.mcp.register_tool(
            "place_bid",
            self.place_bid,
            description="Place a bid on an NFT auction",
            arguments=[
                CompletionArgument(name="collection", type="string", description="NFT collection contract address"),
                CompletionArgument(name="token_id", type="string", description="NFT token ID"),
                CompletionArgument(name="amount", type="string", description="Bid amount in native token"),
                CompletionArgument(name="bidder", type="string", description="Bidder address"),
                CompletionArgument(name="marketplace", type="string", description="Marketplace name (e.g., opensea, rarible)", default="opensea"),
                CompletionArgument(name="chain", type="string", description="Blockchain network (default: ethereum)", default="ethereum")
            ]
        )
        self.mcp.register_tool(
            "mint_nft",
            self.mint_nft,
            description="Mint a new NFT",
            arguments=[
                CompletionArgument(name="contract_address", type="string", description="NFT contract address"),
                CompletionArgument(name="metadata", type="dict", description="NFT metadata (e.g., name, description, image_url)"),
                CompletionArgument(name="minter", type="string", description="Minter address"),
                CompletionArgument(name="chain", type="string", description="Blockchain network (default: ethereum)", default="ethereum")
            ]
        )    
        self.mcp.register_tool(
            "list_nft_for_sale",
            self.list_nft_for_sale,
            description="List an NFT for sale",
            arguments=[
                CompletionArgument(name="contract_address", type="string", description="NFT contract address"),
                CompletionArgument(name="token_id", type="string", description="NFT token ID"),
                CompletionArgument(name="price", type="string", description="Sale price in native token"),
                CompletionArgument(name="seller", type="string", description="Seller address"),
                CompletionArgument(name="marketplace", type="string", description="Marketplace name (e.g., opensea, rarible)", default="opensea"),
                CompletionArgument(name="chain", type="string", description="Blockchain network (default: ethereum)", default="ethereum")
            ]
        )
        self.mcp.register_tool(
            "get_marketplace_trends",
            self.get_marketplace_trends,
            description="Analyze NFT marketplace trends",
            arguments=[
                CompletionArgument(name="collection", type="string", description="NFT collection contract address"),
                CompletionArgument(name="chain", type="string", description="Blockchain network (default: ethereum)", default="ethereum")
            ]
        )
        self.mcp.register_tool(
            "monitor_nft_transaction",
            self.monitor_nft_transaction,
            description="Monitor an NFT transaction status",
            arguments=[
                CompletionArgument(name="tx_id", type="string", description="Transaction ID"),
                CompletionArgument(name="chain", type="string", description="Blockchain network (default: ethereum)", default="ethereum")
            ]
        )
    
    async def get_nft_metadata(self, context: AppContext, arguments: Dict[str, Any]) -> Completion:
        """Retrieve metadata for an NFT"""
        contract_address = arguments.get("contract_address")
        token_id = arguments.get("token_id")
        chain = arguments.get("chain", "ethereum")

        if not is_address(contract_address):
            return Completion(result={"error": "Invalid contract address"}, status="error")
        if not token_id.isdigit():
            return Completion(result={"error": "Invalid token ID"}, status="error")
        if chain not in SUPPORTED_CHAINS:
            return Completion(result={"error": f"Chain {chain} not supported"}, status="error")

        try:
            w3 = context.web3_connections.get(chain)
            if not w3:
                return Completion(result={"error": f"Chain {chain} not connected"}, status="error")

            # Fetch ABI from cache or Etherscan
            abi = context.abi_cache.get(contract_address)
            if not abi:
                response = requests.get(
                    f"{SUPPORTED_CHAINS[chain]['explorer']}?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
                )
                abi = json.loads(response.json().get("result", "[]"))
                context.abi_cache[contract_address] = abi

            contract = w3.eth.contract(address=to_checksum_address(contract_address), abi=abi)
            token_uri = contract.functions.tokenURI(int(token_id)).call()
            
            # Fetch metadata from token URI
            async with aiohttp.ClientSession() as session:
                async with session.get(token_uri) as response:
                    metadata = await response.json()
                    return Completion(
                        result=NFTMetadata(
                            contract_address=contract_address,
                            token_id=token_id,
                            name=metadata.get("name"),
                            description=metadata.get("description"),
                            image_url=metadata.get("image"),
                            attributes=metadata.get("attributes"),
                            chain=chain
                        ).dict(),
                        status="success"
                    )
        except Exception as e:
            logger.error(f"Error fetching NFT metadata: {e}")
            return Completion(result={"error": str(e)}, status="error")

    async def place_bid(self, context: AppContext, arguments: Dict[str, Any]) -> Completion:
        """Place a bid on an NFT auction"""
        collection = arguments.get("collection")
        token_id = arguments.get("token_id")
        amount = arguments.get("amount")
        bidder = arguments.get("bidder")
        marketplace = arguments.get("marketplace", "opensea")
        chain = arguments.get("chain", "ethereum")

        if not is_address(collection) or not is_address(bidder):
            return Completion(result={"error": "Invalid address"}, status="error")
        if not token_id.isdigit():
            return Completion(result={"error": "Invalid token ID"}, status="error")
        try:
            amount = Decimal(amount)
            if amount <= 0:
                raise ValueError("Bid amount must be positive")
        except (ValueError, TypeError):
            return Completion(result={"error": "Invalid bid amount"}, status="error")
        if chain not in SUPPORTED_CHAINS:
            return Completion(result={"error": f"Chain {chain} not supported"}, status="error")
        if marketplace not in MARKETPLACE_CONTRACTS:
            return Completion(result={"error": f"Marketplace {marketplace} not supported"}, status="error")

        try:
            w3 = context.web3_connections.get(chain)
            if not w3:
                return Completion(result={"error": f"Chain {chain} not connected"}, status="error")

            tx_id = hashlib.sha256(f"{collection}{token_id}{bidder}{time.time()}".encode()).hexdigest()
            # Simulate bid placement (actual implementation requires marketplace-specific contract calls)
            # Example: OpenSea Wyvern Exchange requires creating an order
            cursor = context.db_connection.cursor()
            cursor.execute(
                "INSERT INTO transactions (id, type, contract_address, token_id, amount, bidder, status, created_at, marketplace) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (tx_id, "bid", collection, token_id, str(amount), bidder, TransactionStatus.PENDING.value, datetime.now().isoformat(), marketplace)
            )
            context.db_connection.commit()

            return Completion(
                result=BidTransaction(
                    id=tx_id,
                    collection=collection,
                    token_id=token_id,
                    amount=str(amount),
                    bidder=bidder,
                    status=TransactionStatus.PENDING.value,
                    created_at=datetime.now().isoformat(),
                    marketplace=marketplace
                ).dict(),
                status="success"
            )
        except Exception as e:
            logger.error(f"Error placing bid: {e}")
            return Completion(result={"error": str(e)}, status="error")

    async def mint_nft(self, context: AppContext, arguments: Dict[str, Any]) -> Completion:
        """Mint a new NFT"""
        contract_address = arguments.get("contract_address")
        metadata = arguments.get("metadata")
        minter = arguments.get("minter")
        chain = arguments.get("chain", "ethereum")

        if not is_address(contract_address) or not is_address(minter):
            return Completion(result={"error": "Invalid address"}, status="error")
        if not isinstance(metadata, dict):
            return Completion(result={"error": "Invalid metadata"}, status="error")
        if chain not in SUPPORTED_CHAINS:
            return Completion(result={"error": f"Chain {chain} not supported"}, status="error")

        try:
            w3 = context.web3_connections.get(chain)
            if not w3:
                return Completion(result={"error": f"Chain {chain} not connected"}, status="error")

            tx_id = hashlib.sha256(f"{contract_address}{minter}{time.time()}".encode()).hexdigest()
            # Simulate minting (actual implementation requires contract-specific mint function)
            cursor = context.db_connection.cursor()
            cursor.execute(
                "INSERT INTO transactions (id, type, contract_address, minter, metadata, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tx_id, "mint", contract_address, minter, json.dumps(metadata), TransactionStatus.PENDING.value, datetime.now().isoformat())
            )
            context.db_connection.commit()

            return Completion(
                result=MintTransaction(
                    id=tx_id,
                    contract_address=contract_address,
                    minter=minter,
                    metadata=metadata,
                    status=TransactionStatus.PENDING.value,
                    created_at=datetime.now().isoformat()
                ).dict(),
                status="success"
            )
        except Exception as e:
            logger.error(f"Error minting NFT: {e}")
            return Completion(result={"error": str(e)}, status="error")

    async def list_nft_for_sale(self, context: AppContext, arguments: Dict[str, Any]) -> Completion:
        """List an NFT for sale"""
        contract_address = arguments.get("contract_address")
        token_id = arguments.get("token_id")
        price = arguments.get("price")
        seller = arguments.get("seller")
        marketplace = arguments.get("marketplace", "opensea")
        chain = arguments.get("chain", "ethereum")

        if not is_address(contract_address) or not is_address(seller):
            return Completion(result={"error": "Invalid address"}, status="error")
        if not token_id.isdigit():
            return Completion(result={"error": "Invalid token ID"}, status="error")
        try:
            price = Decimal(price)
            if price <= 0:
                raise ValueError("Price must be positive")
        except (ValueError, TypeError):
            return Completion(result={"error": "Invalid price"}, status="error")
        if chain not in SUPPORTED_CHAINS:
            return Completion(result={"error": f"Chain {chain} not supported"}, status="error")
        if marketplace not in MARKETPLACE_CONTRACTS:
            return Completion(result={"error": f"Marketplace {marketplace} not supported"}, status="error")

        try:
            w3 = context.web3_connections.get(chain)
            if not w3:
                return Completion(result={"error": f"Chain {chain} not connected"}, status="error")

            listing_id = hashlib.sha256(f"{contract_address}{token_id}{seller}{time.time()}".encode()).hexdigest()
            # Simulate listing (actual implementation requires marketplace-specific contract calls)
            cursor = context.db_connection.cursor()
            cursor.execute(
                "INSERT INTO listings (id, contract_address, token_id, price, seller, status, created_at, marketplace) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (listing_id, contract_address, token_id, str(price), seller, "active", datetime.now().isoformat(), marketplace)
            )
            context.db_connection.commit()

            return Completion(
                result=SaleListing(
                    id=listing_id,
                    contract_address=contract_address,
                    token_id=token_id,
                    price=str(price),
                    seller=seller,
                    status="active",
                    created_at=datetime.now().isoformat(),
                    marketplace=marketplace
                ).dict(),
                status="success"
            )
        except Exception as e:
            logger.error(f"Error listing NFT for sale: {e}")
            return Completion(result={"error": str(e)}, status="error")

    async def get_marketplace_trends(self, context: AppContext, arguments: Dict[str, Any]) -> Completion:
        """Analyze NFT marketplace trends"""
        collection = arguments.get("collection")
        chain = arguments.get("chain", "ethereum")

        if not is_address(collection):
            return Completion(result={"error": "Invalid collection address"}, status="error")
        if chain not in SUPPORTED_CHAINS:
            return Completion(result={"error": f"Chain {chain} not supported"}, status="error")

        try:
            w3 = context.web3_connections.get(chain)
            if not w3:
                return Completion(result={"error": f"Chain {chain} not connected"}, status="error")

            # Simulate trend analysis (actual implementation requires marketplace API or contract event logs)
            # Example: Fetch floor price and volume via OpenSea/Alchemy API
            return Completion(
                result=MarketTrend(
                    collection=collection,
                    floor_price="0.1",  # Placeholder
                    volume_24h="10.5",  # Placeholder
                    sales_24h=50,       # Placeholder
                    chain=chain
                ).dict(),
                status="success"
            )
        except Exception as e:
            logger.error(f"Error fetching marketplace trends: {e}")
            return Completion(result={"error": str(e)}, status="error")

    async def monitor_nft_transaction(self, context: AppContext, arguments: Dict[str, Any]) -> Completion:
        """Monitor an NFT transaction status"""
        tx_id = arguments.get("tx_id")
        chain = arguments.get("chain", "ethereum")

        if not tx_id:
            return Completion(result={"error": "Invalid transaction ID"}, status="error")
        if chain not in SUPPORTED_CHAINS:
            return Completion(result={"error": f"Chain {chain} not supported"}, status="error")

        try:
            w3 = context.web3_connections.get(chain)
            if not w3:
                return Completion(result={"error": f"Chain {chain} not connected"}, status="error")

            cursor = context.db_connection.cursor()
            cursor.execute("SELECT * FROM transactions WHERE id = ?", (tx_id,))
            tx = cursor.fetchone()
            if not tx:
                return Completion(result={"error": "Transaction not found"}, status="error")

            # Simulate transaction status check
            status = TransactionStatus.PENDING.value  # Placeholder; check tx_hash status via w3.eth.get_transaction_receipt
            cursor.execute("UPDATE transactions SET status = ? WHERE id = ?", (status, tx_id))
            context.db_connection.commit()

            return Completion(
                result={"tx_id": tx_id, "status": status},
                status="success"
            )
        except Exception as e:
            logger.error(f"Error monitoring transaction: {e}")
            return Completion(result={"error": str(e)}, status="error")


# Initialize the server and expose it globally
server_instance = NFTMarketplaceServer().mcp
#mcp = server_instance
#app = mcp  # Alternative name for compatibility
#server = mcp  # Alternative name for compatibility
