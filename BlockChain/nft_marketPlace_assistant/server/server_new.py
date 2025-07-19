"""
NFT Marketplace Assistant MCP Server

An MCP server for interacting with NFT marketplaces like OpenSea and Rarible.
Provides tools for NFT metadata retrieval, bidding, minting, listing, and market analysis.
"""

import asyncio
import json
import logging
import os
import sqlite3
import time
import hmac
import hashlib
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Union, Any, AsyncIterator
from dataclasses import dataclass

import aiohttp
import requests
from web3 import Web3
from eth_utils import to_checksum_address, is_address
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent, ImageContent, EmbeddedResource
from dotenv import load_dotenv
from cachetools import TTLCache

# Load environment variables
load_dotenv()
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID", "7464fe4568974a00b5cf20e94ebc4833")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "3NK7D3FBF2AQ23RBEDPX9BVZH4DD4E3DHZ")
ALCHEMY_API_KEY = os.getenv("ALCHEMY_API_KEY", "your_alchemy_api_key")
HMAC_SECRET = os.getenv("HMAC_SECRET", "your-secret-key")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Supported blockchain networks
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

# Marketplace contract addresses and ABIs
MARKETPLACE_CONTRACTS = {
    "opensea": {
        "ethereum": "0x7f268357A8c2552623316e2562D90e642bB538E5",
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
                    {"indexed": True, "name": "hash", "type": "bytes32"},
                    {"indexed": True, "name": "exchange", "type": "address"},
                    {"indexed": True, "name": "maker", "type": "address"},
                    {"indexed": False, "name": "taker", "type": "address"},
                    {"indexed": False, "name": "makerRelayerFee", "type": "uint256"},
                    {"indexed": False, "name": "takerRelayerFee", "type": "uint256"},
                    {"indexed": False, "name": "makerProtocolFee", "type": "uint256"},
                    {"indexed": False, "name": "takerProtocolFee", "type": "uint256"},
                    {"indexed": False, "name": "feeRecipient", "type": "address"},
                    {"indexed": False, "name": "feeMethod", "type": "uint8"},
                    {"indexed": False, "name": "side", "type": "uint8"},
                    {"indexed": False, "name": "saleKind", "type": "uint8"},
                    {"indexed": False, "name": "target", "type": "address"}
                ],
                "name": "OrderApprovedPartOne",
                "type": "event"
            }
        ]
    },
    "rarible": {
        "ethereum": "0x9757F2d2b135150BBeb65308D4a91804107cd8D6",
        "abi": [
            {
                "inputs": [
                    {"internalType": "contract IERC20Upgradeable", "name": "_token", "type": "address"}
                ],
                "name": "deposit",
                "outputs": [],
                "stateMutability": "payable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "contract IERC20Upgradeable", "name": "_token", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"}
                ],
                "name": "withdraw",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "internalType": "bytes32", "name": "orderHash", "type": "bytes32"},
                    {"indexed": True, "internalType": "address", "name": "maker", "type": "address"},
                    {"indexed": False, "internalType": "address", "name": "taker", "type": "address"},
                    {"indexed": False, "internalType": "uint256", "name": "makerValue", "type": "uint256"},
                    {"indexed": False, "internalType": "uint256", "name": "takerValue", "type": "uint256"}
                ],
                "name": "Match",
                "type": "event"
            }
        ]
    }
}

# Pydantic models for data validation
class NFTMetadata(BaseModel):
    name: str
    description: str
    image: str
    attributes: List[Dict[str, Any]] = []
    external_url: Optional[str] = None

class BidTransaction(BaseModel):
    transaction_id: str
    collection: str
    token_id: str
    amount: str
    bidder: str
    marketplace: str
    chain: str
    status: str = "pending"
    timestamp: float = Field(default_factory=time.time)

class MintTransaction(BaseModel):
    transaction_id: str
    contract_address: str
    metadata: Dict[str, Any]
    minter: str
    chain: str
    status: str = "pending"
    timestamp: float = Field(default_factory=time.time)

class SaleListing(BaseModel):
    listing_id: str
    contract_address: str
    token_id: str
    price: str
    seller: str
    marketplace: str
    chain: str
    status: str = "active"
    timestamp: float = Field(default_factory=time.time)

class MarketplaceTrends(BaseModel):
    collection: str
    chain: str
    floor_price: Optional[str] = None
    volume_24h: Optional[str] = None
    sales_count_24h: Optional[int] = None
    average_price_24h: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)

# Initialize FastMCP server
mcp = FastMCP(
    name="NFTMarketplace",
    dependencies=["web3", "aiohttp", "python-dotenv", "cachetools", "pydantic"]
)

# Global variables for server state
transactions: Dict[str, Union[BidTransaction, MintTransaction, SaleListing]] = {}
web3_connections: Dict[str, Web3] = {}
db_connection: Optional[sqlite3.Connection] = None
abi_cache = TTLCache(maxsize=100, ttl=3600)  # Cache ABIs for 1 hour
gas_price_cache = TTLCache(maxsize=10, ttl=300)  # Cache gas prices for 5 minutes

def _initialize_db() -> sqlite3.Connection:
    """Initialize SQLite database with proper schema and error handling"""
    try:
        db_path = os.path.join(os.path.dirname(__file__), "nft_marketplace.db")
        conn = sqlite3.connect(db_path, check_same_thread=False)
        
        # Create tables for transactions and listings
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                data TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS listings (
                id TEXT PRIMARY KEY,
                contract_address TEXT NOT NULL,
                token_id TEXT NOT NULL,
                price TEXT NOT NULL,
                seller TEXT NOT NULL,
                marketplace TEXT NOT NULL,
                chain TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        logger.info("Database initialized successfully")
        return conn
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

async def _get_web3_connection(chain: str) -> Web3:
    """Get Web3 connection for specified chain"""
    if chain not in web3_connections:
        if chain not in SUPPORTED_CHAINS:
            raise ValueError(f"Unsupported chain: {chain}")
        
        chain_config = SUPPORTED_CHAINS[chain]
        w3 = Web3(Web3.HTTPProvider(chain_config["rpc_url"]))
        
        if not w3.is_connected():
            raise ConnectionError(f"Failed to connect to {chain} network")
        
        web3_connections[chain] = w3
        logger.info(f"Connected to {chain} network")
    
    return web3_connections[chain]

@mcp.tool()
async def get_nft_metadata(contract_address: str, token_id: str, chain: str = "ethereum") -> List[TextContent]:
    """Retrieve metadata for an NFT"""
    try:
        if not is_address(contract_address):
            return [TextContent(type="text", text=f"Invalid contract address: {contract_address}")]
        
        w3 = await _get_web3_connection(chain)
        contract_address = to_checksum_address(contract_address)
        
        # Standard ERC-721 ABI for tokenURI function
        erc721_abi = [
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "tokenURI",
                "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        contract = w3.eth.contract(address=contract_address, abi=erc721_abi)
        token_uri = contract.functions.tokenURI(int(token_id)).call()
        
        # Fetch metadata from URI
        if token_uri.startswith("ipfs://"):
            token_uri = token_uri.replace("ipfs://", "https://ipfs.io/ipfs/")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(token_uri) as response:
                if response.status == 200:
                    metadata = await response.json()
                    
                    # Validate and format metadata
                    nft_metadata = NFTMetadata(**metadata)
                    
                    result = f"""NFT Metadata for {contract_address}#{token_id}:
Name: {nft_metadata.name}
Description: {nft_metadata.description}
Image: {nft_metadata.image}
Attributes: {json.dumps(nft_metadata.attributes, indent=2)}
External URL: {nft_metadata.external_url or 'N/A'}
Chain: {chain}"""
                    
                    return [TextContent(type="text", text=result)]
                else:
                    return [TextContent(type="text", text=f"Failed to fetch metadata from {token_uri}")]
    
    except Exception as e:
        logger.error(f"Error retrieving NFT metadata: {e}")
        return [TextContent(type="text", text=f"Error retrieving NFT metadata: {str(e)}")]

@mcp.tool()
async def place_bid(collection: str, token_id: str, amount: str, bidder: str, marketplace: str = "opensea", chain: str = "ethereum") -> List[TextContent]:
    """Place a bid on an NFT auction"""
    try:
        if not is_address(collection) or not is_address(bidder):
            return [TextContent(type="text", text="Invalid address provided")]
        
        # Generate transaction ID
        tx_id = f"bid_{int(time.time())}_{collection}_{token_id}"
        
        # Create bid transaction record
        bid_tx = BidTransaction(
            transaction_id=tx_id,
            collection=collection,
            token_id=token_id,
            amount=amount,
            bidder=bidder,
            marketplace=marketplace,
            chain=chain
        )
        
        # Store in global transactions dict
        transactions[tx_id] = bid_tx
        
        # Store in database
        if db_connection:
            db_connection.execute(
                "INSERT INTO transactions (id, type, data, status) VALUES (?, ?, ?, ?)",
                (tx_id, "bid", bid_tx.model_dump_json(), "pending")
            )
            db_connection.commit()
        
        result = f"""Bid placed successfully!
Transaction ID: {tx_id}
Collection: {collection}
Token ID: {token_id}
Bid Amount: {amount} {SUPPORTED_CHAINS[chain]['native_token']}
Bidder: {bidder}
Marketplace: {marketplace}
Chain: {chain}
Status: Pending

Note: This is a simulated bid. In a real implementation, this would interact with the marketplace smart contract."""
        
        return [TextContent(type="text", text=result)]
    
    except Exception as e:
        logger.error(f"Error placing bid: {e}")
        return [TextContent(type="text", text=f"Error placing bid: {str(e)}")]

@mcp.tool()
async def mint_nft(contract_address: str, metadata: dict, minter: str, chain: str = "ethereum") -> List[TextContent]:
    """Mint a new NFT"""
    try:
        if not is_address(contract_address) or not is_address(minter):
            return [TextContent(type="text", text="Invalid address provided")]
        
        # Generate transaction ID
        tx_id = f"mint_{int(time.time())}_{contract_address}"
        
        # Create mint transaction record
        mint_tx = MintTransaction(
            transaction_id=tx_id,
            contract_address=contract_address,
            metadata=metadata,
            minter=minter,
            chain=chain
        )
        
        # Store in global transactions dict
        transactions[tx_id] = mint_tx
        
        # Store in database
        if db_connection:
            db_connection.execute(
                "INSERT INTO transactions (id, type, data, status) VALUES (?, ?, ?, ?)",
                (tx_id, "mint", mint_tx.model_dump_json(), "pending")
            )
            db_connection.commit()
        
        result = f"""NFT minting initiated!
Transaction ID: {tx_id}
Contract: {contract_address}
Minter: {minter}
Chain: {chain}
Metadata: {json.dumps(metadata, indent=2)}
Status: Pending

Note: This is a simulated mint. In a real implementation, this would interact with the NFT contract."""
        
        return [TextContent(type="text", text=result)]
    
    except Exception as e:
        logger.error(f"Error minting NFT: {e}")
        return [TextContent(type="text", text=f"Error minting NFT: {str(e)}")]

@mcp.tool()
async def list_nft_for_sale(contract_address: str, token_id: str, price: str, seller: str, marketplace: str = "opensea", chain: str = "ethereum") -> List[TextContent]:
    """List an NFT for sale"""
    try:
        if not is_address(contract_address) or not is_address(seller):
            return [TextContent(type="text", text="Invalid address provided")]
        
        # Generate listing ID
        listing_id = f"listing_{int(time.time())}_{contract_address}_{token_id}"
        
        # Create sale listing record
        sale_listing = SaleListing(
            listing_id=listing_id,
            contract_address=contract_address,
            token_id=token_id,
            price=price,
            seller=seller,
            marketplace=marketplace,
            chain=chain
        )
        
        # Store in global transactions dict
        transactions[listing_id] = sale_listing
        
        # Store in database
        if db_connection:
            db_connection.execute(
                "INSERT INTO listings (id, contract_address, token_id, price, seller, marketplace, chain, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (listing_id, contract_address, token_id, price, seller, marketplace, chain, "active")
            )
            db_connection.commit()
        
        result = f"""NFT listed for sale!
Listing ID: {listing_id}
Contract: {contract_address}
Token ID: {token_id}
Price: {price} {SUPPORTED_CHAINS[chain]['native_token']}
Seller: {seller}
Marketplace: {marketplace}
Chain: {chain}
Status: Active

Note: This is a simulated listing. In a real implementation, this would interact with the marketplace contract."""
        
        return [TextContent(type="text", text=result)]
    
    except Exception as e:
        logger.error(f"Error listing NFT: {e}")
        return [TextContent(type="text", text=f"Error listing NFT: {str(e)}")]

@mcp.tool()
async def get_marketplace_trends(collection: str, chain: str = "ethereum") -> List[TextContent]:
    """Analyze NFT marketplace trends"""
    try:
        if not is_address(collection):
            return [TextContent(type="text", text=f"Invalid collection address: {collection}")]
        
        # Simulate marketplace trends data
        # In a real implementation, this would fetch from OpenSea API, Rarible API, etc.
        trends = MarketplaceTrends(
            collection=collection,
            chain=chain,
            floor_price="0.5",
            volume_24h="125.7",
            sales_count_24h=42,
            average_price_24h="2.99"
        )
        
        result = f"""Marketplace Trends for {collection}:
Chain: {chain}
Floor Price: {trends.floor_price} {SUPPORTED_CHAINS[chain]['native_token']}
24h Volume: {trends.volume_24h} {SUPPORTED_CHAINS[chain]['native_token']}
24h Sales: {trends.sales_count_24h}
24h Average Price: {trends.average_price_24h} {SUPPORTED_CHAINS[chain]['native_token']}
Last Updated: {time.ctime(trends.timestamp)}

Note: This is simulated data. In a real implementation, this would fetch live data from marketplace APIs."""
        
        return [TextContent(type="text", text=result)]
    
    except Exception as e:
        logger.error(f"Error getting marketplace trends: {e}")
        return [TextContent(type="text", text=f"Error getting marketplace trends: {str(e)}")]

@mcp.tool()
async def monitor_nft_transaction(tx_id: str, chain: str = "ethereum") -> List[TextContent]:
    """Monitor an NFT transaction status"""
    try:
        # Check if transaction exists in our records
        if tx_id in transactions:
            tx = transactions[tx_id]
            
            if isinstance(tx, BidTransaction):
                result = f"""Bid Transaction Status:
Transaction ID: {tx.transaction_id}
Collection: {tx.collection}
Token ID: {tx.token_id}
Amount: {tx.amount} {SUPPORTED_CHAINS[tx.chain]['native_token']}
Bidder: {tx.bidder}
Marketplace: {tx.marketplace}
Chain: {tx.chain}
Status: {tx.status}
Created: {time.ctime(tx.timestamp)}"""
            
            elif isinstance(tx, MintTransaction):
                result = f"""Mint Transaction Status:
Transaction ID: {tx.transaction_id}
Contract: {tx.contract_address}
Minter: {tx.minter}
Chain: {tx.chain}
Status: {tx.status}
Created: {time.ctime(tx.timestamp)}
Metadata: {json.dumps(tx.metadata, indent=2)}"""
            
            elif isinstance(tx, SaleListing):
                result = f"""Sale Listing Status:
Listing ID: {tx.listing_id}
Contract: {tx.contract_address}
Token ID: {tx.token_id}
Price: {tx.price} {SUPPORTED_CHAINS[tx.chain]['native_token']}
Seller: {tx.seller}
Marketplace: {tx.marketplace}
Chain: {tx.chain}
Status: {tx.status}
Created: {time.ctime(tx.timestamp)}"""
            
            else:
                result = f"Unknown transaction type for ID: {tx_id}"
        
        else:
            # Try to look up transaction on blockchain
            w3 = await _get_web3_connection(chain)
            try:
                tx_receipt = w3.eth.get_transaction_receipt(tx_id)
                result = f"""Blockchain Transaction Status:
Transaction Hash: {tx_id}
Block Number: {tx_receipt.blockNumber}
Gas Used: {tx_receipt.gasUsed}
Status: {'Success' if tx_receipt.status == 1 else 'Failed'}
Chain: {chain}"""
            except Exception:
                result = f"Transaction {tx_id} not found in our records or on the blockchain"
        
        return [TextContent(type="text", text=result)]
    
    except Exception as e:
        logger.error(f"Error monitoring transaction: {e}")
        return [TextContent(type="text", text=f"Error monitoring transaction: {str(e)}")]

# Initialize database on module load
try:
    db_connection = _initialize_db()
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")
    db_connection = None

# Export the server instance
app = mcp
server = mcp
