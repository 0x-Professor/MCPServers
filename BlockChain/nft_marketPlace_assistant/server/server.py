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
from datetime import datetime

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
ALCHEMY_API_KEY = os.getenv("ALCHEMY_API_KEY", "vH5jh4T1PWnfVIxV7su69")
HMAC_SECRET = os.getenv("HMAC_SECRET", "wfnwvnw23452tdvwt454354fwefw4t3")
OPENSEA_API_KEY = os.getenv("OPENSEA_API_KEY", "your_opensea_api_key")

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
        "decimals": 18,
        "opensea_api": "https://api.opensea.io/api/v2"
    },
    "polygon": {
        "chain_id": 137,
        "name": "Polygon",
        "rpc_url": f"https://polygon-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}",
        "explorer": "https://api.polygonscan.com/api",
        "native_token": "MATIC",
        "decimals": 18,
        "opensea_api": "https://api.opensea.io/api/v2"
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

class CollectionStats(BaseModel):
    collection: str
    chain: str
    total_supply: Optional[int] = None
    num_owners: Optional[int] = None
    floor_price: Optional[str] = None
    total_volume: Optional[str] = None
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
        
        # Create tables for transactions, listings, metadata, and collection stats
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nfts (
                contract_address TEXT NOT NULL,
                token_id TEXT NOT NULL,
                name TEXT,
                description TEXT,
                image TEXT,
                attributes TEXT,
                external_url TEXT,
                chain TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (contract_address, token_id)
            )
        """)
        
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
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS collection_stats (
                collection TEXT PRIMARY KEY,
                chain TEXT NOT NULL,
                total_supply INTEGER,
                num_owners INTEGER,
                floor_price TEXT,
                total_volume TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_nfts_contract ON nfts(contract_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_listings_contract ON listings(contract_address)")
        
        conn.commit()
        logger.info("Database initialized successfully")
        return conn
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

async def _get_web3_connection(chain: str) -> Web3:
    """Get Web3 connection for specified chain with retry logic"""
    if chain not in web3_connections:
        if chain not in SUPPORTED_CHAINS:
            raise ValueError(f"Unsupported chain: {chain}")
        
        chain_config = SUPPORTED_CHAINS[chain]
        max_retries = 3
        for attempt in range(max_retries):
            try:
                w3 = Web3(Web3.HTTPProvider(chain_config["rpc_url"]))
                if w3.is_connected():
                    web3_connections[chain] = w3
                    logger.info(f"Connected to {chain} network on attempt {attempt + 1}")
                    break
                else:
                    logger.warning(f"Failed to connect to {chain} network on attempt {attempt + 1}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2)
            except Exception as e:
                logger.error(f"Error connecting to {chain} on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
        else:
            raise ConnectionError(f"Failed to connect to {chain} network after {max_retries} attempts")
    
    return web3_connections[chain]

@mcp.tool()
async def get_nft_metadata(contract_address: str, token_id: str, chain: str = "ethereum") -> List[TextContent]:
    """Retrieve metadata for an NFT"""
    try:
        if not is_address(contract_address):
            return [TextContent(type="text", text=f"Invalid contract address: {contract_address}")]
        if not token_id.isdigit():
            return [TextContent(type="text", text=f"Invalid token ID: {token_id}")]
        
        # Check database for cached metadata
        if db_connection:
            cursor = db_connection.cursor()
            cursor.execute(
                "SELECT name, description, image, attributes, external_url FROM nfts WHERE contract_address = ? AND token_id = ? AND chain = ?",
                (contract_address, token_id, chain)
            )
            result = cursor.fetchone()
            if result:
                name, description, image, attributes, external_url = result
                result_text = f"""NFT Metadata for {contract_address}#{token_id}:
Name: {name}
Description: {description}
Image: {image}
Attributes: {attributes}
External URL: {external_url or 'N/A'}
Chain: {chain}
Source: Database cache"""
                return [TextContent(type="text", text=result_text)]
        
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
        
        # Handle IPFS URIs
        if token_uri.startswith("ipfs://"):
            token_uri = token_uri.replace("ipfs://", "https://ipfs.io/ipfs/")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(token_uri) as response:
                if response.status == 200:
                    metadata = await response.json()
                    
                    # Validate and format metadata
                    nft_metadata = NFTMetadata(**metadata)
                    
                    # Store in database
                    if db_connection:
                        cursor = db_connection.cursor()
                        cursor.execute(
                            "INSERT OR REPLACE INTO nfts (contract_address, token_id, name, description, image, attributes, external_url, chain) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                contract_address,
                                token_id,
                                nft_metadata.name,
                                nft_metadata.description,
                                nft_metadata.image,
                                json.dumps(nft_metadata.attributes),
                                nft_metadata.external_url,
                                chain
                            )
                        )
                        db_connection.commit()
                    
                    result = f"""NFT Metadata for {contract_address}#{token_id}:
Name: {nft_metadata.name}
Description: {nft_metadata.description}
Image: {nft_metadata.image}
Attributes: {json.dumps(nft_metadata.attributes, indent=2)}
External URL: {nft_metadata.external_url or 'N/A'}
Chain: {chain}"""
                    
                    return [TextContent(type="text", text=result)]
                else:
                    return [TextContent(type="text", text=f"Failed to fetch metadata from {token_uri}: HTTP {response.status}")]
    
    except Exception as e:
        logger.error(f"Error retrieving NFT metadata: {e}")
        return [TextContent(type="text", text=f"Error retrieving NFT metadata: {str(e)}")]

@mcp.tool()
async def place_bid(collection: str, token_id: str, amount: str, bidder: str, marketplace: str = "opensea", chain: str = "ethereum") -> List[TextContent]:
    """Place a bid on an NFT auction"""
    try:
        if not is_address(collection) or not is_address(bidder):
            return [TextContent(type="text", text="Invalid address provided")]
        if not token_id.isdigit():
            return [TextContent(type="text", text=f"Invalid token ID: {token_id}")]
        try:
            float(amount)
            if float(amount) <= 0:
                raise ValueError("Amount must be positive")
        except ValueError:
            return [TextContent(type="text", text=f"Invalid bid amount: {amount}")]
        if chain not in SUPPORTED_CHAINS:
            return [TextContent(type="text", text=f"Unsupported chain: {chain}")]
        if marketplace not in MARKETPLACE_CONTRACTS:
            return [TextContent(type="text", text=f"Unsupported marketplace: {marketplace}")]
        
        # Generate transaction ID
        tx_id = f"bid_{hashlib.sha256(f'{collection}{token_id}{bidder}{time.time()}'.encode()).hexdigest()}"
        
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
        if not isinstance(metadata, dict):
            return [TextContent(type="text", text="Invalid metadata format")]
        if chain not in SUPPORTED_CHAINS:
            return [TextContent(type="text", text=f"Unsupported chain: {chain}")]
        
        # Generate transaction ID
        tx_id = f"mint_{hashlib.sha256(f'{contract_address}{minter}{time.time()}'.encode()).hexdigest()}"
        
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
        if not token_id.isdigit():
            return [TextContent(type="text", text=f"Invalid token ID: {token_id}")]
        try:
            float(price)
            if float(price) <= 0:
                raise ValueError("Price must be positive")
        except ValueError:
            return [TextContent(type="text", text=f"Invalid price: {price}")]
        if chain not in SUPPORTED_CHAINS:
            return [TextContent(type="text", text=f"Unsupported chain: {chain}")]
        if marketplace not in MARKETPLACE_CONTRACTS:
            return [TextContent(type="text", text=f"Unsupported marketplace: {marketplace}")]
        
        # Generate listing ID
        listing_id = f"listing_{hashlib.sha256(f'{contract_address}{token_id}{seller}{time.time()}'.encode()).hexdigest()}"
        
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
    """Analyze NFT marketplace trends using OpenSea API"""
    try:
        if not is_address(collection):
            return [TextContent(type="text", text=f"Invalid collection address: {collection}")]
        if chain not in SUPPORTED_CHAINS:
            return [TextContent(type="text", text=f"Unsupported chain: {chain}")]
        
        # Check database for cached stats
        if db_connection:
            cursor = db_connection.cursor()
            cursor.execute(
                "SELECT floor_price, total_volume, num_owners, total_supply FROM collection_stats WHERE collection = ? AND chain = ?",
                (collection, chain)
            )
            result = cursor.fetchone()
            if result and (time.time() - cursor.execute("SELECT created_at FROM collection_stats WHERE collection = ? AND chain = ?", 
                                                       (collection, chain)).fetchone()[0].timestamp()) < 3600:
                floor_price, total_volume, num_owners, total_supply = result
                result_text = f"""Marketplace Trends for {collection}:
Chain: {chain}
Floor Price: {floor_price or 'N/A'} {SUPPORTED_CHAINS[chain]['native_token']}
Total Volume: {total_volume or 'N/A'} {SUPPORTED_CHAINS[chain]['native_token']}
Number of Owners: {num_owners or 'N/A'}
Total Supply: {total_supply or 'N/A'}
Source: Database cache"""
                return [TextContent(type="text", text=result_text)]
        
        # Fetch from OpenSea API
        chain_name = "matic" if chain == "polygon" else chain
        async with aiohttp.ClientSession() as session:
            headers = {"X-API-KEY": OPENSEA_API_KEY} if OPENSEA_API_KEY else {}
            async with session.get(
                f"{SUPPORTED_CHAINS[chain]['opensea_api']}/collection/{collection}/stats",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get("stats", {})
                    
                    trends = MarketplaceTrends(
                        collection=collection,
                        chain=chain,
                        floor_price=str(stats.get("floor_price", 0)),
                        volume_24h=str(stats.get("one_day_volume", 0)),
                        sales_count_24h=stats.get("one_day_sales", 0),
                        average_price_24h=str(stats.get("one_day_average_price", 0))
                    )
                    
                    # Store in database
                    if db_connection:
                        cursor = db_connection.cursor()
                        cursor.execute(
                            "INSERT OR REPLACE INTO collection_stats (collection, chain, floor_price, total_volume, num_owners, total_supply) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                collection,
                                chain,
                                trends.floor_price,
                                str(stats.get("total_volume", 0)),
                                stats.get("num_owners", None),
                                stats.get("total_supply", None)
                            )
                        )
                        db_connection.commit()
                    
                    result = f"""Marketplace Trends for {collection}:
Chain: {chain}
Floor Price: {trends.floor_price} {SUPPORTED_CHAINS[chain]['native_token']}
24h Volume: {trends.volume_24h} {SUPPORTED_CHAINS[chain]['native_token']}
24h Sales: {trends.sales_count_24h}
24h Average Price: {trends.average_price_24h} {SUPPORTED_CHAINS[chain]['native_token']}
Last Updated: {time.ctime(trends.timestamp)}"""
                    
                    return [TextContent(type="text", text=result)]
                else:
                    return [TextContent(type="text", text=f"Failed to fetch trends from OpenSea: HTTP {response.status}")]
    
    except Exception as e:
        logger.error(f"Error getting marketplace trends: {e}")
        return [TextContent(type="text", text=f"Error getting marketplace trends: {str(e)}")]

@mcp.tool()
async def monitor_nft_transaction(tx_id: str, chain: str = "ethereum") -> List[TextContent]:
    """Monitor an NFT transaction status"""
    try:
        if chain not in SUPPORTED_CHAINS:
            return [TextContent(type="text", text=f"Unsupported chain: {chain}")]
        
        # Check database first
        if db_connection:
            cursor = db_connection.cursor()
            cursor.execute("SELECT data, status FROM transactions WHERE id = ?", (tx_id,))
            result = cursor.fetchone()
            if result:
                data, status = result
                tx = json.loads(data)
                if tx["type"] == "bid":
                    bid_tx = BidTransaction(**tx)
                    result = f"""Bid Transaction Status:
Transaction ID: {bid_tx.transaction_id}
Collection: {bid_tx.collection}
Token ID: {bid_tx.token_id}
Amount: {bid_tx.amount} {SUPPORTED_CHAINS[bid_tx.chain]['native_token']}
Bidder: {bid_tx.bidder}
Marketplace: {bid_tx.marketplace}
Chain: {bid_tx.chain}
Status: {bid_tx.status}
Created: {time.ctime(bid_tx.timestamp)}"""
                elif tx["type"] == "mint":
                    mint_tx = MintTransaction(**tx)
                    result = f"""Mint Transaction Status:
Transaction ID: {mint_tx.transaction_id}
Contract: {mint_tx.contract_address}
Minter: {mint_tx.minter}
Chain: {mint_tx.chain}
Status: {mint_tx.status}
Created: {time.ctime(mint_tx.timestamp)}
Metadata: {json.dumps(mint_tx.metadata, indent=2)}"""
                elif tx["type"] == "cancel_bid":
                    result = f"""Cancel Bid Transaction Status:
Transaction ID: {tx['transaction_id']}
Collection: {tx['collection']}
Token ID: {tx['token_id']}
Bidder: {tx['bidder']}
Marketplace: {tx['marketplace']}
Chain: {tx['chain']}
Status: {tx['status']}
Created: {time.ctime(tx['timestamp'])}"""
                else:
                    result = f"Unknown transaction type for ID: {tx_id}"
                return [TextContent(type="text", text=result)]
        
        # Check global transactions dict
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
                status = "Success" if tx_receipt.status == 1 else "Failed"
                result = f"""Blockchain Transaction Status:
Transaction Hash: {tx_id}
Block Number: {tx_receipt.blockNumber}
Gas Used: {tx_receipt.gasUsed}
Status: {status}
Chain: {chain}"""
            except Exception:
                result = f"Transaction {tx_id} not found in our records or on the blockchain"
        
        return [TextContent(type="text", text=result)]
    
    except Exception as e:
        logger.error(f"Error monitoring transaction: {e}")
        return [TextContent(type="text", text=f"Error monitoring transaction: {str(e)}")]

@mcp.tool()
async def get_nft_ownership(contract_address: str, token_id: str, chain: str = "ethereum") -> List[TextContent]:
    """Retrieve the current owner of an NFT"""
    try:
        if not is_address(contract_address):
            return [TextContent(type="text", text=f"Invalid contract address: {contract_address}")]
        if not token_id.isdigit():
            return [TextContent(type="text", text=f"Invalid token ID: {token_id}")]
        if chain not in SUPPORTED_CHAINS:
            return [TextContent(type="text", text=f"Unsupported chain: {chain}")]
        
        w3 = await _get_web3_connection(chain)
        contract_address = to_checksum_address(contract_address)
        
        # Standard ERC-721 ABI for ownerOf function
        erc721_abi = [
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "ownerOf",
                "outputs": [{"internalType": "address", "name": "", "type": "address"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        contract = w3.eth.contract(address=contract_address, abi=erc721_abi)
        owner = contract.functions.ownerOf(int(token_id)).call()
        
        result = f"""NFT Ownership for {contract_address}#{token_id}:
Owner: {owner}
Chain: {chain}"""
        
        return [TextContent(type="text", text=result)]
    
    except Exception as e:
        logger.error(f"Error retrieving NFT ownership: {e}")
        return [TextContent(type="text", text=f"Error retrieving NFT ownership: {str(e)}")]

@mcp.tool()
async def cancel_bid(tx_id: str, bidder: str, chain: str = "ethereum") -> List[TextContent]:
    """Cancel an existing bid on an NFT"""
    try:
        if not is_address(bidder):
            return [TextContent(type="text", text=f"Invalid bidder address: {bidder}")]
        if chain not in SUPPORTED_CHAINS:
            return [TextContent(type="text", text=f"Unsupported chain: {chain}")]
        
        # Check database for bid
        if db_connection:
            cursor = db_connection.cursor()
            cursor.execute("SELECT data, status FROM transactions WHERE id = ? AND type = 'bid'", (tx_id,))
            result = cursor.fetchone()
            if result:
                data, status = result
                bid_tx = BidTransaction(**json.loads(data))
                if bid_tx.bidder.lower() != bidder.lower():
                    return [TextContent(type="text", text="Bidder address does not match the original bid")]
                if status != "pending":
                    return [TextContent(type="text", text=f"Cannot cancel bid with status: {status}")]
                
                # Update status to cancelled
                cursor.execute("UPDATE transactions SET status = ? WHERE id = ?", ("cancelled", tx_id))
                db_connection.commit()
                
                # Update in-memory transactions
                if tx_id in transactions and isinstance(transactions[tx_id], BidTransaction):
                    transactions[tx_id].status = "cancelled"
                
                result = f"""Bid cancelled successfully!
Transaction ID: {tx_id}
Collection: {bid_tx.collection}
Token ID: {bid_tx.token_id}
Bidder: {bid_tx.bidder}
Marketplace: {bid_tx.marketplace}
Chain: {bid_tx.chain}
Status: Cancelled

Note: This is a simulated cancellation. In a real implementation, this would interact with the marketplace contract."""
                return [TextContent(type="text", text=result)]
        
        # Check in-memory transactions
        if tx_id in transactions and isinstance(transactions[tx_id], BidTransaction):
            bid_tx = transactions[tx_id]
            if bid_tx.bidder.lower() != bidder.lower():
                return [TextContent(type="text", text="Bidder address does not match the original bid")]
            if bid_tx.status != "pending":
                return [TextContent(type="text", text=f"Cannot cancel bid with status: {bid_tx.status}")]
            
            bid_tx.status = "cancelled"
            if db_connection:
                db_connection.execute(
                    "INSERT OR REPLACE INTO transactions (id, type, data, status) VALUES (?, ?, ?, ?)",
                    (tx_id, "bid", bid_tx.model_dump_json(), "cancelled")
                )
                db_connection.commit()
            
            result = f"""Bid cancelled successfully!
Transaction ID: {tx_id}
Collection: {bid_tx.collection}
Token ID: {bid_tx.token_id}
Bidder: {bid_tx.bidder}
Marketplace: {bid_tx.marketplace}
Chain: {bid_tx.chain}
Status: Cancelled

Note: This is a simulated cancellation. In a real implementation, this would interact with the marketplace contract."""
            return [TextContent(type="text", text=result)]
        
        return [TextContent(type="text", text=f"Bid transaction {tx_id} not found")]
    
    except Exception as e:
        logger.error(f"Error cancelling bid: {e}")
        return [TextContent(type="text", text=f"Error cancelling bid: {str(e)}")]

@mcp.tool()
async def get_collection_stats(collection: str, chain: str = "ethereum") -> List[TextContent]:
    """Fetch detailed statistics for an NFT collection"""
    try:
        if not is_address(collection):
            return [TextContent(type="text", text=f"Invalid collection address: {collection}")]
        if chain not in SUPPORTED_CHAINS:
            return [TextContent(type="text", text=f"Unsupported chain: {chain}")]
        
        # Check database for cached stats
        if db_connection:
            cursor = db_connection.cursor()
            cursor.execute(
                "SELECT total_supply, num_owners, floor_price, total_volume FROM collection_stats WHERE collection = ? AND chain = ?",
                (collection, chain)
            )
            result = cursor.fetchone()
            if result and (time.time() - cursor.execute("SELECT created_at FROM collection_stats WHERE collection = ? AND chain = ?", 
                                                       (collection, chain)).fetchone()[0].timestamp()) < 3600:
                total_supply, num_owners, floor_price, total_volume = result
                result_text = f"""Collection Stats for {collection}:
Chain: {chain}
Total Supply: {total_supply or 'N/A'}
Number of Owners: {num_owners or 'N/A'}
Floor Price: {floor_price or 'N/A'} {SUPPORTED_CHAINS[chain]['native_token']}
Total Volume: {total_volume or 'N/A'} {SUPPORTED_CHAINS[chain]['native_token']}
Source: Database cache"""
                return [TextContent(type="text", text=result_text)]
        
        # Fetch from Alchemy NFT API
        chain_name = "matic" if chain == "polygon" else "eth"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://eth-mainnet.g.alchemy.com/nft/v3/{ALCHEMY_API_KEY}/getContractMetadata?contractAddress={collection}"
            ) if chain == "ethereum" else session.get(
                f"https://polygon-mainnet.g.alchemy.com/nft/v3/{ALCHEMY_API_KEY}/getContractMetadata?contractAddress={collection}"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = CollectionStats(
                        collection=collection,
                        chain=chain,
                        total_supply=data.get("totalSupply"),
                        num_owners=None,  # Alchemy API doesn't provide num_owners
                        floor_price=None,  # Fetch from OpenSea below
                        total_volume=None
                    )
                    
                    # Fetch floor price and volume from OpenSea
                    async with session.get(
                        f"{SUPPORTED_CHAINS[chain]['opensea_api']}/collection/{collection}/stats",
                        headers={"X-API-KEY": OPENSEA_API_KEY} if OPENSEA_API_KEY else {}
                    ) as opensea_response:
                        if opensea_response.status == 200:
                            opensea_data = await opensea_response.json()
                            opensea_stats = opensea_data.get("stats", {})
                            stats.floor_price = str(opensea_stats.get("floor_price", 0))
                            stats.total_volume = str(opensea_stats.get("total_volume", 0))
                            stats.num_owners = opensea_stats.get("num_owners", None)
                    
                    # Store in database
                    if db_connection:
                        cursor = db_connection.cursor()
                        cursor.execute(
                            "INSERT OR REPLACE INTO collection_stats (collection, chain, total_supply, num_owners, floor_price, total_volume) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                collection,
                                chain,
                                stats.total_supply,
                                stats.num_owners,
                                stats.floor_price,
                                stats.total_volume
                            )
                        )
                        db_connection.commit()
                    
                    result = f"""Collection Stats for {collection}:
Chain: {chain}
Total Supply: {stats.total_supply or 'N/A'}
Number of Owners: {stats.num_owners or 'N/A'}
Floor Price: {stats.floor_price or 'N/A'} {SUPPORTED_CHAINS[chain]['native_token']}
Total Volume: {stats.total_volume or 'N/A'} {SUPPORTED_CHAINS[chain]['native_token']}
Last Updated: {time.ctime(stats.timestamp)}"""
                    
                    return [TextContent(type="text", text=result)]
                else:
                    return [TextContent(type="text", text=f"Failed to fetch collection stats from Alchemy: HTTP {response.status}")]
    
    except Exception as e:
        logger.error(f"Error getting collection stats: {e}")
        return [TextContent(type="text", text=f"Error getting collection stats: {str(e)}")]

# Initialize database on module load
try:
    db_connection = _initialize_db()
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")
    db_connection = None

# Export the server instance
app = mcp
server = mcp