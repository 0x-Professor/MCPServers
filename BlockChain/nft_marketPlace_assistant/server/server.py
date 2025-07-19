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
