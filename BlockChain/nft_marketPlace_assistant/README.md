# NFT Marketplace Assistant MCP Server

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

![License](https://img.shields.io/badge/license-MIT-blue)

![Python](https://img.shields.io/badge/python-3.8%2B-blue)

![Dependencies](https://img.shields.io/badge/dependencies-up%20to%20date-green)

![MCP](https://img.shields.io/badge/MCP-0.1.2-blue)A professional-grade Model Context Protocol (MCP) server for interacting with NFT marketplaces like OpenSea and Rarible. Built with Python and the MCP Python SDK, this server exposes a suite of tools for NFT operations, including metadata retrieval, bidding, minting, listing, trend analysis, ownership queries, bid cancellation, and collection statistics. It supports Ethereum and Polygon blockchains, leveraging Alchemy for blockchain interactions and OpenSea for real-time marketplace data.

Designed by a professional developer, this project emphasizes modularity, scalability, and robust error handling, making it suitable for integration with LLM-driven applications or direct API usage. The server uses FastMCP for protocol compliance, SQLite for data persistence, and Pydantic for strict data validation.

## Table of Contents

- Overview
- Features
- Architecture
- Prerequisites
- Installation
- Configuration
- Running the Server
- Available Tools
- API Examples
- Database Schema
- Troubleshooting
- Contributing
- License

## Overview

The NFT Marketplace Assistant MCP Server enables seamless interaction with NFT marketplaces through a standardized MCP interface. It provides tools for querying NFT metadata, managing marketplace transactions (bidding, minting, listing), and analyzing market trends. The server integrates with blockchain networks (Ethereum, Polygon) via Web3.py and Alchemy, and fetches real-time marketplace data from OpenSea’s API. Data is cached in a SQLite database for performance, and all operations are validated using Pydantic models.

This server is ideal for developers building LLM-powered NFT applications, blockchain analytics tools, or marketplace integrations. It adheres to the MCP specification, ensuring compatibility with MCP clients and tools like the MCP Inspector.

## Features

- **Multi-Chain Support**: Operates on Ethereum and Polygon blockchains.
- **NFT Operations**:
  - Retrieve NFT metadata (name, description, image, attributes).
  - Place and cancel bids on NFT auctions (simulated).
  - Mint new NFTs (simulated).
  - List NFTs for sale (simulated).
  - Monitor transaction statuses (database and on-chain).
  - Analyze marketplace trends (floor price, 24h volume, sales count).
  - Query current NFT ownership.
  - Fetch collection statistics (total supply, owners, volume).
- **Real-Time Data**: Integrates with OpenSea API for trends and Alchemy NFT API for contract metadata.
- **Database Caching**: Stores NFT metadata and collection stats in SQLite with indexing.
- **Robust Validation**: Uses Pydantic for type-safe input/output validation.
- **Error Handling**: Includes retry logic for blockchain connections and comprehensive logging.
- **MCP Compliance**: Built with FastMCP for standardized LLM context integration.
- **Scalable Design**: Modular architecture with lifecycle management and caching.

## Architecture

The server is built using the MCP Python SDK and follows a modular, microservices-oriented design:

- **FastMCP**: Handles MCP protocol compliance, tool registration, and HTTP transport (Streamable HTTP).
- **Web3.py**: Connects to Ethereum and Polygon via Alchemy RPCs for blockchain interactions.
- **APIs**:
  - OpenSea API: Fetches real-time marketplace trends and collection stats.
  - Alchemy NFT API: Retrieves contract metadata (e.g., total supply).
- **SQLite Database**: Stores transactions, listings, NFT metadata, and collection stats with indexes for performance.
- **Pydantic Models**: Validates data for NFT metadata, transactions, listings, and trends.
- **Caching**: Uses `TTLCache` for ABIs (1 hour) and gas prices (5 minutes).
- **Logging**: Comprehensive logging with timestamps and levels for debugging.

Tools are exposed as MCP endpoints, accessible via HTTP or the MCP Inspector UI. The server supports stateless operation for scalability and includes lifecycle management for resource initialization.

## Prerequisites

- **Python**: 3.8 or higher
- **uv**: Python package manager (recommended, see uv documentation)
- **API Keys**:
  - Alchemy API Key for blockchain RPCs
  - Etherscan API Key for contract ABI fetching
  - OpenSea API Key for marketplace data
- **Operating System**: Windows, macOS, or Linux
- **Git**: Optional, for cloning the repository

## Installation

1. **Clone the Repository** (optional, if hosted):

   ```bash
   git clone https://github.com/your-repo/nft-marketplace-assistant.git
   cd nft-marketplace-assistant
   ```

2. **Create a uv-Managed Project** (if starting fresh):

   ```bash
   uv init nft-marketplace-assistant
   cd nft-marketplace-assistant
   ```

3. **Set Up a Virtual Environment**:

   ```bash
   uv venv
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # macOS/Linux
   ```

4. **Install Dependencies**:

   ```bash
   uv add "mcp[cli]>=0.1.2" aiohttp>=3.8.6 requests>=2.31.0 web3>=6.11.0 python-dotenv>=1.0.0 cachetools>=5.3.1 pydantic>=2.0.0
   ```

5. **Verify Installation**:

   ```bash
   uv pip list
   ```

   Ensure the following are installed:

   - `mcp[cli]>=0.1.2`
   - `aiohttp>=3.8.6`
   - `requests>=2.31.0`
   - `web3>=6.11.0`
   - `python-dotenv>=1.0.0`
   - `cachetools>=5.3.1`
   - `pydantic>=2.0.0`

6. **Clear Python Cache** (if updating):

   ```bash
   del /s server\__pycache__  # Windows
   rm -rf server/__pycache__  # macOS/Linux
   ```

## Configuration

1. **Create a** `.env` **File**: In the project root (`U:\MCPServers\BlockChain\nft_marketPlace_assistant`), create a `.env` file:

   ```env
   INFURA_PROJECT_ID=your_infura_project_id
   ETHERSCAN_API_KEY=your_etherscan_api_key
   ALCHEMY_API_KEY=your_alchemy_api_key
   HMAC_SECRET=your_hmac_secret
   OPENSEA_API_KEY=your_opensea_api_key
   ```

  

   Obtain API keys from:

   - Alchemy
   - Etherscan
   - OpenSea

2. **Verify** `.env`: Ensure all keys are valid. Missing or invalid keys may cause API failures.

## Running the Server

### Development Mode

Start the server with the MCP Inspector UI for testing and debugging:

```bash
uv run mcp dev .\server\server.py
```

Access the MCP Inspector at `http://localhost:3001`.

### Production Mode

Run the server for production use:

```bash
uv run mcp run .\server\server.py
```

### Claude Desktop Integration

Install the server in Claude Desktop for LLM integration:

```bash
uv run mcp install .\server\server.py --name "NFT Marketplace Assistant"
```

Optionally, include environment variables:

```bash
uv run mcp install .\server\server.py -f .env
```

### Direct Execution

For custom deployments:

```bash
uv run python .\server\server.py
```

### Mounting to an ASGI Server

Mount the server to an existing FastAPI/Starlette application:

```python
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from server import mcp  # Import your MCP server

app = FastAPI()
app.mount("/nft", mcp.streamable_http_app())
```

## Available Tools

The server exposes the following MCP tools, accessible via HTTP endpoints or the MCP Inspector:

1. `get_nft_metadata`:

   - **Description**: Retrieves NFT metadata (name, description, image, attributes) from the token URI, cached in SQLite.
   - **Parameters**:
     - `contract_address` (str): NFT contract address.
     - `token_id` (str): NFT token ID.
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with formatted metadata.

2. `place_bid`:

   - **Description**: Simulates placing a bid on an NFT auction, storing it in the database.
   - **Parameters**:
     - `collection` (str): NFT collection contract address.
     - `token_id` (str): NFT token ID.
     - `amount` (str): Bid amount in native token (e.g., ETH, MATIC).
     - `bidder` (str): Bidder address.
     - `marketplace` (str, optional): `opensea` or `rarible` (default: `opensea`).
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with bid details.

3. `mint_nft`:

   - **Description**: Simulates minting a new NFT, storing it in the database.
   - **Parameters**:
     - `contract_address` (str): NFT contract address.
     - `metadata` (dict): NFT metadata (e.g., `{"name": "NFT", "description": "Test"}`).
     - `minter` (str): Minter address.
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with mint details.

4. `list_nft_for_sale`:

   - **Description**: Simulates listing an NFT for sale, storing it in the database.
   - **Parameters**:
     - `contract_address` (str): NFT contract address.
     - `token_id` (str): NFT token ID.
     - `price` (str): Sale price in native token.
     - `seller` (str): Seller address.
     - `marketplace` (str, optional): `opensea` or `rarible` (default: `opensea`).
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with listing details.

5. `get_marketplace_trends`:

   - **Description**: Fetches real-time marketplace trends (floor price, 24h volume, sales) from OpenSea, cached in SQLite.
   - **Parameters**:
     - `collection` (str): NFT collection contract address.
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with trend statistics.

6. `monitor_nft_transaction`:

   - **Description**: Monitors transaction status (bid, mint, listing, or cancellation) in the database or on-chain.
   - **Parameters**:
     - `tx_id` (str): Transaction ID or hash.
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with transaction status.

7. `get_nft_ownership`:

   - **Description**: Retrieves the current owner of an NFT using the ERC-721 `ownerOf` function.
   - **Parameters**:
     - `contract_address` (str): NFT contract address.
     - `token_id` (str): NFT token ID.
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with owner address.

8. `cancel_bid`:

   - **Description**: Cancels a pending bid, updating its status in the database.
   - **Parameters**:
     - `tx_id` (str): Bid transaction ID.
     - `bidder` (str): Bidder address.
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with cancellation details.

9. `get_collection_stats`:

   - **Description**: Fetches collection statistics (total supply, owners, floor price, volume) from Alchemy and OpenSea, cached in SQLite.
   - **Parameters**:
     - `collection` (str): NFT collection contract address.
     - `chain` (str, optional): `ethereum` or `polygon` (default: `ethereum`).
   - **Returns**: `List[TextContent]` with collection stats.

## API Examples

Use `curl` or tools like Postman to interact with the server. Replace placeholders (e.g., `0x...`, `bid_...`) with valid values. All endpoints are POST requests to `http://localhost:6277/nft/<tool_name>`.

- **Get NFT Metadata**:

  ```bash
  curl -X POST http://localhost:6277/nft/get_nft_metadata \
    -H "Content-Type: application/json" \
    -d '{"contract_address": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "token_id": "1", "chain": "ethereum"}'
  ```

- **Place Bid**:

  ```bash
  curl -X POST http://localhost:6277/nft/place_bid \
    -H "Content-Type: application/json" \
    -d '{"collection": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "token_id": "1", "amount": "0.5", "bidder": "0xYourAddress", "marketplace": "opensea", "chain": "ethereum"}'
  ```

- **Mint NFT**:

  ```bash
  curl -X POST http://localhost:6277/nft/mint_nft \
    -H "Content-Type: application/json" \
    -d '{"contract_address": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "metadata": {"name": "Test NFT", "description": "A test NFT", "image": "https://example.com/image.png"}, "minter": "0xYourAddress", "chain": "ethereum"}'
  ```

- **List NFT for Sale**:

  ```bash
  curl -X POST http://localhost:6277/nft/list_nft_for_sale \
    -H "Content-Type: application/json" \
    -d '{"contract_address": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "token_id": "1", "price": "1.0", "seller": "0xYourAddress", "marketplace": "opensea", "chain": "ethereum"}'
  ```

- **Get Marketplace Trends**:

  ```bash
  curl -X POST http://localhost:6277/nft/get_marketplace_trends \
    -H "Content-Type: application/json" \
    -d '{"collection": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "chain": "ethereum"}'
  ```

- **Monitor Transaction**:

  ```bash
  curl -X POST http://localhost:6277/nft/monitor_nft_transaction \
    -H "Content-Type: application/json" \
    -d '{"tx_id": "bid_...", "chain": "ethereum"}'
  ```

- **Get NFT Ownership**:

  ```bash
  curl -X POST http://localhost:6277/nft/get_nft_ownership \
    -H "Content-Type: application/json" \
    -d '{"contract_address": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "token_id": "1", "chain": "ethereum"}'
  ```

- **Cancel Bid**:

  ```bash
  curl -X POST http://localhost:6277/nft/cancel_bid \
    -H "Content-Type: application/json" \
    -d '{"tx_id": "bid_...", "bidder": "0xYourAddress", "chain": "ethereum"}'
  ```

- **Get Collection Stats**:

  ```bash
  curl -X POST http://localhost:6277/nft/get_collection_stats \
    -H "Content-Type: application/json" \
    -d '{"collection": "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d", "chain": "ethereum"}'
  ```

## Database Schema

The SQLite database (`server/nft_marketplace.db`) includes four tables:

1. `nfts`:

   - `contract_address` (TEXT, PRIMARY KEY): NFT contract address.
   - `token_id` (TEXT, PRIMARY KEY): NFT token ID.
   - `name` (TEXT): NFT name.
   - `description` (TEXT): NFT description.
   - `image` (TEXT): NFT image URL.
   - `attributes` (TEXT): JSON-encoded attributes.
   - `external_url` (TEXT, nullable): External URL.
   - `chain` (TEXT): Blockchain network (`ethereum`, `polygon`).
   - `created_at` (TIMESTAMP): Creation timestamp.
   - **Index**: `idx_nfts_contract` on `contract_address`.

2. `transactions`:

   - `id` (TEXT, PRIMARY KEY): Transaction ID.
   - `type` (TEXT): Transaction type (`bid`, `mint`, `cancel_bid`).
   - `data` (TEXT): JSON-encoded transaction data.
   - `status` (TEXT): Status (`pending`, `cancelled`).
   - `created_at` (TIMESTAMP): Creation timestamp.
   - **Index**: `idx_transactions_type` on `type`.

3. `listings`:

   - `id` (TEXT, PRIMARY KEY): Listing ID.
   - `contract_address` (TEXT): NFT contract address.
   - `token_id` (TEXT): NFT token ID.
   - `price` (TEXT): Sale price in native token.
   - `seller` (TEXT): Seller address.
   - `marketplace` (TEXT): Marketplace name (`opensea`, `rarible`).
   - `chain` (TEXT): Blockchain network.
   - `status` (TEXT): Status (`active`).
   - `created_at` (TIMESTAMP): Creation timestamp.
   - **Index**: `idx_listings_contract` on `contract_address`.

4. `collection_stats`:

   - `collection` (TEXT, PRIMARY KEY): Collection contract address.
   - `chain` (TEXT): Blockchain network.
   - `total_supply` (INTEGER, nullable): Total NFTs in collection.
   - `num_owners` (INTEGER, nullable): Number of unique owners.
   - `floor_price` (TEXT, nullable): Floor price in native token.
   - `total_volume` (TEXT, nullable): Total trading volume.
   - `created_at` (TIMESTAMP): Creation timestamp.

## Troubleshooting

1. **Server Fails to Start**:

   - **Check Logs**: Review console logs for errors (e.g., `ModuleNotFoundError`, `ConnectionError`).
   - **Verify MCP Version**:

     ```bash
     uv pip show mcp
     ```

     Ensure `mcp[cli]>=0.1.2`. Update if needed:

     ```bash
     uv pip install mcp[cli]>=0.1.2
     ```

2. **API Connection Issues**:

   - **Test Alchemy API**:

     ```python
     import aiohttp
     async def test_alchemy():
         async with aiohttp.ClientSession() as session:
             async with session.get(f"https://eth-mainnet.g.alchemy.com/nft/v3/{ALCHEMY_API_KEY}/getContractMetadata?contractAddress=0x06012c8cf97BEaD5deAe237070F9587f8E7A266d") as resp:
                 print(resp.status, await resp.text())
     if __name__ == "__main__":
         import asyncio
         asyncio.run(test_alchemy())
     ```

     Save as `test_alchemy.py` and run:

     ```bash
     uv run python test_alchemy.py
     ```

     If it fails (e.g., 401 Unauthorized), verify `ALCHEMY_API_KEY` or get a new key from alchemy.com.
   - **Test OpenSea API**:

     ```bash
     curl -H "X-API-KEY: $OPENSEA_API_KEY" "https://api.opensea.io/api/v2/collection/0x06012c8cf97BEaD5deAe237070F9587f8E7A266d/stats"
     ```

     If rate-limited or unauthorized, ensure `OPENSEA_API_KEY` is valid in `.env`.

3. **Blockchain Connection Issues**:

   - **Test Web3 Connections**:

     ```python
     from web3 import Web3
     chains = {
         "ethereum": f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}",
         "polygon": f"https://polygon-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"
     }
     for chain, url in chains.items():
         w3 = Web3(Web3.HTTPProvider(url))
         print(f"{chain}: {w3.is_connected()}")
     ```

     Save as `test_web3.py` and run:

     ```bash
     uv run python test_web3.py
     ```

     If connections fail, switch to Infura in `server.py`:

     ```python
     SUPPORTED_CHAINS["ethereum"]["rpc_url"] = f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"
     SUPPORTED_CHAINS["polygon"]["rpc_url"] = f"https://polygon-mainnet.infura.io/v3/{INFURA_PROJECT_ID}"
     ```

4. **Database Issues**:

   - **Test Database**:

     ```python
     import sqlite3
     conn = sqlite3.connect("server/nft_marketplace.db")
     cursor = conn.cursor()
     cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
     print(cursor.fetchall())
     conn.close()
     ```

     Save as `test_db.py` and run:

     ```bash
     uv run python test_db.py
     ```

     Expected output: `[('nfts',), ('transactions',), ('listings',), ('collection_stats',)]`. If tables are missing, delete `server/nft_marketplace.db` and restart the server.

5. **Simulated Operations**:

   - Tools (`place_bid`, `mint_nft`, `list_nft_for_sale`, `cancel_bid`) are simulated to avoid complex blockchain interactions (e.g., transaction signing, gas estimation). To enable real interactions:
     - Add private key management for `bidder`, `minter`, `seller`.
     - Implement full contract ABIs for OpenSea/Rarible.
     - Add gas estimation and transaction submission logic.

6. **Common Errors**:

   - **Invalid Address**: Ensure `contract_address`, `bidder`, `minter`, `seller` are valid Ethereum addresses (e.g., `0x...`).
   - **Invalid Token ID**: Use numeric token IDs (e.g., `"1"`).
   - **API Rate Limits**: Check OpenSea/Alchemy dashboards for rate limit status. Use valid API keys to avoid throttling.

If issues persist, share:

- Full error traceback from `uv run mcp dev .\server\server.py`.
- Output of `uv pip show mcp`.
- Results from `test_alchemy.py`, `test_web3.py`, and `test_db.py`.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository (update URL if hosted).
2. Create a feature branch:

   ```bash
   git checkout -b feature/your-feature
   ```
3. Commit changes:

   ```bash
   git commit -m "Add your feature"
   ```
4. Push to the branch:

   ```bash
   git push origin feature/your-feature
   ```
5. Open a pull request with a detailed description.

Follow PEP 8 style guidelines and include tests for new features. See the MCP Contributing Guide for more details.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## About

A professional MCP server for NFT marketplace interactions, built with Python, Web3.py, and the MCP Python SDK. Supports Ethereum and Polygon, with real-time data from OpenSea and Alchemy.