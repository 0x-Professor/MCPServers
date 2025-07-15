Cross-Chain Bridge Assistant MCP Server

A comprehensive MCP (Multi-Chain Protocol) server for cross-chain asset transfers, supporting Ethereum, Polygon, Arbitrum, and Optimism. The server provides tools for estimating bridge fees, initiating transactions, monitoring transfers, and retrieving transaction history, with secure OAuth 2.1 authentication and SQLite-based transaction storage.
Table of Contents

Features
Prerequisites
Installation
Configuration
Usage
Project Structure
Supported Chains
API Endpoints
Troubleshooting
Contributing
License

Features

Cross-Chain Bridging: Supports asset transfers between Ethereum, Polygon, Arbitrum, and Optimism using bridge contracts (e.g., Polygon Bridge, Arbitrum Bridge, Optimism Bridge).
Fee Estimation: Estimates gas fees, bridge fees, and transaction times for cross-chain transfers.
Transaction Monitoring: Tracks transaction status (pending, confirmed, failed, cancelled) with real-time updates.
Transaction History: Retrieves historical transaction data for a given address or chain.
Authentication: Implements OAuth 2.1 token verification for secure access.
Database Storage: Uses SQLite to store transaction data persistently.
Caching: Utilizes TTLCache for ABI and gas price caching to optimize performance.
Reliable Connections: Connects to blockchain networks with retry logic and multiple RPC providers.

Prerequisites

Python: Version 3.11 or higher (tested with 3.13).
uv: Package manager for Python (recommended for dependency management).
Infura or Alchemy Account: For reliable blockchain RPC endpoints.
Etherscan API Key: For fetching contract ABIs and transaction data.
Git: For cloning the repository (optional).
Operating System: Tested on Windows; should work on Linux/macOS with minor adjustments.

Installation

Clone the Repository (if applicable):
git clone https://github.com/your-repo/cross_chain_bridge_assistant.git
cd cross_chain_bridge_assistant

If you’re working locally at U:\MCPServers\BlockChain\cross_chain_bridge_assistant, skip this step.

Install uv:Download and install uv from astral-sh/uv:
curl -LsSf https://astral.sh/uv/install.sh | sh


Set Up Virtual Environment:Navigate to the project directory and create a virtual environment:
cd U:\MCPServers\BlockChain\cross_chain_bridge_assistant
uv venv --python 3.11

Activate the virtual environment:

Windows:.\.venv\Scripts\activate


Linux/macOS:source .venv/bin/activate




Install Dependencies:Use the pyproject.toml to install dependencies:
uv sync

Alternatively, install from requirements.txt:
uv pip install -r requirements.txt

The dependencies include:

mcp[cli]>=0.1.2
aiohttp>=3.8.6
requests>=2.31.0
web3>=6.11.0
python-dotenv>=1.0.0
cachetools>=5.3.1
pydantic>=2.0.0



Configuration

Create .env File:In the project root (U:\MCPServers\BlockChain\cross_chain_bridge_assistant), create a .env file with the following:
INFURA_PROJECT_ID=your_infura_project_id
ETHERSCAN_API_KEY=your_etherscan_api_key
HMAC_SECRET=your-secret-key
AUTH_ISSUER_URL=https://auth.example.com
AUTH_SERVER_URL=http://localhost:3001
ALCHEMY_API_KEY=your_alchemy_api_key


INFURA_PROJECT_ID: Get from Infura. Example: 7464fe4568974a00b5cf20e94ebc4833.
ETHERSCAN_API_KEY: Get from Etherscan. Example: 3NK7D3FBF2AQ23RBEDPX9BVZH4DD4E3DHZ.
ALCHEMY_API_KEY: Get from Alchemy (optional, for alternative RPCs).
HMAC_SECRET: A secure key for signing transactions (generate a random string for local testing).
AUTH_ISSUER_URL and AUTH_SERVER_URL: Use placeholders for local testing or configure for OAuth 2.1 authentication.


Verify Environment:Test the .env file loading:
from dotenv import load_dotenv
import os
load_dotenv()
print(os.getenv("INFURA_PROJECT_ID"))

Save as test_env.py and run uv run python test_env.py.


Usage

Run the Server:Start the MCP server in development mode (includes MCP Inspector UI):
uv run mcp dev server/server.py

For production-like mode:
uv run mcp run server/server.py

The server runs on http://localhost:3001 by default.

Interact with the Server:

MCP Inspector: In dev mode, open http://localhost:3001 in a browser to use the interactive UI for testing tools like get_transaction_history, estimate_bridge_fees, etc.
API Calls: Use curl or a tool like Postman to interact with endpoints. Example:curl -X POST http://localhost:3001/bridge/get_transaction_history \
  -H "Content-Type: application/json" \
  -d '{"address": "0xYourAddress", "chain": "ethereum"}'




Available Tools:

get_transaction_history: Retrieves transaction history for a given address and chain.
estimate_bridge_fees: Estimates fees for cross-chain transfers.
initiate_bridge: Initiates a cross-chain asset transfer.
monitor_transaction: Tracks the status of a bridge transaction.
get_bridge_status: Returns operational status and liquidity for supported bridges.



Project Structure
cross_chain_bridge_assistant/
├── .venv/                 # Virtual environment
├── server/                # Server code
│   ├── server.py          # Main MCP server implementation
│   ├── bridge.db          # SQLite database for transaction storage
├── .python-version        # Python version specification
├── main.py                # Entry point (optional, minimal)
├── pyproject.toml         # Project metadata and dependencies
├── requirements.txt        # Dependency list
├── uv.lock                # Dependency lockfile
├── .env                   # Environment variables
└── README.md              # This file

Supported Chains
The server supports the following chains, configured in SUPPORTED_CHAINS:

Ethereum Mainnet: Chain ID 1, native token ETH
Polygon: Chain ID 137, native token MATIC
Arbitrum One: Chain ID 42161, native token ETH
Optimism: Chain ID 10, native token ETH

Each chain uses reliable RPC endpoints (e.g., Infura or Alchemy) with retry logic to ensure connectivity.
API Endpoints
The server exposes endpoints via the MCP protocol (bridge:// scheme). Key endpoints include:

bridge://config/chains: Lists supported chains and their configurations.
bridge://get_transaction_history: Retrieves transaction history for an address.
Parameters: address (string), chain (string, optional, default: "ethereum")
Example: {"address": "0x123...", "chain": "polygon"}


bridge://estimate_bridge_fees: Estimates fees for a cross-chain transfer.
bridge://initiate_bridge: Initiates a new bridge transaction.
bridge://monitor_transaction: Monitors the status of a transaction.
bridge://get_bridge_status: Returns bridge status and liquidity.

Use the MCP Inspector (mcp dev) to explore all endpoints interactively.
Troubleshooting

Error: name 'geth_poa_middleware' is not defined:

Ensure server.py does not reference geth_poa_middleware. The _app_lifespan method should not include middleware injection for Polygon.
Clear Python cache: del /s server\__pycache__.


Error: 'AppContext' object is not subscriptable:

Verify that handler methods (e.g., get_transaction_history) use dot notation (context.web3_connections) instead of dictionary access (context["web3_connections"]).


Failed to Connect to Networks:

Test RPC endpoints:from web3 import Web3
chains = {
    "ethereum": "https://mainnet.infura.io/v3/your_infura_project_id",
    "polygon": "https://polygon-mainnet.infura.io/v3/your_infura_project_id",
    "arbitrum": "https://arbitrum-mainnet.infura.io/v3/your_infura_project_id",
    "optimism": "https://optimism-mainnet.infura.io/v3/your_infura_project_id"
}
for chain, url in chains.items():
    w3 = Web3(Web3.HTTPProvider(url))
    print(f"{chain}: {w3.is_connected()}")

Save as test_rpcs.py and run uv run python test_rpcs.py.
If connections fail, verify your INFURA_PROJECT_ID or switch to Alchemy RPCs.
Check network settings (firewall, VPN, proxy).


Authentication Errors:

If AUTH_ISSUER_URL is not set up, bypass authentication by removing auth and token_verifier from FastMCP initialization in server.py.


Database Issues:

Ensure server/bridge.db exists and the transactions table is created by _initialize_db.
Test database:import sqlite3
conn = sqlite3.connect("server/bridge.db")
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
print(cursor.fetchall())

Run uv run python test_db.py.



Contributing
Contributions are welcome! To contribute:

Fork the repository (if hosted on GitHub).
Create a feature branch: git checkout -b feature/your-feature.
Commit changes: git commit -m "Add your feature".
Push to the branch: git push origin feature/your-feature.
Open a pull request.

Please include tests and update documentation as needed.
License
This project is licensed under the MIT License. See the LICENSE file for details.