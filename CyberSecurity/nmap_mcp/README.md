# Cybersecurity Nmap MCP Server

[![PyPI](https://img.shields.io/pypi/v/mcp.svg)](https://pypi.org/project/mcp/)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Documentation](https://img.shields.io/badge/docs-mcp-blue.svg)](https://docs.modelcontextprotocol.org/)
[![GitHub Discussions](https://img.shields.io/badge/discussions-GitHub-blue.svg)](https://github.com/modelcontextprotocol/python-sdk/discussions)

The **Cybersecurity Nmap MCP Server** is a Model Context Protocol (MCP) server designed for cybersecurity tasks, leveraging Nmap for network scanning and Shodan for real-time vulnerability analysis. Built using the MCP Python SDK, it provides a secure, standardized interface for penetration testing, exposing tools for host discovery, port scanning, service enumeration, OS detection, vulnerability scanning, and firewall analysis. This server is optimized for AI-driven LLM interactions, enabling natural language commands for cybersecurity workflows.

## Overview

This server implements the [Model Context Protocol (MCP)](https://docs.modelcontextprotocol.org/) to expose cybersecurity tools and resources to LLM applications. It uses `FastMCP` from the MCP Python SDK to handle protocol compliance, connection management, and message routing. Key features include:

- **Nmap Integration**: Supports a wide range of Nmap scan types (e.g., TCP SYN, UDP, ACK, Window, Maimon) for comprehensive network analysis.
- **NSE Support**: Executes Nmap Scripting Engine (NSE) scripts (e.g., `vulners`, `http-enum`, `mysql-vuln-cve2012-2122`) for vulnerability detection and service enumeration.
- **Shodan Integration**: Queries the Shodan API for real-time CVE data, enhancing scan results.
- **Security Features**: Includes input validation, rate limiting (15 requests/minute per IP), and OAuth 2.1 authentication.
- **Database**: Stores scan results and vulnerabilities in an SQLite database (`server/cybersecurity.db`).
- **Tools**: Provides a complete pentesting workflow with tools for host discovery, scanning, analysis, and reporting.

## Installation

### Prerequisites

- **Operating System**: Kali Linux (tested on WSL Kali Linux, version 2024.3 or later).
- **Python**: Version 3.8 or later.
- **Nmap**: Version 7.97 or later.
- **uv**: Fast Python package manager (recommended).
- **Shodan API Key**: Provided (`nRkTNilUGNIUJpSmnQQPYIefiCziYQnD`) or obtain one from [Shodan](https://account.shodan.io).
- **Internet Connection**: Required for package installation and Shodan API queries.

### Step 1: Install Nmap
Install and verify Nmap:
```bash
sudo apt update
sudo apt install nmap -y
nmap --version
```
Update NSE scripts:
```bash
sudo nmap --script-updatedb
```

### Step 2: Install uv
Install `uv` for dependency management:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
uv --version
```

### Step 3: Set Up the Project
Create and initialize the project:
```bash
mkdir -p ~/MCPServers/Cybersecurity/nmap_mcp
cd ~/MCPServers/Cybersecurity/nmap_mcp
uv init cybersecurity-nmap-mcp
uv venv
source .venv/bin/activate
```

### Step 4: Install Dependencies
Add required packages using `uv`. This project supports both `python-libnmap` and `python-nmap` libraries:

**Option A: Using python-libnmap (Recommended for cross-platform compatibility):**
```bash
uv add "mcp[cli]>=0.1.2" python-libnmap>=0.7.3 pydantic>=2.0.0 aiohttp>=3.8.6 python-dotenv>=1.0.0 shodan>=1.31.0
```

**Option B: Using python-nmap (Alternative if libnmap doesn't work):**
```bash
uv add "mcp[cli]>=0.1.2" python-nmap>=0.7.1 pydantic>=2.0.0 aiohttp>=3.8.6 python-dotenv>=1.0.0 shodan>=1.31.0
```

> **Note**: If you encounter issues with one library, try the other. The server code is designed to work with both, but compatibility may vary depending on your system configuration.

### Step 5: Configure Environment
Create a `.env` file in the project root:
```bash
echo -e "OAUTH_TOKEN=mock-token-1234567890\nSHODAN_API_KEY=your api key" > .env
```

### Step 6: Save the Server Code
Place the `server.py` file in the `server` directory:
```bash
mkdir -p server
```
Copy the provided `server.py` (from previous responses) to `server/server.py`.

## Running the Server

### Development Mode
Run the server with the MCP Inspector for testing and debugging:
```bash
uv run mcp dev ./server/server.py
```
- Access the MCP Inspector at `http://localhost:3001`.
- Use the web interface to test tools and view results.

### Direct Execution
For custom deployments:
```bash
uv run python ./server/server.py
```

### Streamable HTTP Transport
The server uses the Streamable HTTP transport (recommended for production):
```python
mcp.run(transport="streamable-http")
```
- Supports stateless operation for scalability.
- Mountable in FastAPI applications for multi-server deployments.

## Usage

### Tools
The server exposes the following MCP tools, accessible via HTTP POST requests or the MCP Inspector:

- **`run_nmap_scan`**: Performs Nmap scans with customizable scan types and arguments.
- **`analyze_nmap_results`**: Analyzes scan results with Shodan vulnerability data.
- **`run_nse_vulnerability_scan`**: Executes NSE scripts for vulnerability detection.
- **`run_os_detection`**: Identifies operating systems and versions.
- **`enumerate_services`**: Enumerates detailed service information.
- **`analyze_firewall`**: Detects firewall/IDS configurations.
- **`run_full_pentest_scan`**: Runs a comprehensive pentesting workflow.
- **`run_host_discovery`**: Performs host discovery using ping scans.
- **`run_advanced_nse_scan`**: Executes advanced NSE script combinations.

### Example API Calls
Use `curl` or the MCP Inspector to interact with the server. Ensure the `Authorization` header includes the OAuth token from `.env`.

#### Run NSE Vulnerability Scan
```bash
curl -X POST http://localhost:3001/cyber/run_nse_vulnerability_scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-token-1234567890" \
  -d '{"target": "scanme.nmap.org", "nse_scripts": "vulners,mysql-vuln-cve2012-2122"}'
```

#### Run Full Pentest Scan
```bash
curl -X POST http://localhost:3001/cyber/run_full_pentest_scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-token-1234567890" \
  -d '{"target": "scanme.nmap.org", "nse_scripts": "vulners,http-enum,ftp-anon"}'
```

#### Run Host Discovery
```bash
curl -X POST http://localhost:3001/cyber/run_host_discovery \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-token-1234567890" \
  -d '{"target": "192.168.1.0/24", "scan_type": "-PE"}'
```

### Parameters
- `target`: IP or hostname (e.g., `scanme.nmap.org`, `192.168.1.1`).
- `scan_type`: Nmap scan type (e.g., `-sS`, `-sT`, `-sU`, `-sF`, `-sN`, `-sX`, `-sA`, `-sW`, `-sM`, `-sV`, `-O`, `-PE`, `-PP`).
- `nse_scripts`: Comma-separated NSE scripts (e.g., `vulners,http-enum`).
- `extra_args`: Safe Nmap arguments (e.g., `--spoof-mac 0`, `--data-length 100`).

### Example Output
For `run_nse_vulnerability_scan` on `scanme.nmap.org`:
```
Host: 45.33.32.156 (up)
Port 22/tcp: open (ssh OpenSSH 6.6.1p1 Ubuntu-2ubuntu2.13)
Script vulners: CVE-2018-1000119: OpenSSH 6.6.1p1 vulnerability
Port 80/tcp: open (http Apache httpd 2.4.7)
Script http-enum: /wp-admin/: WordPress admin portal detected
Shodan: Found 2 vulnerabilities for http on port 80
```

## Security Features

- **Input Validation**: Uses Pydantic to validate inputs, preventing injection attacks.
- **Rate Limiting**: Limits to 15 requests per minute per IP, stored in SQLite.
- **Authentication**: Implements OAuth 2.1 with a mock `TokenVerifier` (replace with a real OAuth server for production).
- **Restricted Commands**: Blocks dangerous Nmap arguments (e.g., `--script`, `--output`) and limits NSE scripts to an allowlist.
- **Logging**: Captures scan details without sensitive data (e.g., API keys).

## MCP Integration

The server leverages the MCP Python SDK (`FastMCP`) for protocol compliance:

- **Lifespan Management**: Uses `asynccontextmanager` to initialize Nmap and manage resources.
- **Structured Output**: Returns validated Pydantic models for tools (e.g., `VulnerabilityOutput`, `OSOutput`).
- **Stateless HTTP**: Configured with `stateless_http=True` for scalability.
- **Context Access**: Tools access Nmap via `ctx.request_context.lifespan_context`.

For advanced MCP features (e.g., prompts, resources, completions), see the [MCP Python SDK documentation](https://docs.modelcontextprotocol.org/).

## Troubleshooting

### Nmap Library Compatibility Issues

**If you encounter "Error: 'nmap'" or import errors:**

1. **Try switching between nmap libraries:**
   - If using `python-libnmap`, try switching to `python-nmap`:
     ```bash
     uv remove python-libnmap
     uv add python-nmap>=0.7.1
     ```
   - If using `python-nmap`, try switching to `python-libnmap`:
     ```bash
     uv remove python-nmap
     uv add python-libnmap>=0.7.3
     ```

2. **Update the server imports accordingly:**
   - For `python-libnmap`:
     ```python
     from libnmap.process import NmapProcess
     from libnmap.parser import NmapParser
     ```
   - For `python-nmap`:
     ```python
     import nmap
     ```

### Environment-Specific Issues

- **Nmap Binary Not Found**:
  - **Windows**: Download and install from [nmap.org](https://nmap.org/download.html)
  - **WSL/Linux**: `sudo apt update && sudo apt install nmap -y`
  - **Verify installation**: `nmap --version`
  - **Check PATH**: Ensure nmap is in your system PATH

- **Cross-Platform Compatibility**:
  - **Windows + WSL**: The server automatically detects and tries multiple nmap paths
  - **If WSL nmap works but Windows doesn't**: Run the entire server in WSL
  - **Test nmap accessibility**:
    ```bash
    # For python-nmap
    python3 -c "import nmap; nm = nmap.PortScanner(); print(nm.nmap_version())"
    
    # For python-libnmap
    python3 -c "from libnmap.process import NmapProcess; print('libnmap available')"
    ```

- **Permission Issues**:
  - Add `--unprivileged` flag to nmap arguments if you get permission errors
  - Run with administrator/sudo privileges if needed for advanced scans

### Other Common Issues

- **Shodan API Errors**:
  - Verify API key: `python3 -c "import shodan; api = shodan.Shodan('your_key'); print(api.info())"`
  - Check credits at [Shodan](https://account.shodan.io)

- **WSL Networking Issues**:
  - Test connectivity: `ping scanme.nmap.org`
  - Update WSL: `wsl --update` in PowerShell
  - Check Windows Defender/Firewall settings

- **Server Startup Issues**:
  - Check detailed logs:
    ```bash
    uv run mcp dev ./server/server.py
    ```
  - Verify all dependencies are installed:
    ```bash
    uv sync
    ```

## Legal and Ethical Notes

- **Ethical Usage**: Only scan targets you own or have explicit permission to scan, per [Nmap’s legal guidelines](https://nmap.org/book/legal-issues.html). Unauthorized scanning may violate laws like the U.S. Computer Fraud and Abuse Act (CFAA).
- **Safe Testing**: Use `scanme.nmap.org` for testing, as it’s permitted by Nmap.
- **Secure Deployment**: Replace the mock OAuth token with a real OAuth server for production.

## Contributing

Contributions are welcome! See the [MCP Python SDK contributing guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/CONTRIBUTING.md) for details. To contribute to this server:
1. Fork the repository (if hosted).
2. Create a feature branch (`git checkout -b feature/new-tool`).
3. Commit changes (`git commit -m "Add new tool"`).
4. Push to the branch (`git push origin feature/new-tool`).
5. Open a pull request.

## License

This project is licensed under the [MIT License](https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE).

## About

The Cybersecurity Nmap MCP Server is built using the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) to provide a secure, standardized interface for cybersecurity tasks with Nmap and Shodan. For questions or support, join the [GitHub Discussions](https://github.com/modelcontextprotocol/python-sdk/discussions).