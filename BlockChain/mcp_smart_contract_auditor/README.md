# MCP Smart Contract Auditor

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-async--ready-green?logo=fastapi)
![Web3](https://img.shields.io/badge/Web3-Ethereum-informational?logo=ethereum)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen)

A next-generation, AI-powered smart contract auditing platform built with FastMCP and Python. This tool leverages advanced static analysis, pattern recognition, and DeFi/security best practices to help developers, auditors, and organizations secure their blockchain applications.

---

## 🚀 Features

- **Automated Vulnerability Detection**: Scans Solidity smart contracts for common and advanced vulnerabilities (reentrancy, overflows, access control, unchecked calls, timestamp dependencies, and more).
- **Gas Optimization Analysis**: Identifies inefficient code patterns and suggests gas-saving improvements.
- **DeFi & Oracle Risk Assessment**: Specialized checks for DeFi protocols, oracles, and MEV exposure.
- **Compliance Checks**: Validates contracts against ERC standards and regulatory best practices (GDPR, SEC, etc.).
- **Attack Simulation**: Simulates common attack vectors (reentrancy, flash loan, front-running, sandwich attacks).
- **Upgradeability & Proxy Analysis**: Detects risks in upgradeable/proxy contract patterns.
- **Continuous Monitoring**: Monitors deployed contracts for changes, suspicious activity, and on-chain events.
- **Modular & Extensible**: Easily add new analysis modules, patterns, or compliance checks.
- **API-First**: Exposes all functionality via a modern FastAPI interface for integration with CI/CD, dashboards, or other tools.

---

## 🧰 MCP Tools Overview

This server exposes a rich suite of tools as API endpoints. Each tool is designed for a specific aspect of smart contract security, gas efficiency, compliance, or DeFi risk. Below is a list of all tools implemented in this MCP server:

| Tool Name                       | Description                                                                                 |
|----------------------------------|---------------------------------------------------------------------------------------------|
| `fetch_contract_code`            | Fetches smart contract source code and bytecode from the blockchain explorer.                |
| `analyze_contract_vulnerabilities` | Analyzes Solidity code for security vulnerabilities using static analysis and pattern matching. |
| `suggest_fixes`                  | Provides actionable fix suggestions for identified vulnerabilities.                          |
| `analyze_gas_efficiency`         | Detects gas inefficiencies and suggests optimizations in contract code.                      |
| `check_compliance`               | Checks code for compliance with ERC standards and regulatory best practices.                 |
| `generate_audit_report`          | Generates a comprehensive audit report including vulnerabilities, gas analysis, and recommendations. |
| `simulate_attacks`               | Simulates attack scenarios (reentrancy, flash loan, front-running, sandwich) on a contract.  |
| `analyze_defi_risks`             | Analyzes DeFi-specific risks for DEX, lending, and yield farming protocols.                  |
| `check_oracle_security`          | Assesses oracle integration security and best practices.                                     |
| `analyze_upgrade_risks`          | Evaluates upgradeable/proxy contract patterns for security risks.                            |
| `check_flash_loan_safety`        | Checks contract safety against flash loan attacks.                                           |
| `analyze_mev_exposure`           | Analyzes contract's exposure to MEV and sandwich attacks.                                    |
| `verify_contract_source`         | Verifies that the provided source code matches the deployed bytecode.                        |
| `generate_security_score`        | Computes an overall security score based on vulnerabilities, gas, and code quality.          |
| `monitor_contract_changes`       | Monitors deployed contracts for changes, suspicious activity, and on-chain events.           |

---

## 🛠️ Installation & Setup

1. **Clone the repository**
   ```sh
   git clone <your-repo-url>
   cd mcp_smart_contract_auditor
   ```

2. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   - Create a `.env` file in the project root:
     ```env
     ETHERSCAN_API_KEY=your_etherscan_api_key
     INFURA_PROJECT_ID=your_infura_project_id
     ```

4. **Run the server**
   ```sh
    .venv\Scripts\activate
    uv add -r requirements.txt
    uv run mcp dev server/server.py
   ```
   - Visit [http://localhost:8000/docs](http://localhost:8000/docs) for the interactive API documentation.

---

## 📚 Usage

- **API Endpoints**: All analysis tools are available as REST endpoints. See `/docs` for details.
- **Analyze a Contract**: Submit Solidity code or a contract address to receive a detailed vulnerability and gas report.
- **Simulate Attacks**: Test your contract against simulated attack scenarios.
- **Compliance & Best Practices**: Check for ERC compliance, code quality, and regulatory alignment.
- **Monitor Contracts**: Set up monitoring for deployed contracts to detect changes or suspicious activity.

---

## 🧠 Example API Calls

- **Analyze Vulnerabilities**
  ```http
  POST /analyze_contract_vulnerabilities
  {
    "code": "<solidity source code>",
    "contract_name": "MyToken"
  }
  ```

- **Fetch Contract Code**
  ```http
  POST /fetch_contract_code
  {
    "address": "0x...",
    "chain": "ethereum"
  }
  ```

- **Simulate Attacks**
  ```http
  POST /simulate_attacks
  {
    "contract_address": "0x...",
    "attack_types": ["reentrancy", "flash_loan"]
  }
  ```

---

## 🧩 Architecture

- **Python 3.8+**
- **FastAPI** (via FastMCP)
- **Async/Await** for high concurrency
- **Modular Tooling**: Each analysis is a separate tool, easily extendable
- **Web3 & Etherscan Integration**: For on-chain and source code analysis

---

## 🌐 Vision & Roadmap

- **AI-Driven Auditing**: Integrate LLMs for deeper code understanding and zero-day vulnerability detection.
- **On-Chain Monitoring**: Real-time alerts for suspicious contract activity.
- **Multi-Chain Support**: Expand to more EVM and non-EVM chains.
- **Developer Dashboard**: Web UI for managing audits, reports, and monitoring.
- **Marketplace Integration**: Connect with bug bounty and audit marketplaces.
- **Continuous Learning**: System improves as new vulnerabilities and patterns emerge.

---

## 🤝 Contributing

We welcome contributions! Please open issues or pull requests for new features, bug fixes, or improvements.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

---

## 🦾 Futuristic Goals

- **Autonomous Security Agents**: Bots that monitor, patch, and defend contracts in real time.
- **Explainable Audits**: Human-readable, AI-generated explanations for every finding.
- **Seamless DevOps Integration**: Plug auditing into your CI/CD pipeline with zero friction.
- **Community-Driven Patterns**: Open registry of new vulnerability patterns and best practices.

---

**Secure the future of Web3 with MCP Smart Contract Auditor!**
