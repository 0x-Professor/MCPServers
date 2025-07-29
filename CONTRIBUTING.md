# Contributing to MCP Servers

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

We're thrilled that you're interested in contributing to the MCP Servers project! This document provides comprehensive guidelines for contributing to our cutting-edge Model Context Protocol server infrastructure for blockchain, AI automation, and cybersecurity.

## 🌟 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Contribution Types](#contribution-types)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Security Guidelines](#security-guidelines)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

## 📋 Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [mr.mazharsaeed790@gmail.com](mailto:mr.mazharsaeed790@gmail.com).

## 🚀 Getting Started

### Prerequisites

- **Python**: 3.8 or higher
- **uv**: Package manager (recommended) - [Install uv](https://github.com/astral-sh/uv)
- **Git**: Version control
- **Docker**: Optional for containerized development
- **Nmap**: Required for cybersecurity components (Linux/WSL)

### Required API Keys

Obtain the following API keys for full functionality:

- **Blockchain**: Alchemy, Etherscan, Infura, OpenSea
- **Security**: Shodan, Unizo EDR/XDR
- **Authentication**: OAuth 2.1 provider (optional for development)

## 🏗️ Development Environment

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
git clone https://github.com/YOUR_USERNAME/MCPServers.git
cd MCPServers
```

### 2. Environment Setup

```bash
# Install uv package manager
pip install uv

# Create virtual environment
uv venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/macOS

# Install development dependencies
uv add -r requirements-dev.txt
```

### 3. Environment Configuration

Create `.env` files in each server directory:

```env
# Example .env for blockchain servers
ALCHEMY_API_KEY=your_alchemy_key
ETHERSCAN_API_KEY=your_etherscan_key
INFURA_PROJECT_ID=your_infura_id
OPENSEA_API_KEY=your_opensea_key

# Example .env for cybersecurity servers
SHODAN_API_KEY=your_shodan_key
UNIZO_API_KEY=your_unizo_key

# Development settings
LOG_LEVEL=DEBUG
ENVIRONMENT=development
```

## 📁 Project Structure

```
MCPServers/
├── BlockChain/                     # Blockchain MCP servers
│   ├── cross_chain_bridge_assistant/
│   ├── nft_marketPlace_assistant/
│   ├── mcp_smart_contract_auditor/
│   └── mcp-crypto-wallet/
├── CyberSecurity/                  # Cybersecurity MCP servers
│   ├── nmap_mcp/
│   └── ComplianceMCP/
├── docs/                          # Documentation
├── tests/                         # Test suites
├── scripts/                       # Utility scripts
├── CONTRIBUTING.md               # This file
├── CODE_OF_CONDUCT.md           # Community guidelines
├── SECURITY.md                  # Security policy
└── LICENSE                      # MIT License
```

## 🎯 Contribution Types

### 🔧 Core Development

- **New MCP Servers**: Implement additional blockchain/security servers
- **Feature Enhancement**: Extend existing server capabilities
- **Performance Optimization**: Improve server performance and scalability
- **API Improvements**: Enhance MCP protocol compliance and API design

### 🐛 Bug Fixes

- **Security Vulnerabilities**: Critical security fixes (see [SECURITY.md](SECURITY.md))
- **Functional Issues**: Bugs affecting server functionality
- **Performance Issues**: Memory leaks, slow operations, resource usage
- **Compatibility**: Cross-platform and dependency compatibility

### 📚 Documentation

- **API Documentation**: OpenAPI/Swagger specifications
- **User Guides**: Setup, configuration, and usage tutorials
- **Developer Documentation**: Architecture, patterns, and best practices
- **Examples**: Sample implementations and use cases

### 🧪 Testing

- **Unit Tests**: Test individual components and functions
- **Integration Tests**: Test server interactions and workflows
- **Security Tests**: Penetration testing and vulnerability assessments
- **Performance Tests**: Load testing and benchmarking

## 🔄 Development Workflow

### 1. Issue First

- **Search Existing Issues**: Check if the issue already exists
- **Create Detailed Issues**: Use our issue templates
- **Get Approval**: Wait for maintainer approval for major changes

### 2. Branch Strategy

```bash
# Create feature branch from main
git checkout main
git pull origin main
git checkout -b feature/your-feature-name

# For different contribution types:
git checkout -b feature/new-solana-server      # New features
git checkout -b bugfix/fix-bridge-fees         # Bug fixes
git checkout -b docs/update-api-docs           # Documentation
git checkout -b security/patch-sql-injection   # Security fixes
```

### 3. Development Process

```bash
# Make your changes
# Write tests
# Update documentation

# Run quality checks
uv run black .                    # Code formatting
uv run flake8                     # Linting
uv run mypy .                     # Type checking
uv run pytest tests/              # Run tests
uv run safety check               # Security scan
```

### 4. Commit Standards

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: type(scope): description
git commit -m "feat(bridge): add Solana bridge support"
git commit -m "fix(nft): resolve metadata caching issue"
git commit -m "docs(api): update OpenAPI specifications"
git commit -m "security(auth): patch OAuth token validation"
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `security`, `perf`

## 📏 Coding Standards

### Python Code Style

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with additional guidelines:

```python
# Use Black for formatting (line length: 88)
# Use type hints for all functions
from typing import Dict, List, Optional, Union
import asyncio
from pydantic import BaseModel, Field

class ServerConfig(BaseModel):
    """Server configuration model with validation."""
    
    server_name: str = Field(..., description="MCP server name")
    port: int = Field(3001, ge=1024, le=65535)
    debug: bool = Field(False, description="Enable debug mode")
    api_keys: Dict[str, str] = Field(default_factory=dict)

async def process_request(
    data: Dict[str, any],
    timeout: Optional[float] = None
) -> Dict[str, any]:
    """
    Process MCP request with proper error handling.
    
    Args:
        data: Request payload
        timeout: Request timeout in seconds
        
    Returns:
        Processed response data
        
    Raises:
        ValidationError: Invalid request data
        TimeoutError: Request timeout exceeded
    """
    # Implementation here
    pass
```

### MCP Server Structure

Follow this pattern for new servers:

```python
from fastmcp import FastMCP
from pydantic import BaseModel
import logging

# Initialize MCP server
mcp = FastMCP("YourServerName")
logger = logging.getLogger(__name__)

class RequestModel(BaseModel):
    """Request validation model."""
    param: str
    optional_param: Optional[int] = None

@mcp.tool()
async def your_tool(request: RequestModel) -> Dict[str, any]:
    """Tool description for MCP inspector."""
    try:
        # Tool implementation
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Tool error: {e}")
        raise

if __name__ == "__main__":
    mcp.run()
```

### Security Best Practices

```python
# Input validation with Pydantic
class SecureInput(BaseModel):
    address: str = Field(..., regex=r"^0x[a-fA-F0-9]{40}$")
    amount: float = Field(..., gt=0, le=1000000)

# Rate limiting
from functools import wraps
import time

def rate_limit(max_calls: int, window: int):
    def decorator(func):
        func._calls = []
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            now = time.time()
            func._calls = [call for call in func._calls if call > now - window]
            
            if len(func._calls) >= max_calls:
                raise Exception("Rate limit exceeded")
            
            func._calls.append(now)
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# Secure API key handling
import os
from cryptography.fernet import Fernet

def get_api_key(service: str) -> str:
    """Securely retrieve API key from environment."""
    key = os.getenv(f"{service.upper()}_API_KEY")
    if not key:
        raise ValueError(f"Missing API key for {service}")
    return key
```

## 🧪 Testing Requirements

### Test Structure

```python
# tests/test_server_name.py
import pytest
from unittest.mock import AsyncMock, patch
from your_server.server import YourServer

class TestYourServer:
    """Test suite for YourServer."""
    
    @pytest.fixture
    async def server(self):
        """Server fixture for testing."""
        return YourServer()
    
    @pytest.mark.asyncio
    async def test_tool_success(self, server):
        """Test successful tool execution."""
        result = await server.your_tool({"param": "value"})
        assert result["status"] == "success"
    
    @pytest.mark.asyncio
    async def test_tool_validation_error(self, server):
        """Test input validation error handling."""
        with pytest.raises(ValidationError):
            await server.your_tool({"invalid": "data"})
    
    @patch('your_server.external_api.call')
    async def test_external_api_error(self, mock_api, server):
        """Test external API error handling."""
        mock_api.side_effect = Exception("API Error")
        
        with pytest.raises(Exception):
            await server.your_tool({"param": "value"})
```

### Test Categories

```bash
# Unit tests - Fast, isolated
uv run pytest tests/unit/ -v

# Integration tests - Slower, with external dependencies
uv run pytest tests/integration/ -v --env=test

# Security tests - Vulnerability and penetration testing
uv run pytest tests/security/ -v

# Performance tests - Load and stress testing
uv run pytest tests/performance/ -v --benchmark-only
```

### Coverage Requirements

- **Minimum Coverage**: 80% for new code
- **Critical Components**: 95% coverage required
- **Security Functions**: 100% coverage required

```bash
# Generate coverage report
uv run pytest --cov=src --cov-report=html --cov-report=term
```

## 🔒 Security Guidelines

### Security Review Process

1. **Automated Scanning**: All PRs scanned with safety, bandit, semgrep
2. **Manual Review**: Security-sensitive changes require manual review
3. **Penetration Testing**: Major features require security testing
4. **Vulnerability Disclosure**: Follow responsible disclosure (see [SECURITY.md](SECURITY.md))

### Security Checklist

- [ ] Input validation with Pydantic models
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (output encoding)
- [ ] Authentication and authorization checks
- [ ] Rate limiting implementation
- [ ] Secure error handling (no sensitive data in logs)
- [ ] API key protection (environment variables)
- [ ] HTTPS enforcement
- [ ] Dependency vulnerability scanning

## 📖 Documentation

### API Documentation

Use OpenAPI/Swagger specifications:

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="MCP Server API",
    description="Model Context Protocol server",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

class ToolRequest(BaseModel):
    """Request model for tool execution."""
    
    param: str = Field(..., description="Required parameter")
    optional: Optional[int] = Field(None, description="Optional parameter")

@app.post("/tools/example", summary="Example tool endpoint")
async def example_tool(request: ToolRequest):
    """
    Execute example tool with specified parameters.
    
    - **param**: Required string parameter
    - **optional**: Optional integer parameter
    
    Returns success status and result data.
    """
    pass
```

### README Requirements

Each server must include:

- [ ] Clear description and purpose
- [ ] Installation instructions
- [ ] Configuration guide
- [ ] Usage examples
- [ ] API documentation links
- [ ] Troubleshooting section
- [ ] Contributing guidelines link

## 🔄 Pull Request Process

### 1. Pre-submission Checklist

- [ ] **Code Quality**: Passes all linting and type checks
- [ ] **Tests**: New code has tests with adequate coverage
- [ ] **Documentation**: Updated relevant documentation
- [ ] **Security**: No security vulnerabilities introduced
- [ ] **Performance**: No significant performance regressions
- [ ] **Backwards Compatibility**: Changes don't break existing APIs

### 2. Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update
- [ ] Security fix

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Security testing completed (if applicable)

## Security Considerations
Describe any security implications

## Breaking Changes
List any breaking changes and migration guide

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No merge conflicts
```

### 3. Review Process

1. **Automated Checks**: CI/CD pipeline must pass
2. **Code Review**: At least one maintainer approval required
3. **Security Review**: Required for security-sensitive changes
4. **Performance Review**: Required for performance-critical changes
5. **Documentation Review**: Required for user-facing changes

### 4. Merge Requirements

- ✅ All CI checks pass
- ✅ Approved by maintainer
- ✅ No unresolved discussions
- ✅ Up-to-date with target branch
- ✅ Commit messages follow conventional format

## 🌍 Community

### Communication Channels

- **GitHub Discussions**: General questions and discussions
- **Issues**: Bug reports and feature requests
- **Email**: Security vulnerabilities ([mr.mazharsaeed790@gmail.com](mailto:mr.mazharsaeed790@gmail.com))
- **Discord**: Community chat (Coming Soon)

### Recognition

Contributors are recognized in:

- **Contributors Section**: README.md acknowledgments
- **Release Notes**: Highlighting significant contributions
- **Hall of Fame**: Outstanding contributors showcase

### Getting Help

- **Documentation**: Check README and API docs first
- **Search Issues**: Look for similar problems
- **Ask Questions**: Use GitHub Discussions
- **Join Community**: Connect with other developers

## 🎖️ Recognition Levels

### Contributor Badges

- 🥉 **Bronze**: 1-5 merged PRs
- 🥈 **Silver**: 6-15 merged PRs or significant feature
- 🥇 **Gold**: 16+ merged PRs or major architectural contribution
- 💎 **Diamond**: Long-term maintainer status

### Hall of Fame

Outstanding contributors who have significantly advanced the project:

- **Muhammad Mazhar Saeed** - Project founder and lead architect
- *Your name could be here!*

## 📄 License

By contributing to MCP Servers, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

## 🙏 Thank You

Thank you for contributing to MCP Servers! Your efforts help build the future of decentralized applications with AI-powered automation and enterprise-grade security.

**Questions?** Reach out to [mr.mazharsaeed790@gmail.com](mailto:mr.mazharsaeed790@gmail.com)

---

*Made with ❤️ by the MCP Servers community*