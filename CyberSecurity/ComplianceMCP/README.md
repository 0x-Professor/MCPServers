# ComplianceMCP

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Unizo API](https://img.shields.io/badge/Unizo-API-ff69b4)](https://docs.unizo.ai/)
[![UV](https://img.shields.io/badge/UV-Enabled-9cf)](https://github.com/astral-sh/uv)

ComplianceMCP is a Model Context Protocol (MCP) server designed to provide comprehensive compliance monitoring and reporting for various security frameworks including GDPR, HIPAA, PCI-DSS, and ISO27001. It integrates with Unizo's EDR & XDR MCP API to deliver real-time compliance status and security insights.

> **Note**: This project uses [UV](https://github.com/astral-sh/uv) for package management and environment management, providing faster and more reliable dependency resolution.

## ✨ Features

- **Multi-Framework Support**: Monitor compliance across GDPR, HIPAA, PCI-DSS, and ISO27001
- **Real-time Alerts**: Get immediate notifications for compliance violations
- **Security Integration**: Seamless integration with Unizo's security platform
- **Detailed Reporting**: Comprehensive compliance reports with actionable insights
- **RESTful API**: Easy integration with existing security tools and workflows

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Unizo API key
- [UV](https://github.com/astral-sh/uv) (recommended) or `pip`

### Installation with UV (Recommended)

1. Install UV (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   Or using pip:
   ```bash
   pip install uv
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/0x-Professor/MCPServers.git 
   cd MCPServers\CyberSecurity\ComplianceMCP
   ```

3. Create and activate a virtual environment with UV:
   ```bash
   uv venv .venv
   # On Windows:
   .venv\\Scripts\\activate
   # On Unix/macOS:
   source .venv/bin/activate
   ```

4. Install dependencies with UV:
   ```bash
   uv pip install -r requirements.txt
   ```

5. Create a `.env` file and add your Unizo API key:
   ```env
   UNIZO_API_KEY=your_api_key_here
   ```

### Installation with pip (Alternative)

If you prefer to use pip instead of UV:

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\\venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt
```

## 🛠️ Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `UNIZO_API_KEY` | Yes | Your Unizo API key | `7vbUh-dcF6Cpb_UxDXCjUGc6wWXhJxgH` |
| `DATABASE_URL` | No | Database connection URL (default: SQLite) | `sqlite:///compliance.db` |
| `LOG_LEVEL` | No | Logging level (default: INFO) | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## 🚦 Running the Server

### With UV (Recommended)

```bash
uv run mcp dev server/server.py
```

### With Python Directly

```bash
python -m mcp server/server.py
```

The server will be available at `http://localhost:6274` by default.

## 🛠️ Tools and Resources

### Available Tools

1. **Check Compliance Status**
   - **Endpoint**: `GET /compliance/{framework}`
   - **Description**: Check compliance status for a specific framework
   - **Frameworks Supported**: GDPR, HIPAA, PCI-DSS, ISO27001
   - **Example**:
     ```bash
     curl -X GET "http://localhost:6274/compliance/GDPR"
     ```

2. **Get Policy Document**
   - **Endpoint**: `GET /policy/{policy_id}`
   - **Description**: Retrieve a specific policy document
   - **Example**:
     ```bash
     curl -X GET "http://localhost:6274/policy/gdpr_privacy_policy"
     ```

3. **Get Vendor Profile**
   - **Endpoint**: `GET /vendor/{vendor_id}`
   - **Description**: Get compliance information for a specific vendor
   - **Example**:
     ```bash
     curl -X GET "http://localhost:6274/vendor/aws"
     ```

### Resource Endpoints

1. **List All Policies**
   ```http
   GET /policies
   ```

2. **Get Compliance Report**
   ```http
   GET /report/{framework}
   ```

3. **Check System Health**
   ```http
   GET /health
   ```

## 📝 Prompts and Usage Examples

### Common Workflows

1. **Check GDPR Compliance**
   ```bash
   curl -X GET "http://localhost:6274/compliance/GDPR"
   ```

2. **Generate Compliance Report**
   ```bash
   curl -X GET "http://localhost:6274/report/HIPAA" -o hipaa_report.pdf
   ```

3. **Monitor Compliance Status**
   ```bash
   # Check status every 5 minutes
   watch -n 300 'curl -s http://localhost:6274/health | jq .'
   ```

### API Response Format

All API responses follow this standard format:

```json
{
    "status": "success|error",
    "data": {},
    "message": "Descriptive message",
    "timestamp": "2025-07-20T09:30:00Z"
}
```

## 🔄 UV-Specific Commands

### Managing Dependencies

```bash
# Add a new package
uv pip install package_name

# Update all dependencies
uv pip compile --upgrade

# Freeze current dependencies
uv pip freeze > requirements.txt
```

### Running Tests

```bash
uv run pytest tests/
```

### Linting

```bash
uv run black .
uv run flake8
```

## 📚 API Documentation

For detailed API documentation, including all available endpoints, request/response formats, and examples, please see the [API Documentation](API_DOCS.md).

### Key API Features

### Check Compliance Status

```http
GET /compliance/{framework}
```

**Parameters:**
- `framework` (required): The compliance framework to check (GDPR, HIPAA, PCI-DSS, ISO27001)

**Example Response:**
```json
{
    "status": "Compliant",
    "last_updated": "2025-07-20T09:30:00Z",
    "alerts_count": 0,
    "source": "unizo",
    "details": "No compliance violations detected"
}
```

### Get Policy Document

```http
GET /policy/{policy_id}
```

**Parameters:**
- `policy_id` (required): The ID of the policy document to retrieve

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📧 Contact

For questions or support, please contact [mr.mazharsaeed790@gmail.com](mailto:mr.mazharsaeed790@gmail.com)

---

<div align="center">
  Made with ❤️ by Mazhar Saeed aka Professor
</div>
