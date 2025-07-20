# ComplianceMCP

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Unizo API](https://img.shields.io/badge/Unizo-API-ff69b4)](https://docs.unizo.ai/)

ComplianceMCP is a Model Context Protocol (MCP) server designed to provide comprehensive compliance monitoring and reporting for various security frameworks including GDPR, HIPAA, PCI-DSS, and ISO27001. It integrates with Unizo's EDR & XDR MCP API to deliver real-time compliance status and security insights.

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
- `pip` package manager

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ComplianceMCP.git
   cd ComplianceMCP
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file and add your Unizo API key:
   ```env
   UNIZO_API_KEY=your_api_key_here
   ```

## 🛠️ Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `UNIZO_API_KEY` | Yes | Your Unizo API key | `7vbUh-dcF6Cpb_UxDXCjUGc6wWXhJxgH` |
| `DATABASE_URL` | No | Database connection URL (default: SQLite) | `sqlite:///compliance.db` |
| `LOG_LEVEL` | No | Logging level (default: INFO) | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## 🚦 Running the Server

Start the MCP server:

```bash
uv run mcp dev server/server.py
```

The server will be available at `http://localhost:6274` by default.

## 📚 API Documentation

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

For questions or support, please contact [your-email@example.com](mailto:your-email@example.com)

---

<div align="center">
  Made with ❤️ by Your Name
</div>
