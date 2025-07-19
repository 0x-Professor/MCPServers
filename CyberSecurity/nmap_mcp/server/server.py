import os
import asyncio
import logging
import sqlite3
import nmap
from datetime import datetime
from contextlib import asynccontextmanager
from typing import List, Dict, Any
from pydantic import BaseModel, Field, validator
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent
from mcp.server.auth.provider import TokenVerifier, TokenInfo
from mcp.server.auth.settings import AuthSettings
import aiohttp
from aiohttp import web
from dotenv import load_dotenv
import shodan

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Initialize Shodan API
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
try:
    shodan_api = shodan.Shodan(SHODAN_API_KEY)
except shodan.APIError as e:
    logger.error(f"Shodan API initialization failed: {str(e)}")
    shodan_api = None