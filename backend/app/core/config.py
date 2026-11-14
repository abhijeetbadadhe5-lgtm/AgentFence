"""AgentFence Configuration & Settings
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_DIR = BASE_DIR / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
SQLITE_PATH = DB_DIR / "agentfence.db"

class Settings:
    PROJECT_NAME: str = "AgentFence"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Delegation-Aware AI Agent Security Gateway for Model Context Protocol (MCP)"
    
    # Server Binding
    HOST: str = os.getenv("AGENTFENCE_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("AGENTFENCE_PORT", "8000"))
    DEBUG: bool = os.getenv("AGENTFENCE_DEBUG", "True").lower() == "true"
    
    # Security & Cryptography
    SECRET_KEY: str = os.getenv("AGENTFENCE_SECRET_KEY", "agentfence-dev-secret-key-32bytes-min-change-in-prod-xyz123")
    ALGORITHM: str = os.getenv("AGENTFENCE_ALGORITHM", "HS256")
    TOKEN_ISSUER: str = os.getenv("AGENTFENCE_ISSUER", "https://auth.agentfence.internal")
    DEFAULT_AUDIENCE: str = os.getenv("AGENTFENCE_AUDIENCE", "agentfence-gateway-v1")
    DEFAULT_TOKEN_EXPIRY_MINUTES: int = int(os.getenv("AGENTFENCE_TOKEN_EXPIRY", "60"))
    MAX_DELEGATION_DEPTH: int = int(os.getenv("AGENTFENCE_MAX_DEPTH", "3"))
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{SQLITE_PATH.as_posix()}")
    
    # MCP Gateway Settings
    UPSTREAM_MCP_HOST: str = os.getenv("UPSTREAM_MCP_HOST", "127.0.0.1")
    UPSTREAM_MCP_PORT: int = int(os.getenv("UPSTREAM_MCP_PORT", "8001"))
    UPSTREAM_ALLOWLIST: list = [
        "http://127.0.0.1:8001",
        "http://localhost:8001",
        "mock://sample-upstream-mcp"
    ]
    
    # Audit Integrity
    AUDIT_GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"

settings = Settings()
