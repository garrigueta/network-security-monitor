"""Configuration management for the AI Agent"""

import os
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Infrastructure
    monitoring_host: str = Field(default="192.168.1.135", env="MONITORING_HOST")
    grafana_port: int = Field(default=3000, env="GRAFANA_PORT")
    loki_port: int = Field(default=3100, env="LOKI_PORT")
    prometheus_port: int = Field(default=9090, env="PROMETHEUS_PORT")
    
    # Authentication
    grafana_user: str = Field(default="admin", env="GRAFANA_USER")
    grafana_password: str = Field(default="admin", env="GRAFANA_PASSWORD")
    
    # Ollama LLM (Remote)
    ollama_host: str = Field(default="192.168.1.100", env="OLLAMA_HOST")
    ollama_port: int = Field(default=11434, env="OLLAMA_PORT")
    ollama_model: str = Field(default="llama3.1:8b", env="OLLAMA_MODEL")
    
    # AI Agent API
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8080, env="API_PORT")
    mcp_port: int = Field(default=8081, env="MCP_PORT")
    
    # Data Processing
    max_log_entries: int = Field(default=1000, env="MAX_LOG_ENTRIES")
    analysis_window_hours: int = Field(default=24, env="ANALYSIS_WINDOW_HOURS")
    cache_ttl_seconds: int = Field(default=300, env="CACHE_TTL_SECONDS")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    
    # Security
    api_key_header: str = Field(default="X-API-Key", env="API_KEY_HEADER")
    api_key: Optional[str] = Field(default=None, env="API_KEY")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    @property
    def grafana_url(self) -> str:
        return f"http://{self.monitoring_host}:{self.grafana_port}"
    
    @property
    def loki_url(self) -> str:
        return f"http://{self.monitoring_host}:{self.loki_port}"
    
    @property
    def prometheus_url(self) -> str:
        return f"http://{self.monitoring_host}:{self.prometheus_port}"
    
    @property
    def ollama_url(self) -> str:
        return f"http://{self.ollama_host}:{self.ollama_port}"


# Global settings instance
settings = Settings()