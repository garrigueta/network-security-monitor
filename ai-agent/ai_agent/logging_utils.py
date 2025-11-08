"""Comprehensive logging utilities for service and AI actions"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime
import structlog
from structlog.processors import JSONRenderer
from structlog.dev import ConsoleRenderer

from .config import settings


class ActionLogger:
    """Centralized logger for tracking service and AI actions"""
    
    ACTION_TYPES = {
        "SERVICE": "service_action",
        "AI": "ai_action",
        "API": "api_request",
        "DATA": "data_collection",
        "ERROR": "error"
    }
    
    @staticmethod
    def log_service_action(
        logger: structlog.BoundLogger,
        action: str,
        status: str = "started",
        **kwargs
    ):
        """
        Log a service action (e.g., API call, data fetch, report generation)
        
        Args:
            logger: Structured logger instance
            action: Description of the action
            status: Action status (started, completed, failed)
            **kwargs: Additional context fields
        """
        log_data = {
            "action_type": ActionLogger.ACTION_TYPES["SERVICE"],
            "action": action,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            **kwargs
        }
        
        if status == "failed":
            logger.error("Service action", **log_data)
        elif status == "completed":
            logger.info("Service action", **log_data)
        else:
            logger.info("Service action", **log_data)
    
    @staticmethod
    def log_ai_action(
        logger: structlog.BoundLogger,
        action: str,
        model: str,
        prompt_length: Optional[int] = None,
        response_length: Optional[int] = None,
        duration_ms: Optional[float] = None,
        status: str = "completed",
        **kwargs
    ):
        """
        Log an AI model action (e.g., query, analysis, generation)
        
        Args:
            logger: Structured logger instance
            action: AI action type (query, analysis, generation)
            model: Model name used
            prompt_length: Length of prompt in characters
            response_length: Length of response in characters
            duration_ms: Time taken in milliseconds
            status: Action status
            **kwargs: Additional context fields
        """
        log_data = {
            "action_type": ActionLogger.ACTION_TYPES["AI"],
            "ai_action": action,
            "model": model,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        if prompt_length is not None:
            log_data["prompt_length"] = prompt_length
        if response_length is not None:
            log_data["response_length"] = response_length
        if duration_ms is not None:
            log_data["duration_ms"] = duration_ms
        
        log_data.update(kwargs)
        
        if status == "failed":
            logger.error("AI action", **log_data)
        else:
            logger.info("AI action", **log_data)
    
    @staticmethod
    def log_api_request(
        logger: structlog.BoundLogger,
        endpoint: str,
        method: str,
        status_code: Optional[int] = None,
        duration_ms: Optional[float] = None,
        client_ip: Optional[str] = None,
        **kwargs
    ):
        """
        Log an API request/response
        
        Args:
            logger: Structured logger instance
            endpoint: API endpoint path
            method: HTTP method
            status_code: Response status code
            duration_ms: Request duration in milliseconds
            client_ip: Client IP address
            **kwargs: Additional context fields
        """
        log_data = {
            "action_type": ActionLogger.ACTION_TYPES["API"],
            "endpoint": endpoint,
            "method": method,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        if status_code is not None:
            log_data["status_code"] = status_code
        if duration_ms is not None:
            log_data["duration_ms"] = duration_ms
        if client_ip is not None:
            log_data["client_ip"] = client_ip
        
        log_data.update(kwargs)
        
        if status_code and status_code >= 400:
            logger.warning("API request", **log_data)
        else:
            logger.info("API request", **log_data)
    
    @staticmethod
    def log_data_collection(
        logger: structlog.BoundLogger,
        source: str,
        action: str,
        records_count: Optional[int] = None,
        duration_ms: Optional[float] = None,
        status: str = "completed",
        **kwargs
    ):
        """
        Log data collection activities
        
        Args:
            logger: Structured logger instance
            source: Data source name (loki, prometheus, honeypot, etc.)
            action: Collection action
            records_count: Number of records retrieved
            duration_ms: Collection duration in milliseconds
            status: Collection status
            **kwargs: Additional context fields
        """
        log_data = {
            "action_type": ActionLogger.ACTION_TYPES["DATA"],
            "data_source": source,
            "data_action": action,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        if records_count is not None:
            log_data["records_count"] = records_count
        if duration_ms is not None:
            log_data["duration_ms"] = duration_ms
        
        log_data.update(kwargs)
        
        if status == "failed":
            logger.error("Data collection", **log_data)
        else:
            logger.info("Data collection", **log_data)


def setup_file_logging() -> Optional[logging.Handler]:
    """Setup file logging with rotation if enabled"""
    if not settings.log_to_file or not settings.log_file:
        return None
    
    try:
        # Create log directory if it doesn't exist
        log_path = Path(settings.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Parse rotation size
        size_str = settings.log_rotation_size.upper()
        multipliers = {"KB": 1024, "MB": 1024**2, "GB": 1024**3}
        max_bytes = 10 * 1024 * 1024  # Default 10MB
        
        for suffix, multiplier in multipliers.items():
            if suffix in size_str:
                try:
                    size_num = float(size_str.replace(suffix, "").strip())
                    max_bytes = int(size_num * multiplier)
                except ValueError:
                    pass
                break
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            filename=settings.log_file,
            maxBytes=max_bytes,
            backupCount=settings.log_retention_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        
        return file_handler
        
    except Exception as e:
        print(f"Warning: Could not setup file logging: {e}", file=sys.stderr)
        return None


def configure_logging():
    """Configure structured logging for the application"""
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    # Add appropriate renderer based on format
    if settings.log_format == "json":
        processors.append(JSONRenderer())
    else:
        processors.append(ConsoleRenderer())
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Setup standard library logging
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        handlers=[]
    )
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    logging.root.addHandler(console_handler)
    
    # Add file handler if enabled
    file_handler = setup_file_logging()
    if file_handler:
        logging.root.addHandler(file_handler)
        logger = structlog.get_logger()
        logger.info(
            "File logging enabled",
            log_file=settings.log_file,
            rotation_size=settings.log_rotation_size,
            retention_count=settings.log_retention_count
        )
    
    return structlog.get_logger()


# Initialize logging on module import
configure_logging()
