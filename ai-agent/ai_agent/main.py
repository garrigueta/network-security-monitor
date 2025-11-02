"""Main entry point for the AI Agent"""

import asyncio
import sys
import structlog
import uvicorn

from .config import settings
from .api.main import app

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer() if settings.log_format == "json" else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


async def main():
    """Main entry point"""
    logger.info("Starting Network Security AI Agent")
    logger.info(f"Configuration: API={settings.api_host}:{settings.api_port}, Ollama={settings.ollama_url}")
    
    try:
        # Start the FastAPI server
        config = uvicorn.Config(
            app=app,
            host=settings.api_host,
            port=settings.api_port,
            log_level=settings.log_level.lower(),
            reload=False  # Set to True for development
        )
        
        server = uvicorn.Server(config)
        await server.serve()
        
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)
    finally:
        logger.info("AI Agent stopped")


if __name__ == "__main__":
    asyncio.run(main())