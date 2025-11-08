"""Main entry point for the AI Agent"""

import asyncio
import sys
import uvicorn

from .config import settings
from .api.main import app
from .logging_utils import configure_logging, ActionLogger

# Configure logging with file support
logger = configure_logging()


async def main():
    """Main entry point"""
    ActionLogger.log_service_action(
        logger,
        action="ai_agent_startup",
        status="started",
        api_host=settings.api_host,
        api_port=settings.api_port,
        ollama_url=settings.ollama_url
    )
    
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
        
        ActionLogger.log_service_action(
            logger,
            action="fastapi_server_start",
            status="started",
            host=settings.api_host,
            port=settings.api_port
        )
        
        await server.serve()
        
    except KeyboardInterrupt:
        ActionLogger.log_service_action(
            logger,
            action="ai_agent_shutdown",
            status="completed",
            reason="keyboard_interrupt"
        )
    except Exception as e:
        ActionLogger.log_service_action(
            logger,
            action="ai_agent_error",
            status="failed",
            error=str(e)
        )
        sys.exit(1)
    finally:
        ActionLogger.log_service_action(
            logger,
            action="ai_agent_stopped",
            status="completed"
        )


if __name__ == "__main__":
    asyncio.run(main())