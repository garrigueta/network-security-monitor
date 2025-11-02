"""FastAPI application for the AI Agent"""

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import structlog

from ..config import settings
from ..mcp.server import mcp_server
from ..ai_engine import AIEngine
from ..data_sources import DataCollector
from ..reports.generator import ReportGenerator
from ..reports.scheduler import ReportScheduler
from ..reports.models import (
    ReportLevel, ReportRequest, ReportListResponse, ReportConfiguration, ReportMetadata
)
from .models import (
    HealthResponse,
    AnalysisRequest,
    AnalysisResponse,
    QueryRequest,
    QueryResponse
)

logger = structlog.get_logger()
security = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting AI Agent API...")
    
    # Initialize AI engine
    app.state.ai_engine = AIEngine()
    await app.state.ai_engine.initialize()
    
    # Initialize data sources
    app.state.data_sources = DataCollector()
    
    # Initialize report generator
    app.state.report_generator = ReportGenerator(
        ai_engine=app.state.ai_engine,
        data_sources=app.state.data_sources
    )
    
    # Initialize and start report scheduler
    app.state.report_scheduler = ReportScheduler(
        report_generator=app.state.report_generator,
        config=ReportConfiguration()
    )
    await app.state.report_scheduler.start()
    
    logger.info("AI Agent API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down AI Agent API...")
    if hasattr(app.state, 'report_scheduler'):
        await app.state.report_scheduler.stop()
    if hasattr(app.state, 'ai_engine'):
        await app.state.ai_engine.close()
    logger.info("AI Agent API shut down")


# Create FastAPI app
app = FastAPI(
    title="Network Security AI Agent",
    description="AI-powered analysis of network security infrastructure",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify API key if configured"""
    if settings.api_key:
        if not credentials or credentials.credentials != settings.api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")
    return True


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        services={
            "api": "running",
            "mcp_server": "running",
            "ai_engine": "running" if hasattr(app.state, 'ai_engine') else "starting"
        }
    )


@app.post("/analyze/honeypot", response_model=AnalysisResponse)
async def analyze_honeypot(
    request: AnalysisRequest,
    _: bool = Depends(verify_api_key)
):
    """Analyze honeypot activity and threats"""
    try:
        ai_engine = app.state.ai_engine
        
        analysis = await ai_engine.analyze_honeypot(
            timeframe=request.timeframe,
            focus_areas=request.focus_areas
        )
        
        return AnalysisResponse(
            success=True,
            analysis=analysis,
            timestamp=analysis.get("timestamp"),
            metadata={"source": "honeypot", "timeframe": request.timeframe}
        )
        
    except Exception as e:
        logger.error(f"Error analyzing honeypot: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/network", response_model=AnalysisResponse)
async def analyze_network(
    request: AnalysisRequest,
    _: bool = Depends(verify_api_key)
):
    """Analyze network security and system metrics"""
    try:
        ai_engine = app.state.ai_engine
        
        analysis = await ai_engine.analyze_network(
            timeframe=request.timeframe,
            focus_areas=request.focus_areas
        )
        
        return AnalysisResponse(
            success=True,
            analysis=analysis,
            timestamp=analysis.get("timestamp"),
            metadata={"source": "network", "timeframe": request.timeframe}
        )
        
    except Exception as e:
        logger.error(f"Error analyzing network: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/query", response_model=QueryResponse)
async def natural_language_query(
    request: QueryRequest,
    _: bool = Depends(verify_api_key)
):
    """Process natural language queries about security data"""
    try:
        ai_engine = app.state.ai_engine
        
        response = await ai_engine.process_query(
            query=request.query,
            context=request.context
        )
        
        return QueryResponse(
            success=True,
            response=response["response"],
            sources=response.get("sources", []),
            timestamp=response.get("timestamp"),
            metadata=response.get("metadata", {})
        )
        
    except Exception as e:
        logger.error(f"Error processing query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/mcp/tools")
async def list_mcp_tools(_: bool = Depends(verify_api_key)):
    """List available MCP tools"""
    try:
        tools = mcp_server.tools
        return {
            "tools": [
                {
                    "name": name,
                    "description": tool["description"],
                    "parameters": tool["parameters"]
                }
                for name, tool in tools.items()
            ]
        }
    except Exception as e:
        logger.error(f"Error listing MCP tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/openapi.yaml", include_in_schema=False)
async def get_openapi_yaml():
    """Serve the OpenAPI specification in YAML format"""
    from fastapi.responses import FileResponse
    import os
    
    yaml_path = os.path.join(os.path.dirname(__file__), "..", "..", "openapi.yaml")
    if os.path.exists(yaml_path):
        return FileResponse(
            path=yaml_path,
            media_type="application/x-yaml",
            filename="openapi.yaml"
        )
    else:
        raise HTTPException(status_code=404, detail="OpenAPI specification not found")


# Report Management Endpoints

@app.post("/reports/generate", response_model=dict)
async def generate_report(request: ReportRequest, _: bool = Depends(verify_api_key)):
    """Generate a new security report"""
    try:
        report = await app.state.report_generator.generate_report(
            level=request.level,
            period_hours=request.period_hours,
            focus_areas=request.focus_areas
        )
        
        return {
            "success": True,
            "report_id": report.metadata.id,
            "level": report.metadata.level,
            "status": report.metadata.status,
            "download_url": f"/reports/{report.metadata.id}/export?format={request.export_format}"
        }
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reports", response_model=ReportListResponse)
async def list_reports(
    level: Optional[ReportLevel] = None,
    page: int = 1,
    page_size: int = 50,
    _: bool = Depends(verify_api_key)
):
    """List generated reports with filtering"""
    logger.info(f"List reports called with level={level}, page={page}")
    
    # Read reports from filesystem
    reports = []
    reports_dir = Path("reports")
    
    logger.info(f"Reports dir exists: {reports_dir.exists()}, path: {reports_dir.absolute()}")
    
    if reports_dir.exists():
        files_found = list(reports_dir.glob("*.json"))
        logger.info(f"Found {len(files_found)} JSON files")
        
        for report_file in files_found:
            try:
                with open(report_file, "r") as f:
                    report_data = json.load(f)
                
                # Extract metadata from report
                metadata = report_data.get("metadata", {})
                if metadata:
                    report_metadata = ReportMetadata(**metadata)
                    
                    # Apply level filter if specified
                    if level is None or report_metadata.level == level:
                        reports.append(report_metadata)
                        logger.info(f"Added report {report_metadata.id}")
                        
            except Exception as e:
                logger.warning(f"Failed to read report {report_file}: {e}")
                continue
    
    logger.info(f"Total reports loaded: {len(reports)}")
    
    # Sort by creation time (newest first)
    reports.sort(key=lambda r: r.created_at, reverse=True)
    
    # Apply pagination
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_reports = reports[start_idx:end_idx]
    
    return ReportListResponse(
        reports=paginated_reports,
        total=len(reports),
        page=page,
        page_size=page_size,
        filters={"level": level} if level else {}
    )


@app.get("/reports/{report_id}")
async def get_report(report_id: str, _: bool = Depends(verify_api_key)):
    """Get a specific report"""
    try:
        import json
        from pathlib import Path
        
        report_file = Path("reports") / f"{report_id}.json"
        if not report_file.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        
        with open(report_file, "r") as f:
            report_data = json.load(f)
        
        return report_data
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")
    except Exception as e:
        logger.error(f"Error retrieving report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reports/{report_id}/export")
async def export_report(
    report_id: str, 
    format: str = "json",
    _: bool = Depends(verify_api_key)
):
    """Export report in specified format"""
    try:
        if format not in ["json", "html", "pdf"]:
            raise HTTPException(status_code=400, detail="Unsupported export format")
        
        exported_content = await app.state.report_generator.export_report(report_id, format)
        
        if format == "json":
            from fastapi.responses import JSONResponse
            import json
            return JSONResponse(content=json.loads(exported_content))
        elif format == "html":
            from fastapi.responses import HTMLResponse
            return HTMLResponse(content=exported_content)
        else:  # PDF - would need additional implementation
            raise HTTPException(status_code=501, detail="PDF export not yet implemented")
            
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")
    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reports/schedule/status")
async def get_schedule_status(_: bool = Depends(verify_api_key)):
    """Get report scheduler status and upcoming jobs"""
    try:
        is_running = app.state.report_scheduler.is_running()
        jobs = app.state.report_scheduler.get_scheduled_jobs()
        
        return {
            "scheduler_running": is_running,
            "scheduled_jobs": jobs,
            "total_jobs": len(jobs)
        }
    except Exception as e:
        logger.error(f"Error getting schedule status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/reports/schedule/trigger")
async def trigger_manual_report(
    level: ReportLevel,
    period_hours: int = 24,
    _: bool = Depends(verify_api_key)
):
    """Manually trigger report generation"""
    try:
        report_id = await app.state.report_scheduler.trigger_manual_report(level, period_hours)
        
        return {
            "success": True,
            "report_id": report_id,
            "message": f"Manual {level.value} report generation triggered"
        }
    except Exception as e:
        logger.error(f"Error triggering manual report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ai_agent.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
        log_level=settings.log_level.lower()
    )