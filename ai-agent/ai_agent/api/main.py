"""FastAPI application for the AI Agent"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
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


@app.get("/reports/latest/full")
async def get_latest_report():
    """Return the most recently generated report with full content (public endpoint for Grafana)"""
    reports_dir = Path("reports")

    if not reports_dir.exists():
        # Return a placeholder structure instead of 404
        return {
            "metadata": {
                "id": "none",
                "level": "executive",
                "title": "No Reports Available",
                "created_at": datetime.utcnow().isoformat(),
                "status": "pending"
            },
            "ai_analysis": "No security reports have been generated yet. Reports will appear here once the scheduler runs or you manually trigger report generation.",
            "generated_at": datetime.utcnow().isoformat()
        }

    latest_report = None
    latest_created_ts: Optional[float] = None

    for report_file in reports_dir.glob("*.json"):
        try:
            with open(report_file, "r") as f:
                report_data = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to parse report {report_file}: {e}")
            continue

        metadata = report_data.get("metadata", {})
        created_raw = metadata.get("created_at")
        file_mtime = report_file.stat().st_mtime

        created_ts: float
        if isinstance(created_raw, str):
            iso_value = created_raw.replace("Z", "+00:00")
            try:
                parsed_dt = datetime.fromisoformat(iso_value)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
                created_ts = parsed_dt.timestamp()
            except ValueError:
                logger.debug(
                    "Invalid created_at on %s, using file mtime", report_file.name
                )
                created_ts = file_mtime
        else:
            created_ts = file_mtime

        if latest_created_ts is None or created_ts > latest_created_ts:
            latest_created_ts = created_ts
            latest_report = report_data

    if latest_report is None:
        # Return a placeholder structure instead of 404
        return {
            "metadata": {
                "id": "none",
                "level": "executive",
                "title": "No Reports Available",
                "created_at": datetime.utcnow().isoformat(),
                "status": "pending"
            },
            "ai_analysis": "No security reports have been generated yet. Reports will appear here once the scheduler runs or you manually trigger report generation.",
            "generated_at": datetime.utcnow().isoformat()
        }

    return latest_report


@app.get("/reports/latest/analysis-html", response_class=HTMLResponse)
async def get_latest_analysis_html():
    """Return the latest AI analysis as formatted HTML (public endpoint for Grafana iframe)"""
    import markdown
    
    reports_dir = Path("reports")

    if not reports_dir.exists():
        return HTMLResponse("<p>No reports available</p>")

    latest_report = None
    latest_created_ts: Optional[float] = None

    for report_file in reports_dir.glob("*.json"):
        try:
            with open(report_file, "r") as f:
                report_data = json.load(f)
        except Exception as e:
            continue

        metadata = report_data.get("metadata", {})
        created_raw = metadata.get("created_at")
        file_mtime = report_file.stat().st_mtime

        created_ts: float
        if isinstance(created_raw, str):
            iso_value = created_raw.replace("Z", "+00:00")
            try:
                parsed_dt = datetime.fromisoformat(iso_value)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
                created_ts = parsed_dt.timestamp()
            except ValueError:
                created_ts = file_mtime
        else:
            created_ts = file_mtime

        if latest_created_ts is None or created_ts > latest_created_ts:
            latest_created_ts = created_ts
            latest_report = report_data

    if latest_report is None:
        styled_html = """
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>AI Analysis</title></head>
        <body style="font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5;">
            <div style="background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #ff6b6b; margin-top: 0;">⚠️ No Reports Available</h2>
                <p>No security reports have been generated yet. Trigger a report generation to see AI analysis here.</p>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=styled_html)

    ai_analysis = latest_report.get("ai_analysis", "No analysis available")
    
    # Check if analysis is empty or an error
    if not ai_analysis or len(ai_analysis.strip()) < 10:
        ai_analysis = "⚠️ **Report generated but AI analysis is empty or failed.**\n\nThis may be due to a timeout or connection issue with the AI model."
    
    # Convert markdown to HTML
    html_content = markdown.markdown(ai_analysis, extensions=['extra', 'nl2br', 'tables'])
    
    # Get report metadata for header
    metadata = latest_report.get("metadata", {})
    report_title = metadata.get("title", "AI Security Analysis")
    created_at = metadata.get("created_at", "Unknown")
    
    # Wrap in styled HTML with full document structure
    styled_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AI Security Analysis</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background: #f5f5f5;
                color: #333;
                line-height: 1.8;
            }}
            .container {{
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                max-width: 1200px;
                margin: 0 auto;
            }}
            h1, h2, h3, h4 {{
                color: #2c3e50;
                margin-top: 1.5em;
            }}
            h1 {{ font-size: 2em; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
            h2 {{ font-size: 1.6em; border-bottom: 2px solid #e0e0e0; padding-bottom: 8px; }}
            h3 {{ font-size: 1.3em; color: #34495e; }}
            p {{ margin: 1em 0; }}
            ul, ol {{ margin: 1em 0; padding-left: 2em; }}
            li {{ margin: 0.5em 0; }}
            code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }}
            pre {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            .meta {{ color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; padding: 10px; background: #ecf0f1; border-radius: 4px; }}
            strong {{ color: #2c3e50; }}
            hr {{ border: none; border-top: 1px solid #e0e0e0; margin: 2em 0; }}
            table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #3498db; color: white; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 {report_title}</h1>
            <div class="meta">
                <strong>Generated:</strong> {created_at}<br>
                <strong>Report ID:</strong> {metadata.get('id', 'N/A')}
            </div>
            <hr>
            {html_content}
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=styled_html)


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