"""FastAPI application for the AI Agent"""

import asyncio
import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Security, Request
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
    ReportLevel, ReportRequest, ReportListResponse, ReportConfiguration, ReportMetadata,
    ReportFrequency
)
from .models import (
    HealthResponse,
    AnalysisRequest,
    AnalysisResponse,
    QueryRequest,
    QueryResponse
)
from ..logging_utils import ActionLogger

logger = structlog.get_logger()
security = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    ActionLogger.log_service_action(
        logger,
        action="api_startup",
        status="started",
        host=settings.api_host,
        port=settings.api_port
    )
    
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
    
    # Initialize and start report scheduler with Kubernetes health reports
    scheduler_config = ReportConfiguration()
    # Enable daily Kubernetes cluster health reports at 9 AM
    scheduler_config.frequencies[ReportLevel.EXECUTIVE] = ReportFrequency.DAILY
    
    app.state.report_scheduler = ReportScheduler(
        report_generator=app.state.report_generator,
        config=scheduler_config
    )
    await app.state.report_scheduler.start()
    
    # Schedule daily Kubernetes cluster health report (9 AM)
    app.state.report_scheduler.scheduler.add_job(
        app.state.report_scheduler._generate_kubernetes_health_report,
        trigger='cron',
        hour=9,
        minute=0,
        id='kubernetes_health_daily',
        name='Daily Kubernetes Cluster Health Report',
        misfire_grace_time=3600
    )
    
    ActionLogger.log_service_action(
        logger,
        action="api_startup",
        status="completed",
        host=settings.api_host,
        port=settings.api_port
    )
    
    yield
    
    # Shutdown
    ActionLogger.log_service_action(
        logger,
        action="api_shutdown",
        status="started"
    )
    
    if hasattr(app.state, 'report_scheduler'):
        await app.state.report_scheduler.stop()
    if hasattr(app.state, 'ai_engine'):
        await app.state.ai_engine.close()
    
    ActionLogger.log_service_action(
        logger,
        action="api_shutdown",
        status="completed"
    )


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
    http_request: Request,
    _: bool = Depends(verify_api_key)
):
    """Analyze honeypot activity and threats"""
    start_time = time.time()
    client_ip = http_request.client.host if http_request.client else "unknown"
    
    ActionLogger.log_api_request(
        logger,
        endpoint="/analyze/honeypot",
        method="POST",
        client_ip=client_ip,
        timeframe=request.timeframe,
        focus_areas=request.focus_areas
    )
    
    try:
        ai_engine = app.state.ai_engine
        
        analysis = await ai_engine.analyze_honeypot(
            timeframe=request.timeframe,
            focus_areas=request.focus_areas
        )
        
        duration_ms = (time.time() - start_time) * 1000
        
        ActionLogger.log_api_request(
            logger,
            endpoint="/analyze/honeypot",
            method="POST",
            status_code=200,
            duration_ms=duration_ms,
            client_ip=client_ip,
            timeframe=request.timeframe
        )
        
        return AnalysisResponse(
            success=True,
            analysis=analysis,
            timestamp=analysis.get("timestamp"),
            metadata={"source": "honeypot", "timeframe": request.timeframe}
        )
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        
        ActionLogger.log_api_request(
            logger,
            endpoint="/analyze/honeypot",
            method="POST",
            status_code=500,
            duration_ms=duration_ms,
            client_ip=client_ip,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/network", response_model=AnalysisResponse)
async def analyze_network(
    request: AnalysisRequest,
    http_request: Request,
    _: bool = Depends(verify_api_key)
):
    """Analyze network security and system metrics"""
    start_time = time.time()
    client_ip = http_request.client.host if http_request.client else "unknown"
    
    ActionLogger.log_api_request(
        logger,
        endpoint="/analyze/network",
        method="POST",
        client_ip=client_ip,
        timeframe=request.timeframe,
        focus_areas=request.focus_areas
    )
    
    try:
        ai_engine = app.state.ai_engine
        
        analysis = await ai_engine.analyze_network(
            timeframe=request.timeframe,
            focus_areas=request.focus_areas
        )
        
        duration_ms = (time.time() - start_time) * 1000
        
        ActionLogger.log_api_request(
            logger,
            endpoint="/analyze/network",
            method="POST",
            status_code=200,
            duration_ms=duration_ms,
            client_ip=client_ip,
            timeframe=request.timeframe
        )
        
        return AnalysisResponse(
            success=True,
            analysis=analysis,
            timestamp=analysis.get("timestamp"),
            metadata={"source": "network", "timeframe": request.timeframe}
        )
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        
        ActionLogger.log_api_request(
            logger,
            endpoint="/analyze/network",
            method="POST",
            status_code=500,
            duration_ms=duration_ms,
            client_ip=client_ip,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/kubernetes", response_model=AnalysisResponse)
async def analyze_kubernetes(
    request: AnalysisRequest,
    http_request: Request,
    _: bool = Depends(verify_api_key)
):
    """Analyze Kubernetes cluster health and operational status"""
    start_time = time.time()
    client_ip = http_request.client.host if http_request.client else "unknown"
    
    ActionLogger.log_api_request(
        logger,
        endpoint="/analyze/kubernetes",
        method="POST",
        client_ip=client_ip,
        timeframe=request.timeframe,
        focus_areas=request.focus_areas
    )
    
    try:
        # Convert timeframe to period_hours
        timeframe_to_hours = {"1h": 1, "6h": 6, "12h": 12, "24h": 24, "7d": 168}
        period_hours = timeframe_to_hours.get(request.timeframe, 24)
        
        # Generate report using the report generator (saves to disk automatically)
        report = await app.state.report_generator.generate_report(
            level=ReportLevel.EXECUTIVE,
            period_hours=period_hours,
            focus_areas=request.focus_areas or ["kubernetes", "cluster_health", "error_analysis"]
        )
        
        # Extract the raw analysis data from the report
        analysis = {
            "timestamp": report.metadata.created_at.isoformat(),
            "timeframe": request.timeframe,
            "ai_analysis": report.ai_analysis,
            "executive_summary": {
                "threat_level": report.executive_summary.threat_level,
                "security_score": report.executive_summary.security_score,
                "key_findings": report.executive_summary.key_findings,
                "recommendations": report.executive_summary.recommendations
            },
            "report_id": report.metadata.id
        }
        
        duration_ms = (time.time() - start_time) * 1000
        
        ActionLogger.log_api_request(
            logger,
            endpoint="/analyze/kubernetes",
            method="POST",
            status_code=200,
            duration_ms=duration_ms,
            client_ip=client_ip,
            timeframe=request.timeframe,
            report_id=report.metadata.id
        )
        
        return AnalysisResponse(
            success=True,
            analysis=analysis,
            timestamp=analysis.get("timestamp"),
            metadata={"source": "kubernetes", "timeframe": request.timeframe, "report_id": report.metadata.id}
        )
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        
        ActionLogger.log_api_request(
            logger,
            endpoint="/analyze/kubernetes",
            method="POST",
            status_code=500,
            duration_ms=duration_ms,
            client_ip=client_ip,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/query", response_model=QueryResponse)
async def natural_language_query(
    request: QueryRequest,
    http_request: Request,
    _: bool = Depends(verify_api_key)
):
    """Process natural language queries about security data"""
    start_time = time.time()
    client_ip = http_request.client.host if http_request.client else "unknown"
    
    ActionLogger.log_api_request(
        logger,
        endpoint="/query",
        method="POST",
        client_ip=client_ip,
        query_length=len(request.query),
        has_context=request.context is not None
    )
    
    try:
        ai_engine = app.state.ai_engine
        
        response = await ai_engine.process_query(
            query=request.query,
            context=request.context
        )
        
        duration_ms = (time.time() - start_time) * 1000
        
        ActionLogger.log_api_request(
            logger,
            endpoint="/query",
            method="POST",
            status_code=200,
            duration_ms=duration_ms,
            client_ip=client_ip,
            query_length=len(request.query),
            response_length=len(response["response"])
        )
        
        return QueryResponse(
            success=True,
            response=response["response"],
            sources=response.get("sources", []),
            timestamp=response.get("timestamp"),
            metadata=response.get("metadata", {})
        )
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        
        ActionLogger.log_api_request(
            logger,
            endpoint="/query",
            method="POST",
            status_code=500,
            duration_ms=duration_ms,
            client_ip=client_ip,
            error=str(e)
        )
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


# Data Collection Endpoints

@app.get("/logs/all")
async def get_all_logs(
    hours: int = 24,
    include_files: bool = False,
    _: bool = Depends(verify_api_key)
):
    """
    Get all logs from all applications/sources
    
    Parameters:
    - hours: Time window in hours (default: 24)
    - include_files: Include raw file paths in response (default: False)
    
    Returns comprehensive log data from:
    - Honeypot applications (Cowrie, Heralding)
    - Zeek network monitoring
    - Loki log aggregation
    """
    try:
        data_collector = app.state.data_sources
        
        all_logs = await data_collector.get_all_logs(
            hours=hours,
            include_raw_files=include_files
        )
        
        return {
            "success": True,
            "data": all_logs,
            "metadata": {
                "collection_time": all_logs["collection_timestamp"],
                "time_window_hours": hours,
                "total_entries": all_logs["summary"]["total_entries"],
                "sources": list(all_logs["summary"]["by_source"].keys())
            }
        }
    except Exception as e:
        logger.error(f"Error collecting all logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs/honeypot")
async def get_honeypot_logs(
    hours: int = 24,
    limit: int = 1000,
    _: bool = Depends(verify_api_key)
):
    """Get honeypot logs (Cowrie and Heralding)"""
    try:
        data_collector = app.state.data_sources
        logs = await data_collector.get_honeypot_logs(hours=hours, limit=limit)
        
        return {
            "success": True,
            "count": len(logs),
            "logs": logs
        }
    except Exception as e:
        logger.error(f"Error getting honeypot logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs/zeek")
async def get_zeek_logs(
    log_type: Optional[str] = None,
    hours: int = 24,
    _: bool = Depends(verify_api_key)
):
    """
    Get Zeek network monitoring logs
    
    Parameters:
    - log_type: Specific log type (conn, dns, http, ssl, etc.) or None for all
    - hours: Time window in hours
    """
    try:
        data_collector = app.state.data_sources
        
        if log_type:
            logs = await data_collector.get_local_zeek_logs(
                log_types=[log_type],
                hours=hours
            )
        else:
            logs = await data_collector.get_local_zeek_logs(hours=hours)
        
        total_entries = sum(len(entries) for entries in logs.values())
        
        return {
            "success": True,
            "log_types": list(logs.keys()),
            "total_entries": total_entries,
            "logs": logs
        }
    except Exception as e:
        logger.error(f"Error getting Zeek logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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
    reports_dir = Path(settings.reports_dir)
    
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
    reports_dir = Path(settings.reports_dir)

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
    
    reports_dir = Path(settings.reports_dir)

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
        <body style="font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #181B1F;">
            <div style="background: #1F2329; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.3); color: #D8DEE9;">
                <h2 style="color: #BF616A; margin-top: 0;">⚠️ No Reports Available</h2>
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
    
    # Wrap in styled HTML with full document structure (dark theme)
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
                background: #181B1F;
                color: #D8DEE9;
                line-height: 1.8;
            }}
            .container {{
                background: #1F2329;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.3);
                max-width: 1200px;
                margin: 0 auto;
            }}
            h1, h2, h3, h4 {{
                color: #6E9ECF;
                margin-top: 1.5em;
            }}
            h1 {{ font-size: 2em; border-bottom: 3px solid #4C9AFF; padding-bottom: 10px; }}
            h2 {{ font-size: 1.6em; border-bottom: 2px solid #3A3F47; padding-bottom: 8px; }}
            h3 {{ font-size: 1.3em; color: #88C0D0; }}
            p {{ margin: 1em 0; }}
            ul, ol {{ margin: 1em 0; padding-left: 2em; }}
            li {{ margin: 0.5em 0; }}
            code {{ background: #2E3440; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; color: #A3BE8C; }}
            pre {{ background: #2E3440; color: #D8DEE9; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #434C5E; }}
            .meta {{ color: #81A1C1; font-size: 0.9em; margin-bottom: 20px; padding: 10px; background: #2E3440; border-radius: 4px; border-left: 3px solid #5E81AC; }}
            strong {{ color: #88C0D0; }}
            hr {{ border: none; border-top: 1px solid #3A3F47; margin: 2em 0; }}
            table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
            th, td {{ border: 1px solid #3A3F47; padding: 12px; text-align: left; }}
            th {{ background-color: #5E81AC; color: #ECEFF4; }}
            tr:nth-child(even) {{ background-color: #242933; }}
            a {{ color: #88C0D0; }}
            a:hover {{ color: #5E81AC; }}
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
        
        report_file = Path(settings.reports_dir) / f"{report_id}.json"
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