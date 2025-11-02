"""Report generation models and schemas"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ReportLevel(str, Enum):
    """Report complexity levels"""
    EXECUTIVE = "executive"      # High-level summary for management
    TECHNICAL = "technical"      # Technical analysis for security teams
    DETAILED = "detailed"        # Comprehensive forensic analysis
    REAL_TIME = "real_time"     # Immediate alerts and notifications


class ReportFrequency(str, Enum):
    """Report generation frequency"""
    REAL_TIME = "real_time"     # Immediate (for alerts)
    HOURLY = "hourly"           # Every hour
    DAILY = "daily"             # Daily reports
    WEEKLY = "weekly"           # Weekly summaries
    MONTHLY = "monthly"         # Monthly analysis


class ReportStatus(str, Enum):
    """Report generation status"""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportMetadata(BaseModel):
    """Report metadata and configuration"""
    id: str = Field(..., description="Unique report identifier")
    level: ReportLevel = Field(..., description="Report complexity level")
    frequency: ReportFrequency = Field(..., description="Generation frequency")
    title: str = Field(..., description="Report title")
    description: str = Field(..., description="Report description")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    period_start: datetime = Field(..., description="Analysis period start")
    period_end: datetime = Field(..., description="Analysis period end")
    status: ReportStatus = Field(default=ReportStatus.PENDING)
    tags: List[str] = Field(default_factory=list, description="Report tags")
    data_sources: List[str] = Field(default_factory=list, description="Data sources used")
    
    
class ExecutiveSummary(BaseModel):
    """Executive-level report content"""
    security_score: float = Field(..., ge=0, le=100, description="Overall security score")
    threat_level: str = Field(..., description="Current threat level (LOW/MEDIUM/HIGH/CRITICAL)")
    key_findings: List[str] = Field(..., description="Top 3-5 key findings")
    recommendations: List[str] = Field(..., description="Executive recommendations")
    metrics_summary: Dict[str, Any] = Field(..., description="Key metrics summary")
    trend_analysis: str = Field(..., description="Security trend analysis")


class TechnicalAnalysis(BaseModel):
    """Technical-level report content"""
    attack_vectors: List[Dict[str, Any]] = Field(..., description="Detailed attack vector analysis")
    vulnerability_assessment: Dict[str, Any] = Field(..., description="Vulnerability analysis")
    incident_timeline: List[Dict[str, Any]] = Field(..., description="Security incident timeline")
    network_analysis: Dict[str, Any] = Field(..., description="Network security analysis")
    honeypot_analysis: Dict[str, Any] = Field(..., description="Honeypot activity analysis")
    mitigation_steps: List[Dict[str, Any]] = Field(..., description="Technical mitigation steps")


class DetailedForensics(BaseModel):
    """Detailed forensic analysis content"""
    raw_events: List[Dict[str, Any]] = Field(..., description="Raw security events")
    correlation_analysis: Dict[str, Any] = Field(..., description="Event correlation analysis")
    threat_intelligence: Dict[str, Any] = Field(..., description="Threat intelligence data")
    evidence_chain: List[Dict[str, Any]] = Field(..., description="Evidence chain analysis")
    attribution_analysis: Dict[str, Any] = Field(..., description="Attack attribution analysis")
    ioc_analysis: Dict[str, Any] = Field(..., description="Indicators of Compromise analysis")


class RealTimeAlert(BaseModel):
    """Real-time alert content"""
    alert_id: str = Field(..., description="Alert identifier")
    severity: str = Field(..., description="Alert severity (LOW/MEDIUM/HIGH/CRITICAL)")
    event_type: str = Field(..., description="Type of security event")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    target_system: Optional[str] = Field(None, description="Target system")
    description: str = Field(..., description="Alert description")
    immediate_actions: List[str] = Field(..., description="Immediate response actions")
    context: Dict[str, Any] = Field(..., description="Additional context")


class ReportContent(BaseModel):
    """Complete report content container"""
    metadata: ReportMetadata = Field(..., description="Report metadata")
    executive_summary: Optional[ExecutiveSummary] = None
    technical_analysis: Optional[TechnicalAnalysis] = None
    detailed_forensics: Optional[DetailedForensics] = None
    real_time_alert: Optional[RealTimeAlert] = None
    ai_analysis: str = Field(..., description="AI-generated analysis narrative")
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    export_formats: List[str] = Field(default=["json", "html"], description="Available export formats")


class ReportConfiguration(BaseModel):
    """Report generation configuration"""
    enabled: bool = Field(default=True, description="Enable report generation")
    levels: List[ReportLevel] = Field(default_factory=lambda: list(ReportLevel), description="Enabled report levels")
    frequencies: Dict[ReportLevel, ReportFrequency] = Field(
        default_factory=lambda: {
            ReportLevel.REAL_TIME: ReportFrequency.REAL_TIME,
            ReportLevel.EXECUTIVE: ReportFrequency.DAILY,
            ReportLevel.TECHNICAL: ReportFrequency.DAILY,
            ReportLevel.DETAILED: ReportFrequency.WEEKLY
        },
        description="Frequency per report level"
    )
    retention_days: int = Field(default=90, description="Report retention period in days")
    export_formats: List[str] = Field(default=["json", "html", "pdf"], description="Export formats")
    grafana_integration: bool = Field(default=True, description="Enable Grafana integration")


class ReportRequest(BaseModel):
    """Request for ad-hoc report generation"""
    level: ReportLevel = Field(..., description="Report level")
    period_hours: int = Field(default=24, description="Analysis period in hours")
    focus_areas: Optional[List[str]] = Field(None, description="Specific focus areas")
    export_format: str = Field(default="json", description="Export format")
    include_raw_data: bool = Field(default=False, description="Include raw data in report")


class ReportListResponse(BaseModel):
    """Response for report listing"""
    reports: List[ReportMetadata] = Field(..., description="List of reports")
    total: int = Field(..., description="Total number of reports")
    page: int = Field(default=1, description="Current page")
    page_size: int = Field(default=50, description="Page size")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Applied filters")