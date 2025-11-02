"""Pydantic models for API requests and responses"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    services: Dict[str, str]


class AnalysisRequest(BaseModel):
    """Request for security analysis"""
    timeframe: str = Field(default="24h", description="Analysis timeframe (1h, 6h, 24h, 7d)")
    focus_areas: Optional[List[str]] = Field(default=None, description="Specific areas to focus on")
    include_details: bool = Field(default=True, description="Include detailed analysis")


class AnalysisResponse(BaseModel):
    """Response from security analysis"""
    success: bool
    analysis: Dict[str, Any]
    timestamp: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class QueryRequest(BaseModel):
    """Natural language query request"""
    query: str = Field(description="Natural language query about security data")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Additional context for the query")
    include_sources: bool = Field(default=True, description="Include data sources in response")


class QueryResponse(BaseModel):
    """Response to natural language query"""
    success: bool
    response: str
    sources: Optional[List[str]] = None
    timestamp: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AlertModel(BaseModel):
    """Security alert model"""
    severity: str
    title: str
    description: str
    source: str
    timestamp: str
    details: Optional[Dict[str, Any]] = None


class ThreatPattern(BaseModel):
    """Threat pattern analysis"""
    pattern_type: str
    frequency: int
    severity: str
    description: str
    recommendations: List[str]