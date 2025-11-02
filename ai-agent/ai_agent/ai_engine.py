"""AI Engine for processing queries and analysis using Ollama"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
import httpx
import structlog

from .config import settings
from .data_sources import DataCollector
from .mcp.server import mcp_server
from .prompts import prompt_templates, PromptConfig

logger = structlog.get_logger()


class AIEngine:
    """AI Engine using Ollama for natural language processing and analysis"""
    
    def __init__(self):
        self.data_collector = DataCollector()
        self.http_client = httpx.AsyncClient(timeout=300.0)  # 5 minutes timeout for large models
        # Use centralized system prompt
        self.system_prompt = prompt_templates.SYSTEM_PROMPT
    
    async def initialize(self):
        """Initialize the AI engine"""
        try:
            # Test remote Ollama connection
            response = await self.http_client.get(f"{settings.ollama_url}/api/tags")
            if response.status_code == 200:
                models = response.json()
                available_models = [m['name'] for m in models.get('models', [])]
                logger.info(f"Connected to remote Ollama at {settings.ollama_url}")
                logger.info(f"Available models: {available_models}")
                
                # Check if our configured model is available
                if settings.ollama_model not in available_models:
                    logger.warning(f"Configured model '{settings.ollama_model}' not found. Available: {available_models}")
                    logger.info("Consider pulling the model: ollama pull llama3.1:8b")
                else:
                    logger.info(f"Model '{settings.ollama_model}' is ready")
            else:
                logger.warning(f"Could not connect to remote Ollama at {settings.ollama_url} - AI features may be limited")
        except Exception as e:
            logger.warning(f"Remote Ollama connection failed: {e} - AI features may be limited")
    
    async def analyze_honeypot(self, timeframe: str = "24h", focus_areas: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze honeypot activity using AI"""
        try:
            # Collect honeypot data using MCP
            tools_result = await mcp_server.call_tool(
                "get_honeypot_activity",
                {"hours": self._timeframe_to_hours(timeframe), "limit": 200}
            )
            
            honeypot_data = tools_result[0]["text"] if tools_result else "No honeypot data available"
            
            # Get threat patterns
            patterns_result = await mcp_server.call_tool(
                "analyze_threat_patterns",
                {"timeframe": timeframe, "focus": "all"}
            )
            
            threat_patterns = patterns_result[0]["text"] if patterns_result else "No threat patterns found"
            
            # Create analysis prompt using template
            prompt = prompt_templates.get_honeypot_prompt(
                honeypot_data=honeypot_data,
                threat_patterns=threat_patterns,
                focus_areas=focus_areas or ["general security analysis"],
                timeframe=timeframe
            )
            
            # Get AI analysis with appropriate parameters
            ai_response = await self._query_ollama(prompt, analysis_type="honeypot")
            
            return {
                "timestamp": datetime.now().isoformat(),
                "timeframe": timeframe,
                "ai_analysis": ai_response,
                "raw_data": {
                    "honeypot_activity": honeypot_data,
                    "threat_patterns": threat_patterns
                },
                "focus_areas": focus_areas or ["general"]
            }
            
        except Exception as e:
            logger.error(f"Error in honeypot analysis: {e}")
            return {
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "ai_analysis": "Analysis unavailable due to error"
            }
    
    async def analyze_network(self, timeframe: str = "24h", focus_areas: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze network security and system metrics"""
        try:
            # Get network metrics
            metrics_tasks = []
            for metric in ["cpu_usage", "memory_usage", "network_connections"]:
                task = mcp_server.call_tool("get_network_metrics", {"metric": metric, "duration": "1h"})
                metrics_tasks.append(task)
            
            metrics_results = await asyncio.gather(*metrics_tasks, return_exceptions=True)
            
            # Get security alerts
            alerts_result = await mcp_server.call_tool(
                "get_security_alerts",
                {"severity": "all", "source": "all"}
            )
            
            # Compile data for analysis
            network_data = ""
            for i, result in enumerate(metrics_results):
                if not isinstance(result, Exception) and result:
                    metric_name = ["cpu_usage", "memory_usage", "network_connections"][i]
                    network_data += f"\n{metric_name.upper()}:\n{result[0]['text']}\n"
            
            alerts_data = alerts_result[0]["text"] if alerts_result else "No alerts found"
            
            # Create analysis prompt using template
            prompt = prompt_templates.get_network_prompt(
                network_metrics=network_data,
                security_alerts=alerts_data,
                focus_areas=focus_areas or ["general network security"],
                timeframe=timeframe
            )
            
            # Get AI analysis with appropriate parameters
            ai_response = await self._query_ollama(prompt, analysis_type="network")
            
            return {
                "timestamp": datetime.now().isoformat(),
                "timeframe": timeframe,
                "ai_analysis": ai_response,
                "raw_data": {
                    "network_metrics": network_data,
                    "security_alerts": alerts_data
                },
                "focus_areas": focus_areas or ["general"]
            }
            
        except Exception as e:
            logger.error(f"Error in network analysis: {e}")
            return {
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "ai_analysis": "Analysis unavailable due to error"
            }
    
    async def process_query(self, query: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Process natural language queries about security data"""
        try:
            # Determine what data to fetch based on query
            data_sources = self._determine_data_sources(query)
            
            # Fetch relevant data
            context_data = ""
            sources_used = []
            
            if "honeypot" in data_sources:
                honeypot_result = await mcp_server.call_tool(
                    "get_honeypot_activity",
                    {"hours": 24, "limit": 50}
                )
                if honeypot_result:
                    context_data += f"\nHONEYPOT DATA:\n{honeypot_result[0]['text']}\n"
                    sources_used.append("honeypot")
            
            if "metrics" in data_sources:
                metrics_result = await mcp_server.call_tool(
                    "get_network_metrics",
                    {"metric": "cpu_usage", "duration": "1h"}
                )
                if metrics_result:
                    context_data += f"\nSYSTEM METRICS:\n{metrics_result[0]['text']}\n"
                    sources_used.append("metrics")
            
            if "alerts" in data_sources:
                alerts_result = await mcp_server.call_tool(
                    "get_security_alerts",
                    {"severity": "all", "source": "all"}
                )
                if alerts_result:
                    context_data += f"\nSECURITY ALERTS:\n{alerts_result[0]['text']}\n"
                    sources_used.append("alerts")
            
            # Create prompt with context using template
            prompt = prompt_templates.get_query_prompt(
                context_data=context_data,
                user_query=query,
                additional_context=json.dumps(context, indent=2) if context else ""
            )
            
            # Get AI response with appropriate parameters
            ai_response = await self._query_ollama(prompt, analysis_type="query")
            
            return {
                "timestamp": datetime.now().isoformat(),
                "response": ai_response,
                "sources": sources_used,
                "metadata": {
                    "query_type": "natural_language",
                    "data_sources_used": data_sources,
                    "context_provided": context is not None
                }
            }
            
        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return {
                "timestamp": datetime.now().isoformat(),
                "response": f"I encountered an error while processing your query: {str(e)}",
                "sources": [],
                "metadata": {"error": str(e)}
            }
    
    def _determine_data_sources(self, query: str) -> List[str]:
        """Determine which data sources to query based on the user's question"""
        query_lower = query.lower()
        sources = []
        
        honeypot_keywords = ["honeypot", "attack", "ssh", "telnet", "malware", "intrusion", "cowrie", "dionaea"]
        metrics_keywords = ["cpu", "memory", "performance", "system", "resource", "load"]
        alerts_keywords = ["alert", "warning", "security", "threat", "incident", "suspicious"]
        
        if any(keyword in query_lower for keyword in honeypot_keywords):
            sources.append("honeypot")
        
        if any(keyword in query_lower for keyword in metrics_keywords):
            sources.append("metrics")
        
        if any(keyword in query_lower for keyword in alerts_keywords):
            sources.append("alerts")
        
        # Default to all sources if no specific match
        if not sources:
            sources = ["honeypot", "metrics", "alerts"]
        
        return sources
    
    def _timeframe_to_hours(self, timeframe: str) -> int:
        """Convert timeframe string to hours"""
        timeframe_map = {
            "1h": 1,
            "6h": 6,
            "24h": 24,
            "7d": 168
        }
        return timeframe_map.get(timeframe, 24)
    
    async def _query_ollama(self, prompt: str, analysis_type: str = "query") -> str:
        """Query Ollama LLM with the given prompt and analysis-specific parameters"""
        try:
            # Get parameters for this analysis type
            params = PromptConfig.get_params(analysis_type)
            
            payload = {
                "model": settings.ollama_model,
                "prompt": f"{self.system_prompt}\n\n{prompt}",
                "stream": False,
                "options": {
                    "temperature": params.get("temperature", 0.7),
                    "top_p": params.get("top_p", 0.9),
                    "num_predict": params.get("max_tokens", 2048)
                }
            }
            
            # Add stop sequences if specified
            if params.get("stop"):
                payload["options"]["stop"] = params["stop"]
            
            logger.info(f"Querying Ollama at {settings.ollama_url} with model {settings.ollama_model}")
            
            response = await self.http_client.post(
                f"{settings.ollama_url}/api/generate",
                json=payload,
                timeout=300.0  # 5 minutes timeout for large models
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "No response from AI model")
            else:
                logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                return "AI analysis is currently unavailable (Ollama connection error)"
                
        except Exception as e:
            logger.error(f"Error querying Ollama: {type(e).__name__}: {e}")
            logger.error(f"Ollama URL: {settings.ollama_url}, Model: {settings.ollama_model}")
            return f"AI analysis failed: {type(e).__name__}: {str(e)}"
    
    async def close(self):
        """Close HTTP client and cleanup"""
        await self.http_client.aclose()
        await self.data_collector.close()