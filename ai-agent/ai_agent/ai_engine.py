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
        # Increased timeout and connection settings for remote Ollama
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(600.0, connect=30.0, read=600.0),  # 10 minutes timeout
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
        # Use centralized system prompt
        self.system_prompt = prompt_templates.SYSTEM_PROMPT
    
    def _truncate_data(self, data: str, max_length: int = 5000) -> str:
        """Intelligently truncate data while preserving structure"""
        if len(data) <= max_length:
            return data
        
        # Try to find a good breaking point (end of line, paragraph, etc.)
        truncated = data[:max_length]
        
        # Find last newline or sentence
        last_newline = truncated.rfind('\n')
        if last_newline > max_length * 0.8:  # If we can save 80% of content
            truncated = truncated[:last_newline]
        
        return truncated + f"\n\n[... {len(data) - len(truncated)} more characters truncated ...]"
    
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
        """Analyze honeypot activity using AI with comprehensive log data"""
        try:
            # Get comprehensive logs from all sources
            hours = self._timeframe_to_hours(timeframe)
            all_logs = await self.data_collector.get_all_logs(hours=hours, include_raw_files=False)
            
            # Extract honeypot-specific data
            cowrie_count = len(all_logs["sources"]["honeypot"].get("cowrie", []))
            heralding_count = len(all_logs["sources"]["honeypot"].get("heralding", []))
            
            # Also get Zeek data for correlation
            zeek_summary = {
                "conn": len(all_logs["sources"]["zeek"].get("conn", [])),
                "dns": len(all_logs["sources"]["zeek"].get("dns", [])),
                "http": len(all_logs["sources"]["zeek"].get("http", []))
            }
            
            # Get threat patterns
            threat_patterns = await self.data_collector.analyze_threats(
                timeframe=timeframe, focus="all"
            )
            
            # Create comprehensive analysis prompt
            honeypot_summary = {
                "cowrie_events": cowrie_count,
                "heralding_events": heralding_count,
                "total_honeypot_events": cowrie_count + heralding_count,
                "unique_ips": len(set(
                    log.get("src_ip", "") for log in all_logs["sources"]["honeypot"].get("cowrie", [])
                    if log.get("src_ip")
                ))
            }
            
            prompt = prompt_templates.get_honeypot_prompt(
                honeypot_data=json.dumps(honeypot_summary, indent=2),
                threat_patterns=self._truncate_data(json.dumps(threat_patterns, indent=2), 2000),
                focus_areas=focus_areas or ["general security analysis"],
                timeframe=timeframe,
                zeek_correlation=json.dumps(zeek_summary, indent=2)
            )
            
            # Get AI analysis
            ai_response = await self._query_ollama(prompt, analysis_type="honeypot")
            
            return {
                "timestamp": datetime.now().isoformat(),
                "timeframe": timeframe,
                "ai_analysis": ai_response,
                "raw_data": {
                    "honeypot_summary": honeypot_summary,
                    "zeek_summary": zeek_summary,
                    "threat_patterns": threat_patterns
                },
                "comprehensive_logs": {
                    "total_entries": all_logs["summary"]["total_entries"],
                    "sources": list(all_logs["summary"]["by_source"].keys())
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
        """Analyze network security and system metrics with comprehensive Zeek data"""
        try:
            # Get comprehensive logs
            hours = self._timeframe_to_hours(timeframe)
            all_logs = await self.data_collector.get_all_logs(hours=hours, include_raw_files=False)
            
            # Extract Zeek network analysis
            zeek_logs = all_logs["sources"].get("zeek", {})
            network_summary = {
                "total_connections": len(zeek_logs.get("conn", [])),
                "dns_queries": len(zeek_logs.get("dns", [])),
                "http_requests": len(zeek_logs.get("http", [])),
                "ssl_connections": len(zeek_logs.get("ssl", [])),
                "ssh_attempts": len(zeek_logs.get("ssh", [])),
                "file_transfers": len(zeek_logs.get("files", [])),
                "weird_events": len(zeek_logs.get("weird", [])),
                "security_notices": len(zeek_logs.get("notice", []))
            }
            
            # Get Prometheus metrics for correlation
            metrics_data = {}
            for metric in ["cpu_usage", "memory_usage", "network_connections"]:
                try:
                    result = await self.data_collector.get_prometheus_metrics(metric, "1h")
                    metrics_data[metric] = result
                except Exception as e:
                    logger.warning(f"Could not fetch {metric}: {e}")
            
            # Get security alerts
            alerts = await self.data_collector.get_security_alerts(severity="all", source="all")
            
            # Create comprehensive analysis prompt
            prompt = prompt_templates.get_network_prompt(
                network_metrics=json.dumps(network_summary, indent=2),
                security_alerts=json.dumps(alerts[:20], indent=2) if alerts else "No alerts",
                focus_areas=focus_areas or ["general network security"],
                timeframe=timeframe,
                system_metrics=json.dumps(metrics_data, indent=2)
            )
            
            # Get AI analysis
            ai_response = await self._query_ollama(prompt, analysis_type="network")
            
            return {
                "timestamp": datetime.now().isoformat(),
                "timeframe": timeframe,
                "ai_analysis": ai_response,
                "raw_data": {
                    "zeek_summary": network_summary,
                    "system_metrics": metrics_data,
                    "security_alerts": alerts[:20] if alerts else []
                },
                "comprehensive_logs": {
                    "total_entries": all_logs["summary"]["total_entries"],
                    "zeek_log_types": list(zeek_logs.keys())
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
        """Query Ollama LLM with the given prompt and analysis-specific parameters with retry logic"""
        # Get parameters for this analysis type
        params = PromptConfig.get_params(analysis_type)
        
        # Truncate very long prompts to avoid issues
        max_prompt_length = 8000  # Conservative limit
        full_prompt = f"{self.system_prompt}\n\n{prompt}"
        
        if len(full_prompt) > max_prompt_length:
            logger.warning(f"Prompt too long ({len(full_prompt)} chars), truncating to {max_prompt_length}")
            full_prompt = full_prompt[:max_prompt_length] + "\n\n[Content truncated due to length]"
        
        payload = {
            "model": settings.ollama_model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": params.get("temperature", 0.7),
                "top_p": params.get("top_p", 0.9),
                "top_k": params.get("top_k", 40),
                "num_predict": params.get("max_tokens", 2048),
                "num_ctx": 4096,  # Context window
                "repeat_penalty": 1.1,
                "seed": -1,  # Random seed for variability
                "stop": ["<|endoftext|>", "<|im_end|>"],  # Stop sequences
                # Disable thinking mode that consumes tokens
                "penalize_newline": False,
                "mirostat": 0  # Disable mirostat for more predictable output
            }
        }
        
        # Add stop sequences if specified
        if params.get("stop"):
            payload["options"]["stop"] = params["stop"]
        
        # Retry logic with exponential backoff
        max_retries = 3
        retry_delay = 2  # Start with 2 seconds
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Querying Ollama at {settings.ollama_url} with model {settings.ollama_model} (attempt {attempt + 1}/{max_retries})")
                logger.debug(f"Prompt length: {len(full_prompt)} chars, max_tokens: {payload['options']['num_predict']}")
                
                response = await self.http_client.post(
                    f"{settings.ollama_url}/api/generate",
                    json=payload
                )
                
                if response.status_code == 200:
                    result = response.json()
                    ai_response = result.get("response", "").strip()
                    
                    # Debug log the result structure
                    logger.debug(f"Ollama result keys: {list(result.keys())}")
                    logger.debug(f"Done: {result.get('done')}, Context length: {len(result.get('context', []))}")
                    
                    if ai_response:
                        logger.info(f"Successfully received response from Ollama ({len(ai_response)} chars)")
                        
                        # Validate response is not just whitespace or error message
                        if len(ai_response) < 50 and any(word in ai_response.lower() for word in ['error', 'failed', 'unavailable']):
                            logger.warning(f"Received suspiciously short response: {ai_response}")
                            if attempt < max_retries - 1:
                                logger.info(f"Retrying in {retry_delay} seconds...")
                                await asyncio.sleep(retry_delay)
                                retry_delay *= 2
                                continue
                        
                        return ai_response
                    else:
                        logger.warning(f"Empty response from Ollama. Full result: {result}")
                        if attempt < max_retries - 1:
                            logger.info(f"Retrying with adjusted parameters in {retry_delay} seconds...")
                            # Adjust parameters for retry
                            payload["options"]["temperature"] = 0.8
                            payload["options"]["num_predict"] = min(1024, payload["options"]["num_predict"])
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 2
                            continue
                        return "AI model returned an empty response after multiple attempts. Try again or check model health."
                else:
                    logger.error(f"Ollama API error: {response.status_code} - {response.text[:200]}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    return f"AI analysis unavailable: HTTP {response.status_code}"
                    
            except httpx.ReadTimeout as e:
                logger.error(f"Ollama read timeout on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                return "AI analysis timed out - the model took too long to respond. Consider using a smaller/faster model."
                
            except httpx.ConnectError as e:
                logger.error(f"Cannot connect to Ollama at {settings.ollama_url}: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                return f"Cannot connect to AI model at {settings.ollama_url}. Please check if Ollama is running."
                
            except Exception as e:
                logger.error(f"Unexpected error querying Ollama (attempt {attempt + 1}): {type(e).__name__}: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                return f"AI analysis failed: {type(e).__name__}: {str(e)}"
        
        return "AI analysis failed after multiple retries"
    
    async def close(self):
        """Close HTTP client and cleanup"""
        await self.http_client.aclose()
        await self.data_collector.close()