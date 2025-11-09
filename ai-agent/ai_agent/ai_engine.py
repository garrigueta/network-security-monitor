"""AI Engine for processing queries and analysis using Ollama"""

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import httpx
import structlog

from .config import settings
from .data_sources import DataCollector
from .mcp.server import mcp_server
from .prompts import prompt_templates, PromptConfig
from .logging_utils import ActionLogger

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
        ActionLogger.log_service_action(
            logger,
            action="ai_engine_initialize",
            status="started",
            ollama_url=settings.ollama_url,
            model=settings.ollama_model
        )
        
        try:
            # Test remote Ollama connection
            response = await self.http_client.get(f"{settings.ollama_url}/api/tags")
            if response.status_code == 200:
                models = response.json()
                available_models = [m['name'] for m in models.get('models', [])]
                
                ActionLogger.log_service_action(
                    logger,
                    action="ollama_connection_test",
                    status="completed",
                    ollama_url=settings.ollama_url,
                    available_models=available_models,
                    model_count=len(available_models)
                )
                
                # Check if our configured model is available
                if settings.ollama_model not in available_models:
                    ActionLogger.log_service_action(
                        logger,
                        action="model_availability_check",
                        status="failed",
                        configured_model=settings.ollama_model,
                        available_models=available_models,
                        warning="Model not found"
                    )
                else:
                    ActionLogger.log_service_action(
                        logger,
                        action="model_availability_check",
                        status="completed",
                        model=settings.ollama_model
                    )
            else:
                ActionLogger.log_service_action(
                    logger,
                    action="ollama_connection_test",
                    status="failed",
                    ollama_url=settings.ollama_url,
                    status_code=response.status_code
                )
        except Exception as e:
            ActionLogger.log_service_action(
                logger,
                action="ai_engine_initialize",
                status="failed",
                error=str(e),
                ollama_url=settings.ollama_url
            )
    
    async def analyze_honeypot(self, timeframe: str = "24h", focus_areas: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze honeypot activity using AI with comprehensive log data"""
        start_time = time.time()
        
        ActionLogger.log_ai_action(
            logger,
            action="honeypot_analysis",
            model=settings.ollama_model,
            status="started",
            timeframe=timeframe,
            focus_areas=focus_areas or ["general"]
        )
        
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
            
            duration_ms = (time.time() - start_time) * 1000
            
            ActionLogger.log_ai_action(
                logger,
                action="honeypot_analysis",
                model=settings.ollama_model,
                status="completed",
                duration_ms=duration_ms,
                timeframe=timeframe,
                honeypot_events=honeypot_summary["total_honeypot_events"],
                response_length=len(ai_response)
            )
            
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
            duration_ms = (time.time() - start_time) * 1000
            ActionLogger.log_ai_action(
                logger,
                action="honeypot_analysis",
                model=settings.ollama_model,
                status="failed",
                duration_ms=duration_ms,
                error=str(e)
            )
            return {
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "ai_analysis": "Analysis unavailable due to error"
            }
    
    async def analyze_network(self, timeframe: str = "24h", focus_areas: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze network security and system metrics with comprehensive Zeek data"""
        start_time = time.time()
        
        ActionLogger.log_ai_action(
            logger,
            action="network_analysis",
            model=settings.ollama_model,
            status="started",
            timeframe=timeframe,
            focus_areas=focus_areas or ["general"]
        )
        
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
            
            duration_ms = (time.time() - start_time) * 1000
            
            ActionLogger.log_ai_action(
                logger,
                action="network_analysis",
                model=settings.ollama_model,
                status="completed",
                duration_ms=duration_ms,
                timeframe=timeframe,
                total_connections=network_summary["total_connections"],
                response_length=len(ai_response)
            )
            
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
            duration_ms = (time.time() - start_time) * 1000
            ActionLogger.log_ai_action(
                logger,
                action="network_analysis",
                model=settings.ollama_model,
                status="failed",
                duration_ms=duration_ms,
                error=str(e)
            )
            return {
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "ai_analysis": "Analysis unavailable due to error"
            }
    
    async def analyze_kubernetes_cluster(self, timeframe: str = "24h", focus_areas: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze Kubernetes cluster health and operational status"""
        start_time = time.time()
        
        ActionLogger.log_ai_action(
            logger,
            action="kubernetes_analysis",
            model=settings.ollama_model,
            status="started",
            timeframe=timeframe,
            focus_areas=focus_areas or ["cluster_health"]
        )
        
        try:
            # Get Kubernetes metrics from Prometheus
            hours = self._timeframe_to_hours(timeframe)
            k8s_metrics = await self.data_collector.get_kubernetes_metrics(hours=hours)
            
            # Get Kubernetes error logs from Loki
            k8s_logs = await self.data_collector.get_kubernetes_logs(
                hours=hours, 
                limit=200,
                namespace="network-security"
            )
            
            # Categorize logs by severity and type
            error_logs = {
                "errors": [log for log in k8s_logs if any(term in str(log).lower() for term in ["error", "failed", "exception"])],
                "oom_kills": [log for log in k8s_logs if any(term in str(log).lower() for term in ["oom", "out of memory", "killed"])],
                "crashes": [log for log in k8s_logs if any(term in str(log).lower() for term in ["crash", "panic", "fatal"])],
                "restarts": [log for log in k8s_logs if any(term in str(log).lower() for term in ["restart", "backoff", "crashloop"])],
            }
            
            # Process and summarize error metrics
            error_summary = {
                "oom_events": self._count_metric_values(k8s_metrics["errors"].get("oom_events", {})),
                "memory_failures": self._count_metric_values(k8s_metrics["errors"].get("memory_failures", {})),
                "network_rx_errors": self._count_metric_values(k8s_metrics["errors"].get("network_rx_errors", {})),
                "network_tx_errors": self._count_metric_values(k8s_metrics["errors"].get("network_tx_errors", {})),
                "scrape_errors": self._count_metric_values(k8s_metrics["errors"].get("scrape_errors", {})),
                "log_errors": len(error_logs["errors"]),
                "log_oom_kills": len(error_logs["oom_kills"]),
                "log_crashes": len(error_logs["crashes"]),
                "log_restarts": len(error_logs["restarts"])
            }
            
            # Process resource usage metrics
            resource_summary = {
                "cpu_usage_by_namespace": self._aggregate_by_namespace(k8s_metrics["resource_usage"].get("cpu_usage", {})),
                "memory_usage_by_namespace": self._aggregate_by_namespace(k8s_metrics["resource_usage"].get("memory_usage", {})),
                "top_cpu_pods": self._get_top_pods(k8s_metrics["resource_usage"].get("cpu_usage", {}), limit=10),
                "top_memory_pods": self._get_top_pods(k8s_metrics["resource_usage"].get("memory_usage", {}), limit=10),
                "network_throughput": {
                    "rx_bytes_per_sec": self._count_metric_values(k8s_metrics["resource_usage"].get("network_rx_bytes", {})),
                    "tx_bytes_per_sec": self._count_metric_values(k8s_metrics["resource_usage"].get("network_tx_bytes", {}))
                }
            }
            
            # Prepare sample error logs for analysis (limit to avoid token overflow)
            sample_error_logs = {
                "recent_errors": error_logs["errors"][:10],
                "oom_examples": error_logs["oom_kills"][:5],
                "crash_examples": error_logs["crashes"][:5],
                "restart_examples": error_logs["restarts"][:5]
            }
            
            # Create comprehensive analysis prompt
            prompt = prompt_templates.get_kubernetes_health_prompt(
                kubernetes_metrics=json.dumps(k8s_metrics, indent=2),
                error_summary=json.dumps(error_summary, indent=2),
                resource_trends=json.dumps(resource_summary, indent=2),
                error_logs=json.dumps(sample_error_logs, indent=2, default=str),
                focus_areas=focus_areas or ["cluster_health", "error_analysis", "capacity_planning"],
                timeframe=timeframe
            )
            
            # Get AI analysis
            ai_response = await self._query_ollama(prompt, analysis_type="kubernetes")
            
            duration_ms = (time.time() - start_time) * 1000
            
            ActionLogger.log_ai_action(
                logger,
                action="kubernetes_analysis",
                model=settings.ollama_model,
                status="completed",
                duration_ms=duration_ms,
                timeframe=timeframe,
                total_errors=sum(error_summary.values()),
                response_length=len(ai_response)
            )
            
            return {
                "timestamp": datetime.now().isoformat(),
                "timeframe": timeframe,
                "ai_analysis": ai_response,
                "cluster_metrics": {
                    "errors": error_summary,
                    "resources": resource_summary,
                    "collection_time": k8s_metrics.get("collection_time")
                },
                "error_logs": {
                    "total_errors": len(k8s_logs),
                    "by_category": {k: len(v) for k, v in error_logs.items()},
                    "samples": sample_error_logs
                },
                "raw_data": k8s_metrics,
                "focus_areas": focus_areas or ["cluster_health"]
            }
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            ActionLogger.log_ai_action(
                logger,
                action="kubernetes_analysis",
                model=settings.ollama_model,
                status="failed",
                duration_ms=duration_ms,
                error=str(e)
            )
            return {
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "ai_analysis": "Kubernetes analysis unavailable due to error"
            }
    
    def _count_metric_values(self, metric_data: Dict[str, Any]) -> int:
        """Count total values from Prometheus metric results"""
        if not metric_data or "result" not in metric_data:
            return 0
        
        total = 0
        for result in metric_data["result"]:
            if "value" in result and len(result["value"]) > 1:
                try:
                    total += float(result["value"][1])
                except (ValueError, TypeError):
                    pass
        return int(total)
    
    def _aggregate_by_namespace(self, metric_data: Dict[str, Any]) -> Dict[str, float]:
        """Aggregate metric values by namespace"""
        if not metric_data or "result" not in metric_data:
            return {}
        
        namespace_totals = {}
        for result in metric_data["result"]:
            namespace = result.get("metric", {}).get("namespace", "unknown")
            if "value" in result and len(result["value"]) > 1:
                try:
                    value = float(result["value"][1])
                    namespace_totals[namespace] = namespace_totals.get(namespace, 0) + value
                except (ValueError, TypeError):
                    pass
        return namespace_totals
    
    def _get_top_pods(self, metric_data: Dict[str, Any], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top N pods by metric value"""
        if not metric_data or "result" not in metric_data:
            return []
        
        pod_values = []
        for result in metric_data["result"]:
            metric = result.get("metric", {})
            namespace = metric.get("namespace", "unknown")
            pod = metric.get("pod", "unknown")
            
            if "value" in result and len(result["value"]) > 1:
                try:
                    value = float(result["value"][1])
                    pod_values.append({
                        "namespace": namespace,
                        "pod": pod,
                        "value": value
                    })
                except (ValueError, TypeError):
                    pass
        
        # Sort by value descending and return top N
        pod_values.sort(key=lambda x: x["value"], reverse=True)
        return pod_values[:limit]
    
    async def process_query(self, query: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Process natural language queries about security data"""
        start_time = time.time()
        
        ActionLogger.log_ai_action(
            logger,
            action="query_processing",
            model=settings.ollama_model,
            status="started",
            query_length=len(query),
            has_context=context is not None
        )
        
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
            
            duration_ms = (time.time() - start_time) * 1000
            
            ActionLogger.log_ai_action(
                logger,
                action="query_processing",
                model=settings.ollama_model,
                status="completed",
                duration_ms=duration_ms,
                query_length=len(query),
                response_length=len(ai_response),
                data_sources=data_sources,
                sources_used=sources_used
            )
            
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
            duration_ms = (time.time() - start_time) * 1000
            ActionLogger.log_ai_action(
                logger,
                action="query_processing",
                model=settings.ollama_model,
                status="failed",
                duration_ms=duration_ms,
                query_length=len(query),
                error=str(e)
            )
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
                ActionLogger.log_ai_action(
                    logger,
                    action="ollama_query",
                    model=settings.ollama_model,
                    status="started",
                    prompt_length=len(full_prompt),
                    attempt=f"{attempt + 1}/{max_retries}",
                    analysis_type=analysis_type,
                    temperature=payload['options']['temperature'],
                    max_tokens=payload['options']['num_predict']
                )
                
                response = await self.http_client.post(
                    f"{settings.ollama_url}/api/generate",
                    json=payload
                )
                
                if response.status_code == 200:
                    result = response.json()
                    ai_response = result.get("response", "").strip()
                    
                    if ai_response:
                        ActionLogger.log_ai_action(
                            logger,
                            action="ollama_query",
                            model=settings.ollama_model,
                            status="completed",
                            response_length=len(ai_response),
                            attempt=f"{attempt + 1}/{max_retries}",
                            analysis_type=analysis_type,
                            context_length=len(result.get('context', []))
                        )
                        
                        # Validate response is not just whitespace or error message
                        if len(ai_response) < 50 and any(word in ai_response.lower() for word in ['error', 'failed', 'unavailable']):
                            ActionLogger.log_ai_action(
                                logger,
                                action="ollama_query",
                                model=settings.ollama_model,
                                status="failed",
                                warning="Suspiciously short response",
                                response=ai_response,
                                attempt=f"{attempt + 1}/{max_retries}"
                            )
                            if attempt < max_retries - 1:
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