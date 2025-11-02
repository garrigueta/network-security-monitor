"""Prompt templates and configuration for the AI Agent"""

from typing import Dict, Any
from .config import settings


class PromptTemplates:
    """Centralized prompt templates for different analysis types"""
    
    # Base system prompt for the security AI agent
    SYSTEM_PROMPT = """You are an expert Network Security AI Agent specializing in cybersecurity analysis. You have deep knowledge of:

🔒 SECURITY DOMAINS:
- Honeypot analysis (SSH/Telnet attacks, malware collection)
- Network traffic analysis (Zeek logs, connection patterns)
- System monitoring (resource usage, performance metrics)
- Threat intelligence (attack patterns, IOCs, TTPs)
- Incident response (alert prioritization, forensics)

🎯 YOUR MISSION:
Analyze security data to identify threats, patterns, and provide actionable insights for network defense.

💡 ANALYSIS APPROACH:
- Prioritize critical security findings
- Identify attack patterns and anomalies  
- Correlate events across data sources
- Provide clear, actionable recommendations
- Explain technical findings in context

📊 DATA SOURCES AVAILABLE:
- Cowrie SSH/Telnet honeypot logs
- Dionaea malware honeypot data
- Zeek network monitoring logs
- Prometheus system metrics
- Security alerts and events

🚨 OUTPUT FORMAT:
- Lead with executive summary
- Highlight critical findings
- Provide technical details
- Include specific recommendations
- Use security industry terminology

Always be thorough but concise. Focus on actionable intelligence."""

    # Honeypot-specific analysis prompts
    HONEYPOT_ANALYSIS = """Analyze the honeypot security data below and provide comprehensive insights:

🍯 HONEYPOT DATA:
{honeypot_data}

🔍 THREAT PATTERNS:
{threat_patterns}

📋 ANALYSIS REQUIREMENTS:
1. **Executive Summary** - Key security findings and risk level
2. **Attack Vectors** - Primary methods attackers are using
3. **Threat Actor Analysis** - Geographic distribution, timing patterns
4. **Critical Findings** - High-priority security concerns
5. **Tactical Recommendations** - Immediate actions to take
6. **Strategic Recommendations** - Long-term security improvements

🎯 FOCUS AREAS: {focus_areas}
⏱️ TIMEFRAME: {timeframe}

Prioritize findings by severity and provide specific, actionable guidance."""

    NETWORK_ANALYSIS = """Analyze the network security and system metrics below:

📊 SYSTEM METRICS:
{network_metrics}

🚨 SECURITY ALERTS:
{security_alerts}

📋 ANALYSIS REQUIREMENTS:
1. **System Health Assessment** - Overall infrastructure status
2. **Security Posture** - Current threat landscape
3. **Performance Correlation** - Resource usage impact on security
4. **Alert Analysis** - Priority ranking and investigation guidance
5. **Capacity Planning** - Resource and security scaling needs
6. **Remediation Plan** - Step-by-step improvement actions

🎯 FOCUS AREAS: {focus_areas}
⏱️ TIMEFRAME: {timeframe}

Correlate security events with system performance and provide operational guidance."""

    NATURAL_LANGUAGE_QUERY = """Based on the security data provided, answer the user's question:

📊 AVAILABLE DATA:
{context_data}

❓ USER QUESTION: {user_query}

📋 RESPONSE REQUIREMENTS:
- Answer the specific question asked
- Reference relevant data points
- Provide context and implications
- Suggest follow-up actions if appropriate
- Include confidence level in findings

Additional Context: {additional_context}

Be direct and specific in your response while providing necessary security context."""

    THREAT_HUNTING = """Conduct threat hunting analysis on the provided data:

🔍 HUNTING FOCUS: {hunt_focus}
📊 DATA SOURCES: {data_sources}
⏱️ TIME RANGE: {time_range}

🎯 HUNTING OBJECTIVES:
1. **IOC Discovery** - Identify indicators of compromise
2. **Attack Chain Reconstruction** - Map attack progression
3. **Lateral Movement Detection** - Find evidence of spread
4. **Persistence Mechanisms** - Identify long-term access
5. **Data Exfiltration Signs** - Look for data theft indicators

📋 HUNTING REPORT FORMAT:
- **Executive Summary**: Key findings and risk assessment
- **Technical Findings**: Detailed evidence and artifacts
- **Attack Timeline**: Chronological event sequence
- **TTPs Identified**: Tactics, techniques, and procedures used
- **Hunting Recommendations**: Further investigation areas

Focus on evidence-based findings and provide confidence ratings."""

    @classmethod
    def get_honeypot_prompt(cls, honeypot_data: str, threat_patterns: str, 
                           focus_areas: list, timeframe: str) -> str:
        """Get formatted honeypot analysis prompt"""
        return cls.HONEYPOT_ANALYSIS.format(
            honeypot_data=honeypot_data,
            threat_patterns=threat_patterns,
            focus_areas=", ".join(focus_areas) if focus_areas else "general security analysis",
            timeframe=timeframe
        )
    
    @classmethod
    def get_network_prompt(cls, network_metrics: str, security_alerts: str,
                          focus_areas: list, timeframe: str) -> str:
        """Get formatted network analysis prompt"""
        return cls.NETWORK_ANALYSIS.format(
            network_metrics=network_metrics,
            security_alerts=security_alerts,
            focus_areas=", ".join(focus_areas) if focus_areas else "general network security",
            timeframe=timeframe
        )
    
    @classmethod
    def get_query_prompt(cls, context_data: str, user_query: str, 
                        additional_context: str = "") -> str:
        """Get formatted natural language query prompt"""
        return cls.NATURAL_LANGUAGE_QUERY.format(
            context_data=context_data,
            user_query=user_query,
            additional_context=additional_context or "None provided"
        )
    
    @classmethod
    def get_threat_hunting_prompt(cls, hunt_focus: str, data_sources: list,
                                 time_range: str) -> str:
        """Get formatted threat hunting prompt"""
        return cls.THREAT_HUNTING.format(
            hunt_focus=hunt_focus,
            data_sources=", ".join(data_sources),
            time_range=time_range
        )


class PromptConfig:
    """Configuration for prompt behavior and model parameters"""
    
    # Model parameters for different analysis types
    ANALYSIS_PARAMS = {
        "honeypot": {
            "temperature": 0.3,  # More focused for security analysis
            "top_p": 0.8,
            "max_tokens": 3000,
            "stop": ["END_ANALYSIS"]
        },
        "network": {
            "temperature": 0.4,
            "top_p": 0.9,
            "max_tokens": 2500,
            "stop": ["END_REPORT"]
        },
        "query": {
            "temperature": 0.5,  # Slightly more creative for Q&A
            "top_p": 0.9,
            "max_tokens": 1500,
            "stop": ["END_RESPONSE"]
        },
        "threat_hunting": {
            "temperature": 0.2,  # Very focused for hunting
            "top_p": 0.7,
            "max_tokens": 4000,
            "stop": ["END_HUNT"]
        }
    }
    
    @classmethod
    def get_params(cls, analysis_type: str) -> Dict[str, Any]:
        """Get model parameters for specific analysis type"""
        return cls.ANALYSIS_PARAMS.get(analysis_type, cls.ANALYSIS_PARAMS["query"])


# Global prompt template instance
prompt_templates = PromptTemplates()