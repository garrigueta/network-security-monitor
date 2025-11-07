#!/usr/bin/env python3
"""
Example demonstrating the enhanced AI agent data scraping capabilities.

This script shows how to use the new Zeek log analysis features.
"""
import asyncio
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ai_agent.data_sources import DataCollector


async def demonstrate_zeek_parsing():
    """Demonstrate Zeek log parsing capabilities"""
    print("=" * 70)
    print("AI Agent Enhanced Data Scraping - Zeek Analysis Demo")
    print("=" * 70)
    print()
    
    collector = DataCollector()
    
    # Test 1: Zeek value conversion
    print("1. Testing Zeek Value Type Conversion")
    print("-" * 70)
    test_values = [
        ("123", "count", "Integer count"),
        ("80", "port", "Port number"),
        ("1.5", "time", "Timestamp"),
        ("T", "bool", "Boolean true"),
        ("F", "bool", "Boolean false"),
        ("a,b,c", "vector[string]", "Vector of strings"),
        ("(empty)", "set[string]", "Empty set"),
    ]
    
    for value, zeek_type, description in test_values:
        converted = collector._convert_zeek_value(value, zeek_type)
        print(f"  {description:25} '{value}' ({zeek_type:15}) -> {converted} ({type(converted).__name__})")
    print()
    
    # Test 2: Show supported log types
    print("2. Supported Zeek Log Types")
    print("-" * 70)
    log_types = ["conn", "dns", "http", "ssl", "ssh", "files", "weird", "notice", "software", "x509", "pe"]
    print(f"  The AI agent now supports {len(log_types)} Zeek log types:")
    for i, log_type in enumerate(log_types, 1):
        print(f"    {i:2}. {log_type}")
    print()
    
    # Test 3: Analysis capabilities
    print("3. Available Analysis Methods")
    print("-" * 70)
    analysis_methods = [
        ("analyze_zeek_connections", "Network connection patterns, protocols, suspicious long-duration connections"),
        ("analyze_zeek_dns", "DNS query patterns, suspicious domains, failed queries"),
        ("analyze_zeek_http", "Web traffic patterns, potential SQLi/XSS attacks, file downloads"),
        ("analyze_zeek_files", "File transfers, large files, executable downloads"),
    ]
    
    for method, description in analysis_methods:
        print(f"  • {method}")
        print(f"    {description}")
        print()
    
    # Test 4: MCP Tools
    print("4. New MCP Tools for AI-Powered Analysis")
    print("-" * 70)
    mcp_tools = [
        "analyze_zeek_connections",
        "analyze_zeek_dns",
        "analyze_zeek_http",
        "analyze_zeek_files",
        "get_zeek_logs"
    ]
    
    print(f"  The MCP server now exposes {len(mcp_tools)} new tools for Zeek analysis:")
    for tool in mcp_tools:
        print(f"    • {tool}")
    print()
    
    print("5. Example Usage")
    print("-" * 70)
    print("""
  # Using the DataCollector directly:
  from ai_agent.data_sources import DataCollector
  
  collector = DataCollector()
  
  # Get parsed Zeek connection logs from last 24 hours
  zeek_logs = await collector.get_local_zeek_logs(
      log_types=["conn", "dns", "http"],
      hours=24,
      limit=1000
  )
  
  # Analyze connection patterns
  conn_analysis = await collector.analyze_zeek_connections(hours=24)
  print(f"Total connections: {conn_analysis['total_connections']}")
  print(f"Top protocols: {conn_analysis['protocols']}")
  
  # Analyze DNS patterns
  dns_analysis = await collector.analyze_zeek_dns(hours=24)
  print(f"Total queries: {dns_analysis['total_queries']}")
  print(f"Top domains: {dns_analysis['top_domains']}")
  
  # Using MCP tools via the AI engine:
  from ai_agent.mcp.server import mcp_server
  
  # Get connection analysis
  result = await mcp_server.call_tool(
      "analyze_zeek_connections",
      {"hours": 24}
  )
  print(result[0]['text'])
    """)
    
    print("=" * 70)
    print("✅ Enhanced data scraping capabilities are ready to use!")
    print("=" * 70)
    
    await collector.close()


if __name__ == "__main__":
    asyncio.run(demonstrate_zeek_parsing())
