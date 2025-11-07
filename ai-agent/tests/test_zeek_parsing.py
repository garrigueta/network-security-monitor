"""
Tests for enhanced Zeek log parsing and analysis
"""
import asyncio
from pathlib import Path
import tempfile
import os


# Mock DataCollector for testing parsing logic
class MockDataCollector:
    """Mock DataCollector to test parsing methods"""
    
    def __init__(self):
        pass
    
    def _convert_zeek_value(self, value: str, zeek_type: str):
        """Convert Zeek value based on its type"""
        try:
            if zeek_type in ['count', 'port']:
                return int(value)
            elif zeek_type in ['time', 'interval', 'double']:
                return float(value)
            elif zeek_type == 'bool':
                return value.upper() == 'T'
            elif zeek_type.startswith('vector') or zeek_type.startswith('set'):
                if value == '(empty)':
                    return []
                return value.split(',')
            else:
                return value
        except (ValueError, AttributeError):
            return value


def test_zeek_value_conversion():
    """Test Zeek value type conversion"""
    collector = MockDataCollector()
    
    # Test integer conversion
    assert collector._convert_zeek_value("123", "count") == 123
    assert collector._convert_zeek_value("80", "port") == 80
    
    # Test float conversion
    assert collector._convert_zeek_value("1.5", "time") == 1.5
    assert collector._convert_zeek_value("123.456", "interval") == 123.456
    
    # Test boolean conversion
    assert collector._convert_zeek_value("T", "bool") is True
    assert collector._convert_zeek_value("F", "bool") is False
    
    # Test vector conversion
    assert collector._convert_zeek_value("a,b,c", "vector[string]") == ["a", "b", "c"]
    assert collector._convert_zeek_value("(empty)", "set[string]") == []
    
    # Test string conversion (default)
    assert collector._convert_zeek_value("test", "string") == "test"
    assert collector._convert_zeek_value("-", "string") == "-"


def test_zeek_log_parsing():
    """Test Zeek log parsing with sample data"""
    # Create a temporary Zeek-style log file
    sample_log = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1699364400.123456	CHhAvVGS1DHFjwGM9	192.168.1.100	49301	93.184.216.34	80	tcp	http	5.123	1234	5678	SF	T	F	0	ShADadfF	10	2000	8	3000	(empty)
1699364401.654321	C1234567890ABCDEF	10.0.0.5	12345	8.8.8.8	53	udp	dns	0.05	100	200	SF	T	F	0	D	1	128	1	128	(empty)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(sample_log)
        temp_file = f.name
    
    try:
        # Parse the log file
        field_names = []
        field_types = []
        entries = []
        
        with open(temp_file, 'r') as f:
            for line in f:
                if line.startswith('#fields'):
                    field_names = line.strip().split('\t')[1:]
                elif line.startswith('#types'):
                    field_types = line.strip().split('\t')[1:]
                elif line.startswith('#') or not line.strip():
                    continue
                else:
                    values = line.strip().split('\t')
                    if field_names and len(values) == len(field_names):
                        collector = MockDataCollector()
                        entry = {"log_type": "conn", "source": "zeek"}
                        for i, field_name in enumerate(field_names):
                            value = values[i]
                            if value == '-':
                                entry[field_name] = None
                            else:
                                if field_types and i < len(field_types):
                                    entry[field_name] = collector._convert_zeek_value(value, field_types[i])
                                else:
                                    entry[field_name] = value
                        entries.append(entry)
        
        # Verify parsing results
        assert len(entries) == 2, f"Expected 2 entries, got {len(entries)}"
        
        # Check first entry
        first_entry = entries[0]
        assert first_entry['log_type'] == 'conn'
        assert first_entry['source'] == 'zeek'
        assert isinstance(first_entry['ts'], float)
        assert first_entry['ts'] == 1699364400.123456
        assert first_entry['id.orig_h'] == '192.168.1.100'
        assert first_entry['id.orig_p'] == 49301  # Should be converted to int
        assert first_entry['id.resp_p'] == 80  # Should be converted to int
        assert first_entry['proto'] == 'tcp'
        assert first_entry['service'] == 'http'
        assert isinstance(first_entry['duration'], float)
        assert first_entry['duration'] == 5.123
        assert first_entry['orig_bytes'] == 1234  # Should be converted to int
        assert first_entry['local_orig'] is True  # Should be converted to bool
        assert first_entry['local_resp'] is False  # Should be converted to bool
        
        # Check second entry
        second_entry = entries[1]
        assert second_entry['proto'] == 'udp'
        assert second_entry['service'] == 'dns'
        assert second_entry['id.resp_p'] == 53
        
        print("✅ All Zeek log parsing tests passed!")
        
    finally:
        # Clean up
        os.unlink(temp_file)


def test_mcp_tools_registration():
    """Test that new MCP tools are properly registered"""
    # Import the actual MCP server
    import sys
    sys.path.insert(0, '/home/runner/work/network-security-monitor/network-security-monitor/ai-agent')
    
    from ai_agent.mcp.server import NetworkSecurityMCPServer
    
    server = NetworkSecurityMCPServer()
    tools = server.tools
    
    # Check that new tools are registered
    expected_tools = [
        "get_honeypot_activity",
        "get_network_metrics",
        "get_security_alerts",
        "analyze_threat_patterns",
        "analyze_zeek_connections",
        "analyze_zeek_dns",
        "analyze_zeek_http",
        "analyze_zeek_files",
        "get_zeek_logs"
    ]
    
    for tool_name in expected_tools:
        assert tool_name in tools, f"Tool '{tool_name}' not found in registered tools"
        assert "description" in tools[tool_name], f"Tool '{tool_name}' missing description"
        assert "parameters" in tools[tool_name], f"Tool '{tool_name}' missing parameters"
    
    print(f"✅ All {len(expected_tools)} MCP tools registered successfully!")


if __name__ == "__main__":
    print("Running Zeek parsing tests...")
    test_zeek_value_conversion()
    print("✅ Value conversion test passed!\n")
    
    test_zeek_log_parsing()
    print("✅ Log parsing test passed!\n")
    
    test_mcp_tools_registration()
    print("✅ MCP tools registration test passed!\n")
    
    print("🎉 All tests passed!")
