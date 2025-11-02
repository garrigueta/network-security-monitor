"""
Security test factory - creates test instances based on protocol
"""

from typing import Optional
from .ssh_test import SSHTest
from .telnet_test import TelnetTest
from .ftp_test import FTPTest
from .http_test import HTTPTest
from .database_tests import MySQLTest, PostgreSQLTest
from .dns_test import DNSTest
from .network_tests import PortScanTest, WeirdPacketTest, SuspiciousDomainTest
from .base import BaseTest


class TestFactory:
    """Factory for creating security test instances"""
    
    @staticmethod
    def create(protocol: str, scenario_name: str, target: str, port: int, config: dict) -> Optional[BaseTest]:
        """Create test instance based on protocol"""
        
        test_map = {
            'ssh': SSHTest,
            'telnet': TelnetTest,
            'ftp': FTPTest,
            'http': HTTPTest,
            'mysql': MySQLTest,
            'postgresql': PostgreSQLTest,
            'dns': DNSTest,
            'scan': PortScanTest,
            'weird': WeirdPacketTest,
        }
        
        # Special case for suspicious_domains
        if scenario_name == 'suspicious_domains':
            return SuspiciousDomainTest(target, port, config)
        
        test_class = test_map.get(protocol)
        if test_class:
            return test_class(target, port, config)
        
        return None
