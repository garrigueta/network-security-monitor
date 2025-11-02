"""
DNS security test module - DNS tunneling and suspicious queries
"""

import dns.resolver
import random
import time
from faker import Faker
from .base import BaseTest
from ..core.models import TestResult


class DNSTest(BaseTest):
    """DNS tunneling and suspicious domain query tests"""
    
    def __init__(self, target: str, port: int, config: dict):
        super().__init__(target, port, config)
        self.faker = Faker()
    
    async def execute_tunneling(self) -> TestResult:
        """Simulate DNS tunneling - exfiltrating data via DNS queries"""
        result = self.create_result(
            scenario="dns_tunneling",
            protocol="dns"
        )
        result.target = "8.8.8.8"  # Google DNS
        result.port = 53
        
        start = time.time()
        
        try:
            patterns = self.config
            domain = random.choice(patterns['domains'])
            prefix = random.choice(patterns['tunnel_prefixes'])
            
            # Generate fake data to "exfiltrate" via DNS
            fake_data = self.faker.uuid4().replace('-', '')[:16]
            
            # Create suspicious DNS query with encoded data
            query_domain = f"{prefix}{fake_data}.{domain}"
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                # This will fail but will generate DNS traffic
                answers = resolver.resolve(query_domain, 'A')
                result.success = True
            except dns.resolver.NXDOMAIN:
                # Expected - domain doesn't exist
                result.success = True
                result.details = {"query": query_domain, "type": "DNS_TUNNELING"}
            except Exception as e:
                result.success = True  # Still generated DNS traffic
                result.details = {"query": query_domain, "error": str(e)[:50]}
            
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start
        
        return result
