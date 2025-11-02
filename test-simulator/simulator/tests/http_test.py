"""
HTTP security test module
"""

import requests
import random
import time
from faker import Faker
from .base import BaseTest
from ..core.models import TestResult


class HTTPTest(BaseTest):
    """HTTP scanning and probing security test"""
    
    def __init__(self, target: str, port: int, config: dict):
        super().__init__(target, port, config)
        self.faker = Faker()
    
    async def execute(self) -> TestResult:
        """Execute HTTP security test"""
        result = self.create_result(
            scenario="http_scan",
            protocol="http"
        )
        
        # Common test paths
        paths = [
            "/admin",
            "/login",
            "/.git/config",
            "/wp-admin",
            "/phpmyadmin",
            "/admin.php",
            "/shell.php",
            "/../../../etc/passwd"
        ]
        
        start = time.time()
        
        try:
            session = requests.Session()
            
            # Random user agent if enabled
            if self.config.get('fake_user_agents', True):
                session.headers.update({
                    'User-Agent': self.faker.user_agent()
                })
            
            results = []
            for path in random.sample(paths, 3):  # Try 3 random paths
                try:
                    url = f"http://{self.target}:{self.port}{path}"
                    resp = session.get(url, timeout=5)
                    results.append({
                        "path": path,
                        "status": resp.status_code,
                        "size": len(resp.content)
                    })
                except:
                    pass
            
            result.details = {"paths_tested": results}
            result.success = len(results) > 0
            
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start
        
        return result
