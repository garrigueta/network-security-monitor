"""
SSH security test module
"""

import paramiko
import socket
from .base import BaseTest
from ..core.models import TestResult


class SSHTest(BaseTest):
    """SSH authentication security test"""
    
    async def execute(self, username: str, password: str) -> TestResult:
        """Execute SSH authentication test"""
        result = self.create_result(
            scenario="ssh_bruteforce",
            protocol="ssh",
            username=username
        )
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            start = socket.time.time()
            
            # Attempt connection
            client.connect(
                hostname=self.target,
                port=self.port,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10
            )
            
            result.success = True
            result.details = {"password": password}
            client.close()
            
        except paramiko.AuthenticationException:
            result.error = "Authentication failed"
        except paramiko.SSHException as e:
            result.error = f"SSH error: {str(e)}"
        except socket.timeout:
            result.error = "Connection timeout"
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = socket.time.time() - start
        
        return result
