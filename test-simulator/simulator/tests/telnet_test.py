"""
Telnet security test module
"""

import socket
from .base import BaseTest
from ..core.models import TestResult


class TelnetTest(BaseTest):
    """Telnet connection and authentication security test"""
    
    async def execute(self, username: str, password: str) -> TestResult:
        """Execute Telnet connection attempt"""
        result = self.create_result(
            scenario="telnet_scan",
            protocol="telnet",
            username=username
        )
        
        start = socket.time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, self.port))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result.details = {"banner": banner[:100]}
            
            # Send username
            sock.send(f"{username}\r\n".encode())
            socket.time.sleep(0.5)
            
            # Receive password prompt
            sock.recv(1024)
            
            # Send password
            sock.send(f"{password}\r\n".encode())
            socket.time.sleep(0.5)
            
            # Check response
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if "Welcome" in response or "$" in response or "#" in response:
                result.success = True
            
            sock.close()
            
        except socket.timeout:
            result.error = "Connection timeout"
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = socket.time.time() - start
        
        return result
