"""
Network scanning and anomaly test modules
"""

import socket
import random
import asyncio
import time
import requests
from faker import Faker
from .base import BaseTest
from ..core.models import TestResult


class PortScanTest(BaseTest):
    """Port scanning security test"""
    
    async def execute(self) -> TestResult:
        """Simulate port scanning"""
        result = self.create_result(
            scenario="port_scan",
            protocol="scan"
        )
        
        start = time.time()
        
        try:
            # Select random port
            port_list = (
                self.config.get('common', []) + 
                self.config.get('suspicious', []) + 
                self.config.get('high', [])
            )
            port = random.choice(port_list)
            
            result.port = port
            
            # Quick TCP SYN scan (connect attempt)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            conn_result = sock.connect_ex((self.target, port))
            
            if conn_result == 0:
                result.success = True
                result.details = {"port": port, "state": "open"}
            else:
                result.details = {"port": port, "state": "closed/filtered"}
            
            sock.close()
            
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start
        
        return result


class WeirdPacketTest(BaseTest):
    """Generate malformed/weird packets to trigger Zeek 'weird' events"""
    
    async def execute(self) -> TestResult:
        """Generate malformed packets"""
        result = self.create_result(
            scenario="malformed_packets",
            protocol="weird"
        )
        result.port = 80
        
        start = time.time()
        
        try:
            # Generate various weird network behaviors
            weird_types = [
                "oversized_http_headers",
                "malformed_http_request",
                "invalid_tcp_flags",
                "fragmented_packets"
            ]
            
            weird_type = random.choice(weird_types)
            
            if weird_type == "oversized_http_headers":
                # Send HTTP request with extremely large headers
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, 80))
                
                # Create oversized header
                huge_header = "X-Custom-Header: " + ("A" * 10000) + "\r\n"
                request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n{huge_header}\r\n\r\n"
                
                sock.send(request.encode())
                sock.close()
                
            elif weird_type == "malformed_http_request":
                # Send invalid HTTP request
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, 80))
                
                # Malformed request (no HTTP version)
                request = "GET /admin\r\n\r\n"
                sock.send(request.encode())
                sock.close()
                
            elif weird_type == "invalid_tcp_flags":
                # Send packet with weird TCP flags combination
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                try:
                    sock.connect((self.target, 9999))  # Random port
                except:
                    pass
                sock.close()
            
            elif weird_type == "fragmented_packets":
                # Send data in tiny fragments
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, 80))
                
                # Send HTTP request one byte at a time
                request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
                for char in request:
                    sock.send(char.encode())
                    await asyncio.sleep(0.01)
                
                sock.close()
            
            result.success = True
            result.details = {"weird_type": weird_type}
            
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start
        
        return result


class SuspiciousDomainTest(BaseTest):
    """Query suspicious/malicious domains"""
    
    def __init__(self, target: str, port: int, config: dict):
        super().__init__(target, port, config)
        self.faker = Faker()
    
    async def execute(self) -> TestResult:
        """Query suspicious domains"""
        result = self.create_result(
            scenario="suspicious_domains",
            protocol="http"
        )
        result.target = "dns"
        result.port = 53
        
        start = time.time()
        
        try:
            url = random.choice(self.config['domains'])
            user_agent = random.choice(self.config['user_agents'])
            
            session = requests.Session()
            session.headers.update({'User-Agent': user_agent})
            
            try:
                # Attempt to connect (will likely fail, but generates traffic)
                resp = session.get(url, timeout=3)
                result.success = True
                result.details = {"url": url, "user_agent": user_agent, "status": resp.status_code}
            except requests.exceptions.ConnectionError:
                # Expected - malicious domain
                result.success = True
                result.details = {"url": url, "user_agent": user_agent, "type": "MALICIOUS_DOMAIN"}
            except requests.exceptions.Timeout:
                result.success = True
                result.details = {"url": url, "type": "TIMEOUT"}
            
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start
        
        return result
