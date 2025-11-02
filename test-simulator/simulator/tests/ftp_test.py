"""
FTP security test module
"""

from ftplib import FTP
from .base import BaseTest
from ..core.models import TestResult
import time


class FTPTest(BaseTest):
    """FTP connection and authentication security test"""
    
    async def execute(self, username: str, password: str) -> TestResult:
        """Execute FTP connection attempt"""
        result = self.create_result(
            scenario="ftp_anonymous",
            protocol="ftp",
            username=username
        )
        
        start = time.time()
        
        try:
            ftp = FTP()
            ftp.connect(self.target, self.port, timeout=10)
            
            # Get banner
            banner = ftp.getwelcome()
            result.details = {"banner": banner}
            
            # Attempt login
            ftp.login(username, password)
            
            # List directory
            files = []
            ftp.retrlines('LIST', files.append)
            
            result.success = True
            result.details = {
                "banner": banner,
                "files_count": len(files)
            }
            
            ftp.quit()
            
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start
        
        return result
