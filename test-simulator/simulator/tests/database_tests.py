"""
Database security test modules (MySQL and PostgreSQL)
"""

import pymysql
import psycopg2
import time
from .base import BaseTest
from ..core.models import TestResult


class MySQLTest(BaseTest):
    """MySQL connection and authentication security test"""
    
    async def execute(self, username: str, password: str) -> TestResult:
        """Execute MySQL connection attempt"""
        result = self.create_result(
            scenario="mysql_bruteforce",
            protocol="mysql",
            username=username
        )
        
        start = time.time()
        
        try:
            connection = pymysql.connect(
                host=self.target,
                port=self.port,
                user=username,
                password=password,
                connect_timeout=10
            )
            
            # Query version
            with connection.cursor() as cursor:
                cursor.execute("SELECT VERSION()")
                version = cursor.fetchone()
                result.details = {"version": version[0] if version else None}
            
            result.success = True
            connection.close()
            
        except pymysql.err.OperationalError as e:
            result.error = f"Auth failed: {str(e)}"
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start
        
        return result


class PostgreSQLTest(BaseTest):
    """PostgreSQL connection and authentication security test"""
    
    async def execute(self, username: str, password: str) -> TestResult:
        """Execute PostgreSQL connection attempt"""
        result = self.create_result(
            scenario="postgresql_scan",
            protocol="postgresql",
            username=username
        )
        
        start = time.time()
        
        try:
            connection = psycopg2.connect(
                host=self.target,
                port=self.port,
                user=username,
                password=password,
                connect_timeout=10
            )
            
            # Query version
            cursor = connection.cursor()
            cursor.execute("SELECT version()")
            version = cursor.fetchone()
            result.details = {"version": version[0][:50] if version else None}
            
            result.success = True
            connection.close()
            
        except psycopg2.OperationalError as e:
            result.error = f"Auth failed: {str(e)}"
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start
        
        return result
