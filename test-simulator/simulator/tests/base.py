"""
Base security test module interface
"""

from abc import ABC, abstractmethod
from typing import Optional
import time
from ..core.models import TestResult


class BaseTest(ABC):
    """Base class for all security test modules"""
    
    def __init__(self, target: str, port: int, config: dict):
        self.target = target
        self.port = port
        self.config = config
    
    @abstractmethod
    async def execute(self, **kwargs) -> TestResult:
        """Execute the security test"""
        pass
    
    def create_result(self, scenario: str, protocol: str, **kwargs) -> TestResult:
        """Create a base TestResult with common fields"""
        return TestResult(
            timestamp=TestResult.now_timestamp(),
            scenario=scenario,
            protocol=protocol,
            target=self.target,
            port=self.port,
            **kwargs
        )
    
    async def measure_time(self, func):
        """Measure execution time of async function"""
        start = time.time()
        result = await func()
        elapsed = time.time() - start
        return result, elapsed
