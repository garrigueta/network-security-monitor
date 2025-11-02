"""
Core data models for security testing
"""

from dataclasses import dataclass, asdict
from typing import Dict, Optional
from datetime import datetime


@dataclass
class TestResult:
    """Data class for security test results"""
    timestamp: str
    scenario: str
    protocol: str
    target: str
    port: int
    username: Optional[str] = None
    success: bool = False
    error: Optional[str] = None
    response_time: float = 0.0
    details: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    @staticmethod
    def now_timestamp() -> str:
        """Generate current timestamp"""
        return datetime.now().isoformat()
