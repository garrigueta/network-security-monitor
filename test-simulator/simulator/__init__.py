"""
Security Test Simulator Package
Modular security testing framework for validating honeypots and security monitoring
"""

__version__ = "2.0.0"
__author__ = "Network Security Team"

from .core.simulator import SecurityTestSimulator
from .core.models import TestResult

__all__ = ['SecurityTestSimulator', 'TestResult']
