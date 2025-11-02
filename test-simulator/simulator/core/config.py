"""
Configuration management
"""

import yaml
from typing import Dict, Any
from pathlib import Path


class Config:
    """Configuration manager"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.data = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    @property
    def target_host(self) -> str:
        return self.data['target']['host']
    
    @property
    def target_ports(self) -> Dict[str, int]:
        return self.data['target']['ports']
    
    @property
    def scenarios(self) -> list:
        return self.data['scenarios']
    
    @property
    def patterns(self) -> Dict:
        return self.data['patterns']
    
    @property
    def simulation(self) -> Dict:
        return self.data['simulation']
    
    def get_port(self, protocol: str) -> int:
        """Get port for specific protocol"""
        return self.target_ports.get(protocol, 0)
    
    def get_pattern(self, protocol: str) -> dict:
        """Get test patterns for protocol"""
        return self.patterns.get(protocol, {})
