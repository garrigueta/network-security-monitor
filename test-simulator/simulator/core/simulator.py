"""
Main security test simulator orchestrator
"""

import asyncio
import random
import logging
from pathlib import Path
from typing import List
from colorama import Fore, Style, init

from .config import Config
from .models import TestResult
from ..tests import TestFactory
from ..utils.logger import setup_logger
from ..utils.reporter import Reporter

# Initialize colorama
init(autoreset=True)

logger = setup_logger(__name__)


class SecurityTestSimulator:
    """Main security test simulator orchestrator"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the security test simulator"""
        self.config = Config(config_path)
        self.results: List[TestResult] = []
        self.reporter = Reporter(self.config)
        
        logger.info(f"{Fore.GREEN}Security Test Simulator initialized")
        logger.info(f"{Fore.CYAN}Target: {self.config.target_host}")
    
    def _get_delay(self, base_delay: int) -> float:
        """Calculate delay with optional jitter"""
        if self.config.simulation.get('randomize_timing', True):
            jitter = random.uniform(0, self.config.simulation.get('max_jitter', 3))
            return base_delay + jitter
        return base_delay
    
    def _log_test(self, result: TestResult):
        """Log test result with color coding"""
        color = Fore.GREEN if result.success else Fore.RED
        status = "SUCCESS" if result.success else "FAILED"
        
        log_msg = (
            f"{color}[{result.protocol.upper()}] {status} - "
            f"{result.target}:{result.port}"
        )
        
        if result.username:
            log_msg += f" (user: {result.username})"
        
        if result.error:
            log_msg += f" - {result.error}"
        
        logger.info(log_msg)
        self.results.append(result)
    
    async def run_scenario(self, scenario: dict):
        """Run a single test scenario"""
        protocol = scenario['protocol']
        scenario_name = scenario['name']
        attempts = scenario['attempts']
        delay = scenario['delay']
        
        logger.info(f"{Fore.YELLOW}Starting scenario: {scenario_name}")
        
        # Get target and port
        target = self.config.target_host
        port = self.config.get_port(protocol)
        
        # Get patterns for this protocol
        patterns = self.config.get_pattern(protocol)
        
        for i in range(attempts):
            # Create test instance
            test = TestFactory.create(
                protocol=protocol,
                scenario_name=scenario_name,
                target=target,
                port=port,
                config=patterns
            )
            
            if not test:
                logger.warning(f"Unknown protocol: {protocol}")
                continue
            
            # Execute test based on protocol type
            if protocol in ['ssh', 'telnet', 'ftp', 'mysql', 'postgresql']:
                # Credential-based tests
                usernames = patterns.get('usernames', ['test'])
                passwords = patterns.get('passwords', ['password'])
                username = random.choice(usernames)
                password = random.choice(passwords)
                result = await test.execute(username=username, password=password)
            elif protocol == 'dns':
                result = await test.execute_tunneling()
            else:
                # No credentials needed
                result = await test.execute()
            
            self._log_test(result)
            
            # Delay between attempts
            if i < attempts - 1:
                await asyncio.sleep(self._get_delay(delay))
        
        logger.info(f"{Fore.YELLOW}Completed scenario: {scenario_name}")
    
    async def run_all_scenarios(self):
        """Run all enabled test scenarios"""
        scenarios = [s for s in self.config.scenarios if s.get('enabled', True)]
        
        if self.config.simulation.get('randomize_order', True):
            random.shuffle(scenarios)
        
        logger.info(f"{Fore.GREEN}Starting security test simulation with {len(scenarios)} scenarios")
        
        for scenario in scenarios:
            await self.run_scenario(scenario)
            await asyncio.sleep(2)  # Pause between scenarios
        
        self.reporter.save_results(self.results)
        self.reporter.print_summary(self.results)
    
    def run(self):
        """Main entry point - run simulation"""
        asyncio.run(self.run_all_scenarios())
