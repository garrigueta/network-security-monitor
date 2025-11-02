"""
Result reporting and statistics
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List
from colorama import Fore

from ..core.models import TestResult


class Reporter:
    """Handles result reporting and statistics"""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(config.simulation.get('output_dir', './results'))
        
        # Create output directory
        if config.simulation.get('save_results', True):
            self.output_dir.mkdir(exist_ok=True)
    
    def save_results(self, results: List[TestResult]):
        """Save results to JSON file"""
        if not self.config.simulation.get('save_results', True):
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"test_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        
        print(f"{Fore.GREEN}Results saved to: {filename}")
    
    def print_summary(self, results: List[TestResult]):
        """Print test summary statistics"""
        total = len(results)
        successful = sum(1 for r in results if r.success)
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}SECURITY TEST SIMULATION SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Total tests:       {total}")
        print(f"{Fore.GREEN}Successful:        {successful}")
        print(f"{Fore.RED}Failed:            {total - successful}")
        print(f"{Fore.YELLOW}Success rate:      {(successful/total*100):.1f}%" if total > 0 else "N/A")
        
        # Per-protocol breakdown
        protocols = {}
        for r in results:
            if r.protocol not in protocols:
                protocols[r.protocol] = {'total': 0, 'success': 0}
            protocols[r.protocol]['total'] += 1
            if r.success:
                protocols[r.protocol]['success'] += 1
        
        print(f"\n{Fore.CYAN}Per-Protocol Results:")
        for proto, stats in sorted(protocols.items()):
            rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {proto.upper():12} - {stats['success']}/{stats['total']} ({rate:.1f}%)")
        
        print(f"{Fore.CYAN}{'='*60}\n")
