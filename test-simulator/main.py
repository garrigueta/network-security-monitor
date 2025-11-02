#!/usr/bin/env python3
"""
Security Test Simulator - Main Entry Point
Modular security testing framework for validating security monitoring systems
"""

import sys
import argparse
from pathlib import Path

# Add simulator package to path
sys.path.insert(0, str(Path(__file__).parent))

from simulator import SecurityTestSimulator
from colorama import Fore


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Security Test Simulator - Validate your security monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Run with default config.yaml
  %(prog)s -c custom.yaml     # Use custom configuration
  %(prog)s --version          # Show version
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Security Test Simulator v2.0.0'
    )
    
    args = parser.parse_args()
    
    try:
        simulator = SecurityTestSimulator(args.config)
        simulator.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Test simulation interrupted by user")
        sys.exit(0)
    except FileNotFoundError as e:
        print(f"{Fore.RED}Error: Configuration file not found: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
