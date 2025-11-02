#!/usr/bin/env python3
"""
Advanced Attack Simulator for Honeypot Testing
Simulates various attack vectors across multiple protocols
"""

import asyncio
import random
import time
import socket
import yaml
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Protocol-specific imports
import paramiko
import requests
from faker import Faker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """Data class for attack results"""
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


class AttackSimulator:
    """Main attack simulator class"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the attack simulator"""
        self.config = self._load_config(config_path)
        self.results: List[AttackResult] = []
        self.faker = Faker()
        
        # Create output directory
        if self.config['simulation']['save_results']:
            Path(self.config['simulation']['output_dir']).mkdir(exist_ok=True)
        
        logger.info(f"{Fore.GREEN}Attack Simulator initialized")
        logger.info(f"{Fore.CYAN}Target: {self.config['target']['host']}")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _get_delay(self, base_delay: int) -> float:
        """Calculate delay with optional jitter"""
        if self.config['simulation']['randomize_timing']:
            jitter = random.uniform(0, self.config['simulation']['max_jitter'])
            return base_delay + jitter
        return base_delay
    
    def _log_attack(self, result: AttackResult):
        """Log attack result with color coding"""
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
    
    async def ssh_attack(self, username: str, password: str) -> AttackResult:
        """Simulate SSH brute force attack"""
        target = self.config['target']['host']
        port = self.config['target']['ports']['ssh']
        start_time = time.time()
        
        result = AttackResult(
            timestamp=datetime.now().isoformat(),
            scenario="ssh_bruteforce",
            protocol="ssh",
            target=target,
            port=port,
            username=username
        )
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Attempt connection
            client.connect(
                hostname=target,
                port=port,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10
            )
            
            result.success = True
            result.details = {"password": password}
            client.close()
            
        except paramiko.AuthenticationException:
            result.error = "Authentication failed"
        except paramiko.SSHException as e:
            result.error = f"SSH error: {str(e)}"
        except socket.timeout:
            result.error = "Connection timeout"
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start_time
        
        return result
    
    async def telnet_attack(self, username: str, password: str) -> AttackResult:
        """Simulate Telnet connection attempt"""
        target = self.config['target']['host']
        port = self.config['target']['ports']['telnet']
        start_time = time.time()
        
        result = AttackResult(
            timestamp=datetime.now().isoformat(),
            scenario="telnet_scan",
            protocol="telnet",
            target=target,
            port=port,
            username=username
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, port))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result.details = {"banner": banner[:100]}
            
            # Send username
            sock.send(f"{username}\r\n".encode())
            time.sleep(0.5)
            
            # Receive password prompt
            sock.recv(1024)
            
            # Send password
            sock.send(f"{password}\r\n".encode())
            time.sleep(0.5)
            
            # Check response
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if "Welcome" in response or "$" in response or "#" in response:
                result.success = True
            
            sock.close()
            
        except socket.timeout:
            result.error = "Connection timeout"
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start_time
        
        return result
    
    async def ftp_attack(self, username: str, password: str) -> AttackResult:
        """Simulate FTP connection attempt"""
        target = self.config['target']['host']
        port = self.config['target']['ports']['ftp']
        start_time = time.time()
        
        result = AttackResult(
            timestamp=datetime.now().isoformat(),
            scenario="ftp_anonymous",
            protocol="ftp",
            target=target,
            port=port,
            username=username
        )
        
        try:
            from ftplib import FTP
            
            ftp = FTP()
            ftp.connect(target, port, timeout=10)
            
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
            result.response_time = time.time() - start_time
        
        return result
    
    async def http_attack(self) -> AttackResult:
        """Simulate HTTP scanning and probing"""
        target = self.config['target']['host']
        port = self.config['target']['ports']['http']
        start_time = time.time()
        
        result = AttackResult(
            timestamp=datetime.now().isoformat(),
            scenario="http_scan",
            protocol="http",
            target=target,
            port=port
        )
        
        # Common attack paths
        paths = [
            "/admin",
            "/login",
            "/.git/config",
            "/wp-admin",
            "/phpmyadmin",
            "/admin.php",
            "/shell.php",
            "/../../../etc/passwd"
        ]
        
        try:
            session = requests.Session()
            
            # Random user agent if enabled
            if self.config['simulation']['fake_user_agents']:
                session.headers.update({
                    'User-Agent': self.faker.user_agent()
                })
            
            results = []
            for path in random.sample(paths, 3):  # Try 3 random paths
                try:
                    url = f"http://{target}:{port}{path}"
                    resp = session.get(url, timeout=5)
                    results.append({
                        "path": path,
                        "status": resp.status_code,
                        "size": len(resp.content)
                    })
                except:
                    pass
            
            result.details = {"paths_tested": results}
            result.success = len(results) > 0
            
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start_time
        
        return result
    
    async def mysql_attack(self, username: str, password: str) -> AttackResult:
        """Simulate MySQL connection attempt"""
        target = self.config['target']['host']
        port = self.config['target']['ports']['mysql']
        start_time = time.time()
        
        result = AttackResult(
            timestamp=datetime.now().isoformat(),
            scenario="mysql_bruteforce",
            protocol="mysql",
            target=target,
            port=port,
            username=username
        )
        
        try:
            import pymysql
            
            connection = pymysql.connect(
                host=target,
                port=port,
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
            result.response_time = time.time() - start_time
        
        return result
    
    async def postgresql_attack(self, username: str, password: str) -> AttackResult:
        """Simulate PostgreSQL connection attempt"""
        target = self.config['target']['host']
        port = self.config['target']['ports']['postgresql']
        start_time = time.time()
        
        result = AttackResult(
            timestamp=datetime.now().isoformat(),
            scenario="postgresql_scan",
            protocol="postgresql",
            target=target,
            port=port,
            username=username
        )
        
        try:
            import psycopg2
            
            connection = psycopg2.connect(
                host=target,
                port=port,
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
            result.response_time = time.time() - start_time
        
        return result
    
    async def smtp_attack(self) -> AttackResult:
        """Simulate SMTP connection and enumeration"""
        target = self.config['target']['host']
        port = self.config['target']['ports']['smtp']
        start_time = time.time()
        
        result = AttackResult(
            timestamp=datetime.now().isoformat(),
            scenario="smtp_enum",
            protocol="smtp",
            target=target,
            port=port
        )
        
        try:
            import smtplib
            
            server = smtplib.SMTP(target, port, timeout=10)
            banner = server.ehlo()
            
            result.details = {"banner": str(banner)}
            result.success = True
            
            server.quit()
            
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            result.response_time = time.time() - start_time
        
        return result
    
    async def run_scenario(self, scenario: Dict):
        """Run a single attack scenario"""
        protocol = scenario['protocol']
        attempts = scenario['attempts']
        delay = scenario['delay']
        
        logger.info(f"{Fore.YELLOW}Starting scenario: {scenario['name']}")
        
        patterns = self.config['patterns'].get(protocol, {})
        usernames = patterns.get('usernames', ['test'])
        passwords = patterns.get('passwords', ['password'])
        
        for i in range(attempts):
            # Select random credentials
            username = random.choice(usernames)
            password = random.choice(passwords)
            
            # Execute attack based on protocol
            if protocol == 'ssh':
                result = await self.ssh_attack(username, password)
            elif protocol == 'telnet':
                result = await self.telnet_attack(username, password)
            elif protocol == 'ftp':
                result = await self.ftp_attack(username, password)
            elif protocol == 'http':
                result = await self.http_attack()
            elif protocol == 'mysql':
                result = await self.mysql_attack(username, password)
            elif protocol == 'postgresql':
                result = await self.postgresql_attack(username, password)
            elif protocol == 'smtp':
                result = await self.smtp_attack()
            else:
                logger.warning(f"Unknown protocol: {protocol}")
                continue
            
            self._log_attack(result)
            
            # Delay between attempts
            if i < attempts - 1:
                await asyncio.sleep(self._get_delay(delay))
        
        logger.info(f"{Fore.YELLOW}Completed scenario: {scenario['name']}")
    
    async def run_all_scenarios(self):
        """Run all enabled attack scenarios"""
        scenarios = [s for s in self.config['scenarios'] if s.get('enabled', True)]
        
        if self.config['simulation']['randomize_order']:
            random.shuffle(scenarios)
        
        logger.info(f"{Fore.GREEN}Starting attack simulation with {len(scenarios)} scenarios")
        
        for scenario in scenarios:
            await self.run_scenario(scenario)
            await asyncio.sleep(2)  # Pause between scenarios
        
        self._save_results()
        self._print_summary()
    
    def _save_results(self):
        """Save results to JSON file"""
        if not self.config['simulation']['save_results']:
            return
        
        output_dir = Path(self.config['simulation']['output_dir'])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_dir / f"attack_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump([asdict(r) for r in self.results], f, indent=2)
        
        logger.info(f"{Fore.GREEN}Results saved to: {filename}")
    
    def _print_summary(self):
        """Print attack summary statistics"""
        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}ATTACK SIMULATION SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Total attacks:     {total}")
        print(f"{Fore.GREEN}Successful:        {successful}")
        print(f"{Fore.RED}Failed:            {total - successful}")
        print(f"{Fore.YELLOW}Success rate:      {(successful/total*100):.1f}%" if total > 0 else "N/A")
        
        # Per-protocol breakdown
        protocols = {}
        for r in self.results:
            if r.protocol not in protocols:
                protocols[r.protocol] = {'total': 0, 'success': 0}
            protocols[r.protocol]['total'] += 1
            if r.success:
                protocols[r.protocol]['success'] += 1
        
        print(f"\n{Fore.CYAN}Per-Protocol Results:")
        for proto, stats in protocols.items():
            rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {proto.upper():12} - {stats['success']}/{stats['total']} ({rate:.1f}%)")
        
        print(f"{Fore.CYAN}{'='*60}\n")


async def main():
    """Main entry point"""
    try:
        simulator = AttackSimulator("config.yaml")
        await simulator.run_all_scenarios()
    except KeyboardInterrupt:
        logger.info(f"\n{Fore.YELLOW}Simulation interrupted by user")
    except Exception as e:
        logger.error(f"{Fore.RED}Error: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())
