"""
CLI Interface - Professional command-line argument parsing and validation
"""

import argparse
import sys
import os
from typing import Optional, List


class CLI:
    """Command Line Interface for QuickStrike"""
    
    def __init__(self):
        self.parser = None
        self.args = None
        
    def parse_args(self):
        """Parse and validate command line arguments"""
        
        self.parser = argparse.ArgumentParser(
            description="QuickStrike - Professional Offensive Security Reconnaissance & Vulnerability Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  quickstrike.py -d example.com --mode bounty
  quickstrike.py -l targets.txt --threads 100 --timeout 15
  quickstrike.py -d example.com --proxy socks5://127.0.0.1:1080 --json
  quickstrike.py -l targets.txt --resume --mode deep
            """
        )
        
        self._create_arguments()
        self.args = self.parser.parse_args()
        
        return self.args
    
    def _create_arguments(self):
        """Create all command line arguments"""
        
        # Target selection (mutually exclusive)
        target_group = self.parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument(
            '-d', '--domain',
            help='Single domain to scan'
        )
        target_group.add_argument(
            '-l', '--targets',
            help='File containing list of targets'
        )
        
        # Scan modes
        self.parser.add_argument(
            '--mode',
            choices=['fast', 'bounty', 'deep'],
            default='bounty',
            help='Scanning mode (default: bounty)'
        )
        
        # Performance options
        self.parser.add_argument(
            '--threads',
            type=int,
            default=50,
            help='Number of concurrent threads (default: 50)'
        )
        self.parser.add_argument(
            '--timeout',
            type=int,
            default=10,
            help='Request timeout in seconds (default: 10)'
        )
        
        # Network options
        self.parser.add_argument(
            '--proxy',
            help='Proxy URL (http://, https://, socks4://, socks5://)'
        )
        
        # Output options
        self.parser.add_argument(
            '--json',
            action='store_true',
            help='Output in JSON format'
        )
        self.parser.add_argument(
            '--markdown',
            action='store_true',
            help='Output in Markdown format'
        )
        self.parser.add_argument(
            '--silent',
            action='store_true',
            help='Silent mode (minimal output)'
        )
        
        # Resume functionality
        self.parser.add_argument(
            '--resume',
            action='store_true',
            help='Resume from last checkpoint'
        )
        
        # Additional options
        self.parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Verbose output'
        )
        self.parser.add_argument(
            '--debug',
            action='store_true',
            help='Debug mode with detailed curl commands and logging'
        )
        self.parser.add_argument(
            '--version',
            action='version',
            version='QuickStrike 2.0.0'
        )
    
    def validate_args(self, args) -> bool:
        """Validate command line arguments"""
        
        # Validate target file exists
        if args.targets and not os.path.exists(args.targets):
            print(f"[!] Target file not found: {args.targets}")
            return False
        
        # Validate thread count
        if args.threads < 1 or args.threads > 1000:
            print("[!] Thread count must be between 1 and 1000")
            return False
        
        # Validate timeout
        if args.timeout < 1 or args.timeout > 300:
            print("[!] Timeout must be between 1 and 300 seconds")
            return False
        
        # Validate proxy format
        if args.proxy and not self._validate_proxy(args.proxy):
            print(f"[!] Invalid proxy format: {args.proxy}")
            return False
        
        # Validate output format conflicts
        if args.json and args.markdown:
            print("[!] Cannot specify both --json and --markdown")
            return False
        
        # Check for conflicting resume with single domain
        if args.resume and args.domain:
            print("[!] Resume only works with target files (-l)")
            return False
        
        return True
    
    def _validate_proxy(self, proxy: str) -> bool:
        """Validate proxy URL format"""
        
        import re
        
        proxy_pattern = r'^(https?|socks4|socks5)://[^:]+:\d+$'
        return re.match(proxy_pattern, proxy) is not None
    
    def get_mode_config(self, mode: str) -> dict:
        """Get configuration for different scanning modes"""
        
        configs = {
            'fast': {
                'modules': [
                    'subdomain_takeover',
                    'cloud_storage',
                    'cors_exploit',
                    'token_leakage'
                ],
                'threads': 100,
                'timeout': 5,
                'aggressive': False
            },
            'bounty': {
                'modules': [
                    'api_discovery',
                    'api_mutation',
                    'swagger_exposure',
                    'graphql_exposure',
                    'unauth_api',
                    'idor_detection',
                    'cors_exploit',
                    'rate_limit',
                    'token_leakage',
                    'cloud_storage',
                    'subdomain_takeover',
                    'ip_bypass'
                ],
                'threads': 50,
                'timeout': 10,
                'aggressive': True
            },
            'deep': {
                'modules': [
                    'api_discovery',
                    'api_mutation',
                    'swagger_exposure',
                    'graphql_exposure',
                    'unauth_api',
                    'idor_detection',
                    'cors_exploit',
                    'rate_limit',
                    'token_leakage',
                    'cloud_storage',
                    'subdomain_takeover',
                    'ip_bypass'
                ],
                'threads': 25,
                'timeout': 15,
                'aggressive': True,
                'deep_scan': True
            }
        }
        
        return configs.get(mode, configs['bounty'])
    
    def print_help(self):
        """Print help message"""
        self.parser.print_help()
    
    def print_version(self):
        """Print version information"""
        print("QuickStrike 2.0.0")
        print("Professional Offensive Security Framework")
        print("Author: Aryan Akbar Joyia (cybersecpro-95)")
