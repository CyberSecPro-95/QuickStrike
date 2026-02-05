#!/usr/bin/env python3
"""
QuickStrike - Professional Offensive Security Reconnaissance & Vulnerability Framework
Author: Aryan Akbar Joyia (cybersecpro-95)
Description: Bug bounty focused vulnerability discovery framework
"""

import asyncio
import argparse
import sys
import json
import os
import signal
from pathlib import Path
from datetime import datetime

from core.cli import CLI
from core.scanner import Scanner
from core.output import OutputEngine, show_startup_banner
from core.utils import Colors, Banner
from core.shutdown import shutdown_event


class QuickStrike:
    """Main QuickStrike framework class"""
    
    def __init__(self):
        self.scanner = None
        self.output_engine = None
        self.shutdown_event = shutdown_event
        
    async def initialize(self, args):
        """Initialize framework components"""
        self.output_engine = OutputEngine(args)
        self.scanner = Scanner(args, self.output_engine)
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals - Hard Kill implementation"""
        print(f"\n{Colors.YELLOW}[!] Shutdown signal received. Terminating immediately...{Colors.RESET}")
        shutdown_event.set()
        # Force exit after cleanup message
        sys.exit(0)
        
    async def run(self, args):
        """Main execution method"""
        try:
            await self.initialize(args)
            
            # Load targets
            targets = await self._load_targets(args)
            if not targets:
                print(f"{Colors.RED}[!] No valid targets found{Colors.RESET}")
                return
                
            print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets{Colors.RESET}")
            
            # Start scanning
            results = await self.scanner.scan_targets(targets)
            
            # Generate output
            await self.output_engine.generate_results(results)
            
            print(f"{Colors.GREEN}[+] QuickStrike completed successfully{Colors.RESET}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Fatal error: {str(e)}{Colors.RESET}")
            if args.verbose:
                import traceback
                traceback.print_exc()
                
    async def _load_targets(self, args):
        """Load and validate targets"""
        targets = []
        
        if args.domain:
            # Single domain - normalize first, then validate
            normalized_domain = self._normalize_domain(args.domain)
            if normalized_domain and self._validate_domain(normalized_domain):
                targets.append(normalized_domain)
            else:
                print(f"{Colors.RED}[!] Invalid domain format: {args.domain}{Colors.RESET}")
                
        elif args.targets:
            # Multiple targets from file
            if not os.path.exists(args.targets):
                print(f"{Colors.RED}[!] Target file not found: {args.targets}{Colors.RESET}")
                return targets
                
            try:
                with open(args.targets, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            domain = self._normalize_domain(line)
                            if domain and self._validate_domain(domain):
                                targets.append(domain)
                                
                # Remove duplicates
                targets = list(set(targets))
                
            except Exception as e:
                print(f"{Colors.RED}[!] Error reading target file: {str(e)}{Colors.RESET}")
                
        return targets
        
    def _validate_domain(self, domain):
        """Validate domain format"""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, domain) is not None
        
    def _normalize_domain(self, domain):
        """Normalize domain format - strip protocols, paths, ports, and trailing slashes"""
        if not domain:
            return None
            
        domain = domain.strip()
        
        # Remove protocols (http://, https://, ftp://, etc.)
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # Remove paths
        domain = domain.split('/')[0]
        
        # Remove ports
        domain = domain.split(':')[0]
        
        # Remove trailing slashes
        domain = domain.rstrip('/')
        
        # Convert to lowercase
        domain = domain.lower()
        
        return domain if domain else None


async def main():
    """Main entry point"""
    # Parse CLI arguments first to get silent flag
    cli = CLI()
    args = cli.parse_args()
    
    # Display professional startup banner (respects --silent flag)
    show_startup_banner(silent=args.silent)
    
    # Validate arguments
    if not cli.validate_args(args):
        sys.exit(1)
        
    # Run QuickStrike
    quickstrike = QuickStrike()
    await quickstrike.run(args)


if __name__ == "__main__":
    asyncio.run(main())
