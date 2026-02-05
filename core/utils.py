"""
Core Utilities - Colors, banner, and common utilities
"""

import re
import json
import os
import sys
import time
import random
import string
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Try to import psutil for memory monitoring (optional dependency)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None


class Colors:
    """ANSI color codes for terminal output"""
    
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    
    # Colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    @classmethod
    def disable_colors(cls):
        """Disable all colors (for non-terminal output)"""
        for attr in dir(cls):
            if isinstance(getattr(cls, attr), str) and not attr.startswith('_'):
                setattr(cls, attr, '')


class Banner:
    """QuickStrike banner and branding"""
    
    @staticmethod
    def show():
        """Display QuickStrike banner"""
        banner = f"""
{Colors.BRIGHT_CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗             ║
║  ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║             ║
║     ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║             ║
║     ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║             ║
║     ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗        ║
║     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝        ║
║                                                                              ║
║                    {Colors.BRIGHT_YELLOW}Professional Offensive Security{Colors.BRIGHT_CYAN}                     ║
║                   {Colors.BRIGHT_YELLOW}Reconnaissance & Vulnerability Framework{Colors.BRIGHT_CYAN}                ║
║                                                                              ║
║                         {Colors.BRIGHT_GREEN}Version 2.0.0 | Bug Bounty Focused{Colors.BRIGHT_CYAN}                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
        """
        
        # Animated effect
        for line in banner.split('\n'):
            print(line)
            time.sleep(0.01)
        
        print(f"{Colors.BRIGHT_GREEN}[+] QuickStrike initialized - Ready for action{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Target: Exploitable vulnerabilities | Mode: Real-world bug bounty{Colors.RESET}")
        print()
    
    @staticmethod
    def show_mode(mode: str):
        """Display scanning mode information"""
        mode_info = {
            'fast': {
                'name': 'FAST MODE',
                'color': Colors.BRIGHT_YELLOW,
                'description': 'Quick reconnaissance - High-value targets only'
            },
            'bounty': {
                'name': 'BOUNTY MODE',
                'color': Colors.BRIGHT_GREEN,
                'description': 'Comprehensive bug bounty scanning - Reportable issues'
            },
            'deep': {
                'name': 'DEEP MODE',
                'color': Colors.BRIGHT_MAGENTA,
                'description': 'Exhaustive analysis - Maximum coverage'
            }
        }
        
        info = mode_info.get(mode, mode_info['bounty'])
        print(f"{info['color']}{Colors.BOLD}[{info['name']}]{Colors.RESET}")
        print(f"{Colors.DIM}{info['description']}{Colors.RESET}")
        print()


class URLValidator:
    """URL validation and normalization utilities"""
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate domain format"""
        if not domain or len(domain) > 253:
            return False
        
        # Remove protocol and path
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.split('/')[0].split(':')[0]
        
        # Basic domain regex
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, domain) is not None
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain format"""
        # Remove protocols
        domain = domain.replace('http://', '').replace('https://', '')
        
        # Remove paths
        domain = domain.split('/')[0]
        
        # Remove ports
        domain = domain.split(':')[0]
        
        # Convert to lowercase and strip
        domain = domain.lower().strip()
        
        return domain
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL format"""
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url


class RegexPatterns:
    """Common regex patterns for vulnerability detection"""
    
    # API Keys and Tokens
    AWS_ACCESS_KEY = r'AKIA[0-9A-Z]{16}'
    AWS_SECRET_KEY = r'[0-9a-zA-Z/+]{40}'
    STRIPE_KEY = r'sk_live_[0-9a-zA-Z]{24}'
    GOOGLE_API_KEY = r'AIza[0-9A-Za-z\\-_]{35}'
    GITHUB_TOKEN = r'ghp_[0-9a-zA-Z]{36}'
    JWT_TOKEN = r'eyJ[0-9a-zA-Z\-_]+\.eyJ[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+'
    
    # Sensitive Information
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    IP_ADDRESS = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    CREDIT_CARD = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    
    # API Endpoints
    API_PATTERN = r'/api/|/v1/|/v2/|/rest/|/service/|/backend/'
    SWAGGER_PATTERN = r'swagger|openapi|api-docs'
    GRAPHQL_PATTERN = r'/graphql|/graphiql'
    
    # Error Patterns
    SQL_ERROR = r'SQL syntax.*MySQL|Warning.*mysql_|valid PostgreSQL result|Npgsql\.|org\.postgresql\.util\.PSQLException'
    XSS_REFLECTION = r'<script|onerror=|onload=|javascript:'
    LFI_PATTERN = r'root:x:0:0|/bin/bash|/etc/passwd'


class PayloadGenerator:
    """Generate payloads for vulnerability testing"""
    
    @staticmethod
    def generate_idor_payloads(base_id: str) -> List[str]:
        """Generate IDOR test payloads"""
        payloads = []
        
        try:
            # If numeric ID
            if base_id.isdigit():
                base_num = int(base_id)
                payloads.extend([
                    str(base_num - 1),
                    str(base_num + 1),
                    str(base_num + 10),
                    str(base_num + 100),
                    "1",
                    "0",
                    "999999"
                ])
            
            # UUID variations
            if len(base_id) == 36 and '-' in base_id:
                payloads.extend([
                    "00000000-0000-0000-0000-000000000000",
                    "11111111-1111-1111-1111-111111111111",
                    "12345678-1234-1234-1234-123456789012"
                ])
            
            # Common test IDs
            payloads.extend([
                "admin",
                "test",
                "demo",
                "guest",
                "null",
                "undefined"
            ])
            
        except Exception:
            pass
        
        return list(set(payloads))
    
    @staticmethod
    def generate_api_variations(base_path: str) -> List[str]:
        """Generate API path variations"""
        variations = []
        
        # Version variations
        for version in ['v1', 'v2', 'v3', 'v4']:
            variations.append(f"/{version}{base_path}")
        
        # Common prefixes
        prefixes = ['/api', '/rest', '/service', '/backend', '/internal']
        for prefix in prefixes:
            variations.append(f"{prefix}{base_path}")
            for version in ['v1', 'v2']:
                variations.append(f"{prefix}/{version}{base_path}")
        
        # Admin variations
        variations.extend([
            f"{base_path}/admin",
            f"{base_path}/internal",
            f"{base_path}/debug",
            f"{base_path}/test"
        ])
        
        return list(set(variations))
    
    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """Generate random string for testing"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class FileHelper:
    """File system utilities"""
    
    @staticmethod
    def ensure_directory(path: str) -> bool:
        """Ensure directory exists"""
        try:
            os.makedirs(path, exist_ok=True)
            return True
        except Exception:
            return False
    
    @staticmethod
    def safe_filename(filename: str) -> str:
        """Generate safe filename with path traversal protection"""
        if not filename:
            return "unnamed"
        
        # Path traversal protection - remove any path separators
        filename = filename.replace('..', '').replace('/', '_').replace('\\', '_')
        
        # Remove invalid characters
        safe_chars = '-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        filename = ''.join(c for c in filename if c in safe_chars)
        
        # Limit length and prevent empty filenames
        if len(filename) > 200:
            filename = filename[:200]
        
        filename = filename.strip()
        if not filename or filename.isspace():
            filename = "unnamed"
        
        # Ensure filename doesn't start with a dot (hidden file)
        if filename.startswith('.'):
            filename = 'file' + filename
        
        return filename
    
    @staticmethod
    def write_json(data: Any, filepath: str) -> bool:
        """Write data to JSON file"""
        try:
            FileHelper.ensure_directory(os.path.dirname(filepath))
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception:
            return False
    
    @staticmethod
    def write_text(content: str, filepath: str) -> bool:
        """Write text content to file"""
        try:
            FileHelper.ensure_directory(os.path.dirname(filepath))
            with open(filepath, 'w') as f:
                f.write(content)
            return True
        except Exception:
            return False


class ProgressTracker:
    """Simple progress tracking"""
    
    def __init__(self, total: int, description: str = "Progress"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
    
    def update(self, increment: int = 1):
        """Update progress"""
        self.current += increment
        self._print_progress()
    
    def _print_progress(self):
        """Print progress bar"""
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        bar_length = 50
        filled_length = int(bar_length * self.current // self.total) if self.total > 0 else 0
        
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        elapsed = time.time() - self.start_time
        
        if self.current > 0 and self.total > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f"ETA: {eta:.0f}s"
        else:
            eta_str = "ETA: --"
        
        print(f'\r{Colors.GREEN}[{bar}] {percentage:.1f}%{Colors.RESET} '
              f'{self.current}/{self.total} {eta_str}', end='', flush=True)
        
        if self.current >= self.total:
            print()  # New line when complete


def is_terminal() -> bool:
    """Check if running in terminal"""
    return sys.stdout.isatty()


def setup_colors(silent: bool = False):
    """Setup colors based on environment"""
    if silent or not is_terminal():
        Colors.disable_colors()


class MemoryMonitor:
    """Memory monitoring utility for OOM prevention"""
    
    def __init__(self, max_memory_mb: int = 50):
        self.max_memory_mb = max_memory_mb
        if PSUTIL_AVAILABLE:
            self.process = psutil.Process()
        else:
            self.process = None
            print(f"{Colors.YELLOW}[!] psutil not available - memory monitoring disabled{Colors.RESET}")
    
    def check_memory_usage(self) -> Dict[str, Any]:
        """Check current memory usage"""
        if not PSUTIL_AVAILABLE or not self.process:
            return {'current_mb': 0, 'max_mb': self.max_memory_mb, 'exceeded': False, 'percentage': 0}
        
        try:
            memory_info = self.process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024  # Convert to MB
            
            return {
                'current_mb': memory_mb,
                'max_mb': self.max_memory_mb,
                'exceeded': memory_mb > self.max_memory_mb,
                'percentage': (memory_mb / self.max_memory_mb) * 100
            }
        except Exception:
            return {'current_mb': 0, 'max_mb': self.max_memory_mb, 'exceeded': False, 'percentage': 0}
    
    def emergency_write_and_clear(self, data: Any, filepath: str) -> bool:
        """Emergency write to disk and clear memory buffer"""
        try:
            # Write data to disk
            FileHelper.write_json(data, filepath)
            print(f"[!] Memory limit exceeded - emergency wrote data to {filepath}")
            return True
        except Exception as e:
            print(f"[!] Emergency write failed: {e}")
            return False
    
    def should_trigger_emergency_dump(self) -> bool:
        """Check if emergency memory dump should be triggered"""
        memory_status = self.check_memory_usage()
        return memory_status['exceeded']
