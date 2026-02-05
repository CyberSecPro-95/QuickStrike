"""
Token and Secret Leakage Scanner - Detect exposed tokens, API keys, and secrets
"""

import asyncio
import re
import json
import base64
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass

from core.curl_engine import CurlEngine, CurlResponse
from core.utils import Colors, RegexPatterns


@dataclass
class TokenLeakage:
    """Token/secret leakage finding"""
    url: str
    token_type: str
    leaked_value: str
    context: str
    severity: str
    description: str
    poc_command: str


class TokenLeakageScanner:
    """Advanced token and secret leakage detection"""
    
    def __init__(self, curl_engine: CurlEngine):
        self.curl = curl_engine
        self.findings: List[TokenLeakage] = []
        
        # Enhanced token patterns with context
        self.token_patterns = {
            'aws_access_key': {
                'pattern': RegexPatterns.AWS_ACCESS_KEY,
                'severity': 'Critical',
                'description': 'AWS Access Key ID exposed'
            },
            'aws_secret_key': {
                'pattern': RegexPatterns.AWS_SECRET_KEY,
                'severity': 'Critical',
                'description': 'AWS Secret Key exposed'
            },
            'stripe_publishable': {
                'pattern': r'pk_live_[0-9a-zA-Z]{24}',
                'severity': 'High',
                'description': 'Stripe Publishable Key exposed'
            },
            'stripe_secret': {
                'pattern': RegexPatterns.STRIPE_KEY,
                'severity': 'Critical',
                'description': 'Stripe Secret Key exposed'
            },
            'google_api_key': {
                'pattern': RegexPatterns.GOOGLE_API_KEY,
                'severity': 'High',
                'description': 'Google API Key exposed'
            },
            'github_token': {
                'pattern': RegexPatterns.GITHUB_TOKEN,
                'severity': 'Critical',
                'description': 'GitHub Personal Access Token exposed'
            },
            'jwt_token': {
                'pattern': RegexPatterns.JWT_TOKEN,
                'severity': 'High',
                'description': 'JWT Token exposed'
            },
            'slack_token': {
                'pattern': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
                'severity': 'High',
                'description': 'Slack Token exposed'
            },
            'discord_token': {
                'pattern': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
                'severity': 'High',
                'description': 'Discord Token exposed'
            },
            'twitter_api_key': {
                'pattern': r'[a-zA-Z0-9]{25,50}',
                'severity': 'Medium',
                'description': 'Twitter API Key exposed'
            },
            'facebook_access_token': {
                'pattern': r'EAACEdEose0cBA[0-9A-Za-z]+',
                'severity': 'High',
                'description': 'Facebook Access Token exposed'
            },
            'api_key_generic': {
                'pattern': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{16,}["\']?',
                'severity': 'Medium',
                'description': 'Generic API Key exposed'
            },
            'secret_key': {
                'pattern': r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{16,}["\']?',
                'severity': 'High',
                'description': 'Secret Key exposed'
            },
            'private_key': {
                'pattern': r'-----BEGIN (RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----',
                'severity': 'Critical',
                'description': 'Private Key exposed'
            },
            'database_url': {
                'pattern': r'(mysql|postgresql|mongodb)://[^\s\'"<>]+',
                'severity': 'Critical',
                'description': 'Database URL with credentials exposed'
            },
            'bearer_token': {
                'pattern': r'Bearer\s+[a-zA-Z0-9\-._~+/]+=*',
                'severity': 'Medium',
                'description': 'Bearer Token exposed'
            }
        }
        
        # High-value files to scan
        self.sensitive_files = [
            '/.env',
            '/config.json',
            '/settings.json',
            '/database.yml',
            '/.git/config',
            '/webpack.config.js',
            '/gulpfile.js',
            '/Gruntfile.js',
            '/package.json',
            '/composer.json',
            '/requirements.txt',
            '/Dockerfile',
            '/docker-compose.yml',
            '/Vagrantfile',
            '/.htaccess',
            '/web.config',
            '/.bashrc',
            '/.bash_history',
            '/.zshrc',
            '/.vimrc',
            '/id_rsa',
            '/id_rsa.pub',
            '/known_hosts'
        ]
        
        # JavaScript files to scan
        self.js_patterns = [
            '/app.js',
            '/main.js',
            '/bundle.js',
            '/vendor.js',
            '/config.js',
            '/api.js',
            '/auth.js',
            '/constants.js',
            '/environment.js',
            '/static/js/app.js',
            '/assets/js/main.js',
            '/js/app.js',
            '/javascript/app.js'
        ]
    
    async def scan_target(self, base_url: str, discovered_endpoints: List[str] = None) -> List[TokenLeakage]:
        """Scan target for token and secret leakage"""
        
        print(f"{Colors.YELLOW}[*] Scanning for token leakage on: {base_url}{Colors.RESET}")
        
        # Normalize base URL
        base_url = self._normalize_url(base_url)
        
        # Scan main page
        await self._scan_page(base_url)
        
        # Scan sensitive files
        await self._scan_sensitive_files(base_url)
        
        # Scan JavaScript files
        await self._scan_javascript_files(base_url)
        
        # Scan discovered endpoints
        if discovered_endpoints:
            await self._scan_endpoints(discovered_endpoints)
        
        # Scan API responses
        await self._scan_api_endpoints(base_url)
        
        print(f"{Colors.GREEN}[+] Found {len(self.findings)} token leakage issues{Colors.RESET}")
        return self.findings
    
    async def _scan_page(self, url: str):
        """Scan main page for tokens"""
        
        try:
            response = await self.curl.get(url)
            
            if response.status_code == 200:
                await self._analyze_response(response, url)
        
        except Exception:
            pass
    
    async def _scan_sensitive_files(self, base_url: str):
        """Scan sensitive configuration files"""
        
        tasks = []
        
        for file_path in self.sensitive_files:
            file_url = urljoin(base_url, file_path)
            task = asyncio.create_task(self._scan_file(file_url, file_path))
            tasks.append(task)
        
        # Execute with rate limiting
        batch_size = 5
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
    
    async def _scan_javascript_files(self, base_url: str):
        """Scan JavaScript files for embedded tokens"""
        
        tasks = []
        
        for js_path in self.js_patterns:
            js_url = urljoin(base_url, js_path)
            task = asyncio.create_task(self._scan_file(js_url, js_path))
            tasks.append(task)
        
        # Execute with rate limiting
        batch_size = 3
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
    
    async def _scan_endpoints(self, endpoints: List[str]):
        """Scan discovered endpoints for tokens"""
        
        tasks = []
        
        for endpoint in endpoints[:20]:  # Limit for performance
            task = asyncio.create_task(self._scan_endpoint(endpoint))
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _scan_api_endpoints(self, base_url: str):
        """Scan API endpoints for token leakage"""
        
        api_endpoints = [
            '/api/config',
            '/api/settings',
            '/api/keys',
            '/api/tokens',
            '/api/auth/config',
            '/v1/config',
            '/v2/settings'
        ]
        
        for endpoint in api_endpoints:
            api_url = urljoin(base_url, endpoint)
            await self._scan_endpoint(api_url)
    
    async def _scan_file(self, url: str, file_path: str):
        """Scan specific file for tokens"""
        
        try:
            response = await self.curl.get(url)
            
            if response.status_code == 200:
                await self._analyze_response(response, url, file_path)
        
        except Exception:
            pass
    
    async def _scan_endpoint(self, url: str):
        """Scan endpoint for tokens"""
        
        try:
            response = await self.curl.get(url)
            
            if response.status_code == 200:
                await self._analyze_response(response, url)
        
        except Exception:
            pass
    
    async def _analyze_response(self, response: CurlResponse, url: str, context: str = ""):
        """Analyze response for token patterns"""
        
        content = response.body
        
        # Check each token pattern
        for token_type, token_info in self.token_patterns.items():
            pattern = token_info['pattern']
            
            # Find all matches
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                token_value = match.group()
                
                # Validate the finding
                if self._validate_token(token_type, token_value, content):
                    
                    # Extract context around the token
                    context_snippet = self._extract_context(content, match.start(), match.end())
                    
                    # Create finding
                    finding = TokenLeakage(
                        url=url,
                        token_type=token_type,
                        leaked_value=self._mask_token(token_type, token_value),
                        context=context_snippet,
                        severity=token_info['severity'],
                        description=token_info['description'],
                        poc_command=f"curl -s '{url}'"
                    )
                    
                    self.findings.append(finding)
    
    def _validate_token(self, token_type: str, token_value: str, content: str) -> bool:
        """Validate if the found token is legitimate"""
        
        # Skip obvious false positives
        false_positive_patterns = [
            r'example',
            r'test',
            r'demo',
            r'fake',
            r'sample',
            r'xxx',
            r'yyy',
            r'zzz',
            r'placeholder',
            r'your_api_key_here',
            r'replace_with_your_key'
        ]
        
        token_lower = token_value.lower()
        
        # Check for false positive indicators
        for fp_pattern in false_positive_patterns:
            if fp_pattern in token_lower:
                return False
        
        # Additional validation for specific token types
        if token_type == 'jwt_token':
            return self._validate_jwt(token_value)
        elif token_type == 'aws_access_key':
            return self._validate_aws_key(token_value)
        elif token_type == 'github_token':
            return self._validate_github_token(token_value)
        
        return True
    
    def _validate_jwt(self, token: str) -> bool:
        """Validate JWT token structure"""
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
            
            # Try to decode header and payload
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
            
            # Check for required JWT fields
            if 'alg' in header and ('exp' in payload or 'iat' in payload):
                return True
        
        except Exception:
            pass
        
        return False
    
    def _validate_aws_key(self, key: str) -> bool:
        """Validate AWS key format"""
        
        # AWS Access Key ID format: AKIAxxxxxxxxxxxxxxx
        if not key.startswith('AKIA'):
            return False
        
        if len(key) != 20:
            return False
        
        return True
    
    def _validate_github_token(self, token: str) -> bool:
        """Validate GitHub token format"""
        
        # GitHub Personal Access Token: ghp_xxxxxxxxxxxxxxxxxxxx
        if not token.startswith('ghp_'):
            return False
        
        if len(token) != 40:  # ghp_ + 36 characters
            return False
        
        return True
    
    def _extract_context(self, content: str, start: int, end: int, context_size: int = 100) -> str:
        """Extract context around the token"""
        
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        
        context = content[context_start:context_end]
        
        # Add ellipsis if truncated
        if context_start > 0:
            context = '...' + context
        if context_end < len(content):
            context = context + '...'
        
        return context.strip()
    
    def _mask_token(self, token_type: str, token_value: str) -> str:
        """Mask sensitive parts of the token for display"""
        
        if token_type in ['aws_secret_key', 'stripe_secret', 'github_token']:
            # Show first 4 and last 4 characters
            if len(token_value) > 8:
                return token_value[:4] + '*' * (len(token_value) - 8) + token_value[-4:]
        
        elif token_type == 'jwt_token':
            # Show first part only
            parts = token_value.split('.')
            if len(parts) >= 2:
                return parts[0] + '.***.' + parts[-1][:10] + '...'
        
        elif token_type == 'aws_access_key':
            # Show full access key (less sensitive)
            return token_value
        
        # Default: show first 8 characters
        if len(token_value) > 8:
            return token_value[:8] + '...'
        
        return token_value
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    def get_critical_findings(self) -> List[TokenLeakage]:
        """Get critical severity findings"""
        
        return [finding for finding in self.findings if finding.severity == 'Critical']
    
    def get_high_value_findings(self) -> List[TokenLeakage]:
        """Get high and critical severity findings"""
        
        return [finding for finding in self.findings 
                if finding.severity in ['Critical', 'High']]
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate summary report of findings"""
        
        summary = {
            'total_findings': len(self.findings),
            'by_severity': {},
            'by_type': {},
            'by_url': {}
        }
        
        # Count by severity
        for finding in self.findings:
            severity = finding.severity
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        
        # Count by token type
        for finding in self.findings:
            token_type = finding.token_type
            summary['by_type'][token_type] = summary['by_type'].get(token_type, 0) + 1
        
        # Count by URL
        for finding in self.findings:
            url = finding.url
            summary['by_url'][url] = summary['by_url'].get(url, 0) + 1
        
        return summary
