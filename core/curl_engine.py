"""
Curl Execution Engine - Secure subprocess wrapper for all HTTP operations
"""

import asyncio
import subprocess
import json
import re
import urllib.parse
import shlex
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

# Import for debug output
from core.utils import Colors

# Import global shutdown event for immediate termination
try:
    from core.shutdown import shutdown_event
except ImportError:
    # Fallback for standalone usage
    shutdown_event = None

# Modern browser User-Agent pool for stealth
USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
]


@dataclass
class CurlResponse:
    """HTTP Response data structure"""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time: float
    redirect_url: str
    content_length: int
    content_type: str
    error: Optional[str] = None


class CurlEngine:
    """High-performance curl execution engine with security hardening"""
    
    def __init__(self, timeout: int = 10, max_redirects: int = 5, 
                 proxy: Optional[str] = None, user_agent: str = None, debug: bool = False):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.proxy = proxy
        self.user_agent = user_agent or random.choice(USER_AGENTS)
        self.debug = debug
        
        # Security: Allowed curl options whitelist
        self.allowed_options = {
            'silent', 'location', 'max-redirs', 'connect-timeout', 'max-time',
            'user-agent', 'header', 'data', 'request', 'proxy', 'insecure',
            'compressed', 'resolve', 'dns-servers'
        }
        
    async def get(self, url: str, headers: Optional[Dict[str, str]] = None,
                  follow_redirects: bool = True, **kwargs) -> CurlResponse:
        """Perform HTTP GET request"""
        return await self._request('GET', url, headers=headers, 
                                 follow_redirects=follow_redirects, **kwargs)
    
    async def post(self, url: str, data: Optional[Dict[str, Any]] = None,
                   headers: Optional[Dict[str, str]] = None, **kwargs) -> CurlResponse:
        """Perform HTTP POST request"""
        return await self._request('POST', url, data=data, headers=headers, **kwargs)
    
    async def head(self, url: str, headers: Optional[Dict[str, str]] = None,
                   **kwargs) -> CurlResponse:
        """Perform HTTP HEAD request"""
        return await self._request('HEAD', url, headers=headers, **kwargs)
    
    async def options(self, url: str, headers: Optional[Dict[str, str]] = None,
                      **kwargs) -> CurlResponse:
        """Perform HTTP OPTIONS request"""
        return await self._request('OPTIONS', url, headers=headers, **kwargs)
    
    async def batch_request(self, requests: List[Dict[str, Any]]) -> List[CurlResponse]:
        """Perform multiple requests concurrently"""
        tasks = []
        for req in requests:
            method = req.get('method', 'GET')
            url = req.get('url')
            if url:
                task = asyncio.create_task(
                    self._request(method, url, **{k: v for k, v in req.items() 
                                               if k not in ['method', 'url']})
                )
                tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in responses if isinstance(r, CurlResponse)]
    
    async def _request(self, method: str, url: str, data: Optional[Dict[str, Any]] = None,
                       headers: Optional[Dict[str, str]] = None,
                       follow_redirects: bool = True, **kwargs) -> CurlResponse:
        """Internal request method with security hardening"""
        
        # Security: Validate URL
        if not self._is_safe_url(url):
            return CurlResponse(
                url=url, status_code=0, headers={}, body="", response_time=0,
                redirect_url="", content_length=0, content_type="",
                error="Unsafe URL detected"
            )
        
        # Build curl command with security considerations
        cmd = self._build_curl_command(method, url, data, headers, follow_redirects, **kwargs)
        
        # Debug output
        if self.debug:
            print(f"{Colors.MAGENTA}[DEBUG] Curl command: {' '.join(cmd)}{Colors.RESET}")
        
        try:
            # Execute curl with timeout and resource limits
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024*1024*10  # 10MB output limit
            )
            
            # Wait for completion with timeout and shutdown check
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=self.timeout + 5
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return CurlResponse(
                    url=url, status_code=0, headers={}, body="", response_time=0,
                    redirect_url="", content_length=0, content_type="",
                    error="Request timeout"
                )
            except (asyncio.CancelledError, KeyboardInterrupt):
                # Immediate termination on shutdown
                if process and process.returncode is None:
                    process.terminate()
                    await process.wait()
                raise
            
            # Parse response
            response = self._parse_response(stdout.decode('utf-8', errors='ignore'), url)
            
            # Check for curl errors
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore').strip()
                if error_msg:
                    response.error = error_msg
            
            return response
            
        except Exception as e:
            return CurlResponse(
                url=url, status_code=0, headers={}, body="", response_time=0,
                redirect_url="", content_length=0, content_type="",
                error=f"Request failed: {str(e)}"
            )
    
    def _build_curl_command(self, method: str, url: str, data: Optional[Dict[str, Any]],
                           headers: Optional[Dict[str, str]], follow_redirects: bool,
                           **kwargs) -> List[str]:
        """Build secure curl command"""
        
        # Select random User-Agent for each request
        current_user_agent = random.choice(USER_AGENTS)
        
        # Base command with security options
        cmd = [
            'curl',
            '-s',  # Silent mode
            '-k',  # Ignore SSL certificate errors
            '--connect-timeout', str(self.timeout),
            '--max-time', str(self.timeout + 5),
            '-A', current_user_agent,
            '--compressed',  # Accept compression
            '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'  # Standard Accept header
        ]
        
        # Handle redirects
        if follow_redirects:
            cmd.extend(['-L', '--max-redirs', str(self.max_redirects)])
        
        # Add write format for response parsing
        cmd.extend(['-w', self._get_write_format()])
        
        # Add proxy if specified
        if self.proxy:
            cmd.extend(['--proxy', self.proxy])
        
        # Add custom headers
        if headers:
            for key, value in headers.items():
                # Security: Validate header values
                if self._is_safe_header_value(str(value)):
                    cmd.extend(['-H', f'{key}: {value}'])
        
        # Add request method
        cmd.extend(['-X', method.upper()])
        
        # Add data for POST/PUT requests
        if data and method.upper() in ['POST', 'PUT', 'PATCH']:
            if isinstance(data, dict):
                data_str = urllib.parse.urlencode(data)
                cmd.extend(['-d', data_str])
                cmd.extend(['-H', 'Content-Type: application/x-www-form-urlencoded'])
            else:
                cmd.extend(['-d', str(data)])
        
        # Additional options from kwargs
        for key, value in kwargs.items():
            if key in self.allowed_options:
                if isinstance(value, bool) and value:
                    cmd.extend([f'--{key}'])
                elif not isinstance(value, bool):
                    cmd.extend([f'--{key}', str(value)])
        
        # Add URL as last argument
        cmd.append(url)
        
        return cmd
    
    def _get_write_format(self) -> str:
        """Custom curl output format for parsing"""
        return '%{http_code}|%{time_total}|%{redirect_url}|%{size_download}|%{content_type}'
    
    def _parse_response(self, output: str, url: str) -> CurlResponse:
        """Parse curl response output"""
        
        # Initialize response object
        response = CurlResponse(
            url=url,
            status_code=0,
            headers={},
            body="",
            response_time=0.0,
            redirect_url="",
            content_length=0,
            content_type=""
        )
        
        # Split output into metadata and body
        if '|' in output:
            # Parse metadata from the last line that contains pipe
            lines = output.strip().split('\n')
            metadata_line = None
            
            # Find the line with metadata (contains pipe characters)
            for line in lines:
                if '|' in line and any(char in line for char in ['200', '302', '404']):
                    metadata_line = line
                    break
            
            if metadata_line:
                parts = metadata_line.split('|')
                if len(parts) >= 5:
                    try:
                        response.status_code = int(parts[0]) if parts[0] else 0
                        response.response_time = float(parts[1]) if parts[1] else 0.0
                        response.redirect_url = parts[2] if parts[2] else ""
                        response.content_length = int(parts[3]) if parts[3] else 0
                        response.content_type = parts[4] if parts[4] else ""
                    except (ValueError, IndexError):
                        pass
                
                # Everything before metadata line is body
                if lines:
                    metadata_index = lines.index(metadata_line) if metadata_line in lines else -1
                    if metadata_index > 0:
                        response.body = '\n'.join(lines[:metadata_index])
                    else:
                        # If no clear separation, remove the metadata line from body
                        response.body = '\n'.join([line for line in lines if line != metadata_line])
            else:
                # Fallback: treat everything as body
                response.body = output
        
        # JSON validation for JSON content types
        if response.content_type and 'json' in response.content_type.lower():
            if response.body.strip():
                try:
                    json.loads(response.body)
                except json.JSONDecodeError as e:
                    response.error = f"Invalid JSON response: {str(e)}"
                    response.status_code = 0  # Mark as invalid
        
        return response
    
    def _is_safe_url(self, url: str) -> bool:
        """Security: Validate URL to prevent injection attacks"""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Only allow http and https
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Prevent file:// and other dangerous protocols
            if parsed.scheme in ['file', 'ftp', 'ldap', 'gopher']:
                return False
            
            # Basic URL structure validation
            if not parsed.netloc:
                return False
            
            # Prevent command injection in URL
            dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '<', '>', '"', "'"]
            if any(char in url for char in dangerous_chars):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _is_safe_header_value(self, value: str) -> bool:
        """Security: Validate header values"""
        # Prevent header injection
        dangerous_chars = ['\\n', '\\r', '\\0']
        if any(char in value for char in dangerous_chars):
            return False
        
        # Reasonable length limit
        if len(value) > 8192:
            return False
        
        return True
    
    async def test_connection(self, url: str) -> bool:
        """Test basic connectivity to URL"""
        try:
            response = await self.head(url)
            return response.status_code > 0 and response.error is None
        except Exception:
            return False
    
    def set_proxy(self, proxy: str):
        """Update proxy settings"""
        if proxy and self._is_safe_url(proxy):
            self.proxy = proxy
    
    def set_user_agent(self, user_agent: str):
        """Update user agent"""
        if user_agent and len(user_agent) < 512:
            self.user_agent = user_agent
