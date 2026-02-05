"""
API Endpoint Discovery Module - Find high-value API endpoints
"""

import asyncio
import json
import re
from dataclasses import dataclass
from typing import List, Set, Optional, Dict
from urllib.parse import urljoin, urlparse

from core.curl_engine import CurlEngine, CurlResponse
from core.utils import Colors, RegexPatterns, PayloadGenerator


@dataclass
class APIEndpoint:
    """API endpoint data structure"""
    url: str
    method: str
    status_code: int
    content_type: str
    response_size: int
    auth_required: bool
    parameters: List[str]
    headers: Dict[str, str]
    description: str = ""


class APIDiscovery:
    """Advanced API endpoint discovery"""
    
    def __init__(self, curl_engine: CurlEngine):
        self.curl = curl_engine
        self.discovered_endpoints: List[APIEndpoint] = []
        
        # High-value API patterns
        self.api_patterns = [
            # Core API patterns
            '/api/v1/', '/api/v2/', '/api/v3/', '/api/v4/',
            '/rest/', '/service/', '/backend/', '/internal/',
            
            # Common endpoints
            '/api/users', '/api/auth', '/api/admin', '/api/data',
            '/api/config', '/api/settings', '/api/profile',
            '/api/orders', '/api/payments', '/api/products',
            
            # Version-specific
            '/v1/users', '/v1/auth', '/v1/admin', '/v1/data',
            '/v2/users', '/v2/auth', '/v2/admin', '/v2/data',
            
            # Common paths
            '/graphql', '/graphiql', '/api-docs', '/swagger',
            '/api/docs', '/rest/api', '/webhook', '/callback',
            
            # Admin/management
            '/admin/api', '/management/api', '/control/api',
            '/system/api', '/config/api', '/debug/api'
        ]
        
        # Common API file extensions
        self.api_files = [
            '/api.json', '/api.yaml', '/openapi.json', '/swagger.json',
            '/api.php', '/api.asp', '/api.jsp', '/api.rb'
        ]
        
    async def scan_endpoints(self, base_url: str, discovered_endpoints: List[str] = None) -> List[APIEndpoint]:
        """Main method to scan for API endpoints"""
        
        print(f"{Colors.YELLOW}[*] Starting API endpoint discovery for: {base_url}{Colors.RESET}")
        
        # Normalize base URL
        base_url = self._normalize_url(base_url)
        
        # Test discovered endpoints
        if discovered_endpoints:
            await self._test_discovered_endpoints(discovered_endpoints)
        
        # Discover from various sources
        await self._discover_from_common_paths(base_url)
        await self._discover_from_js_files(base_url)
        await self._discover_from_api_docs(base_url)
        
        # Always test common pages that might have AJAX
        common_pages = ['/search', '/products', '/contacts', '/']
        for page in common_pages:
            page_url = urljoin(base_url, page)
            endpoint = await self._test_endpoint(page_url)
            if endpoint:
                self.discovered_endpoints.append(endpoint)
                print(f"{Colors.GREEN}[+] Found AJAX endpoint: {page_url}{Colors.RESET}")
        
        # If no endpoints found, add basic pages as endpoints for testing
        if not self.discovered_endpoints:
            print(f"{Colors.YELLOW}[*] No API endpoints found, adding basic pages for testing{Colors.RESET}")
            for page in common_pages:
                page_url = urljoin(base_url, page)
                endpoint = APIEndpoint(
                    url=page_url,
                    method='GET',
                    status_code=200,
                    content_type='text/html',
                    response_size=0,
                    auth_required=False,
                    parameters=[],
                    headers={},
                    description=f"Basic page for testing: {page}"
                )
                self.discovered_endpoints.append(endpoint)
        
        print(f"{Colors.GREEN}[+] Discovered {len(self.discovered_endpoints)} API endpoints{Colors.RESET}")
        return self.discovered_endpoints
    
    async def _discover_from_patterns(self, base_url: str):
        """Discover endpoints using common patterns"""
        
        tasks = []
        
        for pattern in self.api_patterns:
            # Test with different base paths
            test_urls = [
                urljoin(base_url, pattern),
                urljoin(base_url, pattern.lstrip('/')),
                urljoin(base_url, f"{pattern}/users"),
                urljoin(base_url, f"{pattern}/auth")
            ]
            
            for url in test_urls:
                task = asyncio.create_task(self._test_endpoint(url))
                tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, APIEndpoint):
                self.discovered_endpoints.append(result)
    
    async def _discover_from_js_files(self, base_url: str):
        """Discover endpoints from JavaScript files"""
        
        # Common JS file locations
        js_patterns = [
            '/app.js', '/main.js', '/bundle.js', '/api.js',
            '/static/js/app.js', '/assets/js/main.js',
            '/js/app.js', '/javascript/app.js'
        ]
        
        for pattern in js_patterns:
            js_url = urljoin(base_url, pattern)
            
            try:
                response = await self.curl.get(js_url)
                
                if response.status_code == 200 and 'javascript' in response.content_type:
                    endpoints = self._extract_endpoints_from_js(response.body, base_url)
                    
                    for endpoint_url in endpoints:
                        endpoint = await self._test_endpoint(endpoint_url)
                        if endpoint:
                            self.discovered_endpoints.append(endpoint)
                            
            except Exception:
                continue
    
    async def _discover_from_robots_txt(self, base_url: str):
        """Discover endpoints from robots.txt"""
        
        robots_url = urljoin(base_url, '/robots.txt')
        
        try:
            response = await self.curl.get(robots_url)
            
            if response.status_code == 200:
                # Extract API paths from robots.txt
                api_paths = re.findall(r'/api/|/v\d+/|/rest/|/graphql/', response.body)
                
                for path in set(api_paths):
                    endpoint_url = urljoin(base_url, path)
                    endpoint = await self._test_endpoint(endpoint_url)
                    if endpoint:
                        self.discovered_endpoints.append(endpoint)
                        
        except Exception:
            pass
    
    async def _discover_from_common_paths(self, base_url: str):
        """Discover endpoints from common API paths"""
        
        # Test common API files
        for file_path in self.api_files:
            file_url = urljoin(base_url, file_path)
            
            try:
                response = await self.curl.head(file_url)
                
                if response.status_code == 200:
                    endpoint = APIEndpoint(
                        url=file_url,
                        method='GET',
                        status_code=response.status_code,
                        content_type=response.content_type,
                        response_size=response.content_length,
                        auth_required=False,
                        parameters=[],
                        headers=response.headers,
                        description=f"API file discovered: {file_path}"
                    )
                    self.discovered_endpoints.append(endpoint)
                    
            except Exception:
                continue
    
    async def _discover_from_api_docs(self, base_url: str):
        """Discover endpoints from API documentation"""
        
        doc_patterns = [
            '/swagger.json', '/openapi.json', '/api-docs',
            '/swagger-ui.html', '/api/docs', '/docs/api'
        ]
        
        for pattern in doc_patterns:
            doc_url = urljoin(base_url, pattern)
            
            try:
                response = await self.curl.get(doc_url)
                
                if response.status_code == 200:
                    # Parse OpenAPI/Swagger specs
                    if 'json' in response.content_type:
                        endpoints = self._parse_openapi_spec(response.body, base_url)
                        self.discovered_endpoints.extend(endpoints)
                    
                    # Add documentation endpoint
                    endpoint = APIEndpoint(
                        url=doc_url,
                        method='GET',
                        status_code=response.status_code,
                        content_type=response.content_type,
                        response_size=response.content_length,
                        auth_required=False,
                        parameters=[],
                        headers=response.headers,
                        description=f"API documentation: {pattern}"
                    )
                    self.discovered_endpoints.append(endpoint)
                    
            except Exception:
                continue
    
    async def _test_endpoint(self, url: str, method: str = 'GET') -> Optional[APIEndpoint]:
        """Test if URL is a valid API endpoint"""
        
        try:
            # Test with different methods
            methods = [method, 'OPTIONS', 'HEAD']
            
            for test_method in methods:
                if test_method == 'GET':
                    response = await self.curl.get(url)
                elif test_method == 'OPTIONS':
                    response = await self.curl.options(url)
                else:
                    response = await self.curl.head(url)
                
                if response.status_code < 500:  # Valid response
                    # Check if it's actually an API endpoint
                    is_api = self._is_api_endpoint(response)
                    
                    if is_api:
                        parameters = self._extract_parameters(response.body)
                        auth_required = self._requires_auth(response)
                        
                        return APIEndpoint(
                            url=url,
                            method=test_method,
                            status_code=response.status_code,
                            content_type=response.content_type,
                            response_size=response.content_length,
                            auth_required=auth_required,
                            parameters=parameters,
                            headers=response.headers,
                            description=self._generate_description(response)
                        )
                        
        except Exception:
            pass
        
        return None
    
    def _extract_endpoints_from_js(self, js_content: str, base_url: str) -> Set[str]:
        """Extract API endpoints from JavaScript content"""
        
        endpoints = set()
        
        # Regex patterns for API endpoints
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'data-naja="([^"]*)"',
            r'do=([^"&\s]*)',
            r'selectedTab=([^"&\s]*)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            
            for match in matches:
                if match.startswith('/'):
                    endpoint_url = urljoin(base_url, match)
                    endpoints.add(endpoint_url)
                elif match in ['switchTab', 'logout', 'login', 'admin']:
                    # This indicates AJAX functionality on the current page
                    endpoints.add(base_url)
        
        return endpoints
    
    def _parse_openapi_spec(self, spec_content: str, base_url: str) -> List[APIEndpoint]:
        """Parse OpenAPI/Swagger specification"""
        
        endpoints = []
        
        try:
            spec = json.loads(spec_content)
            
            # Extract paths from OpenAPI spec
            paths = spec.get('paths', {})
            
            for path, path_obj in paths.items():
                for method, method_obj in path_obj.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoint_url = urljoin(base_url, path)
                        
                        endpoint = APIEndpoint(
                            url=endpoint_url,
                            method=method.upper(),
                            status_code=0,  # Not tested yet
                            content_type='application/json',
                            response_size=0,
                            auth_required=self._check_auth_required(method_obj),
                            parameters=self._extract_openapi_parameters(method_obj),
                            headers={},
                            description=f"OpenAPI spec: {method.upper()} {path}"
                        )
                        endpoints.append(endpoint)
                        
        except Exception:
            pass
        
        return endpoints
    
    def _is_api_endpoint(self, response: CurlResponse) -> bool:
        """Determine if response indicates an API endpoint"""
        
        # Check content type
        api_content_types = [
            'application/json',
            'application/xml',
            'text/xml',
            'application/vnd.api+json'
        ]
        
        if any(content_type in response.content_type for content_type in api_content_types):
            return True
        
        # Check for AJAX indicators in response body
        body_lower = response.body.lower()
        ajax_indicators = [
            'data-naja',
            'switchtab',
            'do=',
            'selectedtab',
            'ajax',
            'json',
            'xml'
        ]
        
        if any(indicator in body_lower for indicator in ajax_indicators):
            return True
        
        # Check for framework patterns
        framework_patterns = [
            'nette framework',
            'csrf token',
            'ajax request'
        ]
        
        if any(pattern in body_lower for pattern in framework_patterns):
            return True
        
        # Check for API patterns in URL
        if any(pattern in response.url.lower() for pattern in ['/api/', '/v1/', '/rest/', '/graphql']):
            return True
        
        return False
    
    def _extract_parameters(self, response_body: str) -> List[str]:
        """Extract parameters from response body"""
        
        parameters = []
        
        try:
            # Try to parse as JSON
            data = json.loads(response_body)
            
            # Extract field names from JSON
            def extract_fields(obj, prefix=''):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        field_name = f"{prefix}.{key}" if prefix else key
                        parameters.append(key)
                        if isinstance(value, (dict, list)):
                            extract_fields(value, field_name)
                elif isinstance(obj, list) and obj:
                    extract_fields(obj[0], prefix)
            
            extract_fields(data)
            
        except Exception:
            # Extract from URL patterns
            url_patterns = [
                r'/(\w+)/\{[^}]+\}',  # /users/{id}
                r'/(\w+)/:\w+',       # /users/:id
                r'[?&](\w+)=',        # ?param=value
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, response_body)
                parameters.extend(matches)
        
        return list(set(parameters))
    
    def _requires_auth(self, response: CurlResponse) -> bool:
        """Check if endpoint requires authentication"""
        
        # Check status codes
        if response.status_code in [401, 403]:
            return True
        
        # Check response body for auth indicators
        auth_indicators = [
            'unauthorized', 'authentication required', 'login required',
            'access denied', 'invalid token', 'expired token',
            'bearer', 'authorization', 'api key'
        ]
        
        body_lower = response.body.lower()
        if any(indicator in body_lower for indicator in auth_indicators):
            return True
        
        # Check headers
        auth_headers = ['www-authenticate', 'x-auth-required']
        if any(header in response.headers for header in auth_headers):
            return True
        
        return False
    
    def _generate_description(self, response: CurlResponse) -> str:
        """Generate endpoint description"""
        
        description_parts = []
        
        # Add content type info
        if 'json' in response.content_type:
            description_parts.append('JSON API')
        elif 'xml' in response.content_type:
            description_parts.append('XML API')
        
        # Add auth requirement
        if response.status_code in [401, 403]:
            description_parts.append('Auth Required')
        
        # Add response info
        if response.status_code == 200:
            description_parts.append('Active')
        
        return ' | '.join(description_parts) if description_parts else 'API Endpoint'
    
    def _check_auth_required(self, method_obj: Dict) -> bool:
        """Check if OpenAPI method requires authentication"""
        
        security = method_obj.get('security', [])
        return len(security) > 0
    
    def _extract_openapi_parameters(self, method_obj: Dict) -> List[str]:
        """Extract parameters from OpenAPI method object"""
        
        parameters = []
        params = method_obj.get('parameters', [])
        
        for param in params:
            param_name = param.get('name', '')
            if param_name:
                parameters.append(param_name)
        
        return parameters
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    async def _analyze_endpoints(self):
        """Analyze discovered endpoints for additional insights"""
        
        for endpoint in self.discovered_endpoints:
            # Test for common vulnerabilities
            await self._test_endpoint_security(endpoint)
    
    async def _test_endpoint_security(self, endpoint: APIEndpoint):
        """Test endpoint for common security issues"""
        
        try:
            # Test for information disclosure
            response = await self.curl.options(endpoint.url)
            
            # Check allowed methods
            allow_header = response.headers.get('allow', '')
            if 'DELETE' in allow_header or 'PUT' in allow_header:
                endpoint.description += f" | Dangerous methods: {allow_header}"
            
            # Check for CORS misconfig
            if 'access-control-allow-origin' in response.headers:
                acao = response.headers['access-control-allow-origin']
                if acao == '*':
                    endpoint.description += " | CORS: Wildcard origin"
            
        except Exception:
            pass
    
    def get_high_value_endpoints(self) -> List[APIEndpoint]:
        """Get high-value endpoints for focused testing"""
        
        high_value = []
        
        for endpoint in self.discovered_endpoints:
            # Prioritize admin endpoints
            if any(keyword in endpoint.url.lower() for keyword in ['admin', 'config', 'system']):
                high_value.append(endpoint)
            
            # Prioritize auth endpoints
            elif any(keyword in endpoint.url.lower() for keyword in ['auth', 'login', 'token']):
                high_value.append(endpoint)
            
            # Prioritize data endpoints
            elif any(keyword in endpoint.url.lower() for keyword in ['users', 'data', 'export']):
                high_value.append(endpoint)
        
        return high_value
