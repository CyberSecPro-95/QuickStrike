"""
Unauthenticated API Access Detection - Find APIs exposing sensitive data without authentication
"""

import asyncio
import json
import re
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass

from core.curl_engine import CurlEngine, CurlResponse
from core.utils import Colors, RegexPatterns


@dataclass
class UnauthAccess:
    """Unauthenticated access finding"""
    url: str
    method: str
    data_type: str
    exposed_data: List[str]
    sample_data: Dict[str, Any]
    severity: str
    description: str


class UnauthAPIDetection:
    """Detect unauthenticated API access to sensitive data"""
    
    def __init__(self, curl_engine: CurlEngine):
        self.curl = curl_engine
        self.findings: List[UnauthAccess] = []
        
        # Sensitive data patterns
        self.sensitive_patterns = {
            'emails': RegexPatterns.EMAIL_PATTERN,
            'user_ids': r'"id":\s*\d+|"user_id":\s*\d+|"userId":\s*\d+',
            'personal_info': r'"name":|"first_name":|"last_name":|"phone":|"address":',
            'financial': r'"credit_card":|"payment":|"billing":|"bank_account":|"amount":',
            'tokens': RegexPatterns.JWT_TOKEN,
            'api_keys': r'"api_key":|"secret":|"token":|"access_token":',
            'internal_data': r'"internal":|"admin":|"debug":|"system":|"config":',
            'location': r'"latitude":|"longitude":|"address":|"location":|"gps":',
            'health': r'"medical":|"health":|"patient":|"diagnosis":|"treatment":'
        }
        
        # High-value endpoints to test
        self.high_value_endpoints = [
            '/api/users',
            '/api/admin/users',
            '/api/v1/users',
            '/api/v2/users',
            '/rest/users',
            '/api/data',
            '/api/export',
            '/api/analytics',
            '/api/logs',
            '/api/config',
            '/api/settings',
            '/api/profiles',
            '/api/customers',
            '/api/orders',
            '/api/transactions',
            '/api/payments',
            '/api/reports',
            '/api/statistics',
            '/api/metrics'
        ]
    
    async def scan_endpoints(self, base_url: str, discovered_endpoints: List[str] = None) -> List[UnauthAccess]:
        """Scan for unauthenticated API access"""
        
        print(f"{Colors.YELLOW}[*] Scanning for unauthenticated API access on: {base_url}{Colors.RESET}")
        
        # Normalize base URL
        base_url = self._normalize_url(base_url)
        
        # Test discovered endpoints
        if discovered_endpoints:
            await self._test_discovered_endpoints(discovered_endpoints)
        
        # Test common high-value endpoints
        await self._test_high_value_endpoints(base_url)
        
        # Test IDOR patterns
        await self._test_idor_patterns(base_url)
        
        # Test pagination bypass
        await self._test_pagination_bypass(base_url)
        
        print(f"{Colors.GREEN}[+] Found {len(self.findings)} unauthenticated access issues{Colors.RESET}")
        return self.findings
    
    async def _test_discovered_endpoints(self, endpoints: List[str]):
        """Test discovered endpoints for unauthenticated access"""
        
        tasks = []
        
        for endpoint in endpoints:
            # Test GET request (most likely to leak data)
            task = asyncio.create_task(self._test_endpoint_access(endpoint, 'GET'))
            tasks.append(task)
            
            # Test POST if it might be an API endpoint
            if any(pattern in endpoint.lower() for pattern in ['/api/', '/v1/', '/rest/']):
                task = asyncio.create_task(self._test_endpoint_access(endpoint, 'POST'))
                tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, UnauthAccess):
                self.findings.append(result)
    
    async def _test_high_value_endpoints(self, base_url: str):
        """Test high-value endpoints for data exposure"""
        
        tasks = []
        
        for endpoint in self.high_value_endpoints:
            full_url = urljoin(base_url, endpoint)
            task = asyncio.create_task(self._test_endpoint_access(full_url, 'GET'))
            tasks.append(task)
        
        # Execute with rate limiting
        batch_size = 10
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in results:
                if isinstance(result, UnauthAccess):
                    self.findings.append(result)
    
    async def _test_idor_patterns(self, base_url: str):
        """Test IDOR patterns for data exposure"""
        
        # Common IDOR patterns
        idor_patterns = [
            '/api/users/1',
            '/api/users/2',
            '/api/admin/users/1',
            '/api/customers/1',
            '/api/orders/1',
            '/api/transactions/1',
            '/api/profiles/1',
            '/api/data/1',
            '/v1/users/1',
            '/v2/users/1',
            '/rest/users/1'
        ]
        
        for pattern in idor_patterns:
            full_url = urljoin(base_url, pattern)
            result = await self._test_endpoint_access(full_url, 'GET')
            
            if result:
                self.findings.append(result)
    
    async def _test_pagination_bypass(self, base_url: str):
        """Test pagination bypass techniques"""
        
        # Common pagination parameters
        pagination_tests = [
            '/api/users?limit=1000',
            '/api/users?limit=9999',
            '/api/users?size=1000',
            '/api/users?count=1000',
            '/api/users?offset=0&limit=1000',
            '/api/data?limit=1000',
            '/api/export?limit=1000',
            '/api/logs?limit=1000'
        ]
        
        for test_url in pagination_tests:
            full_url = urljoin(base_url, test_url)
            result = await self._test_endpoint_access(full_url, 'GET')
            
            if result:
                result.description += " | Pagination bypass possible"
                self.findings.append(result)
    
    async def _test_endpoint_access(self, url: str, method: str = 'GET') -> Optional[UnauthAccess]:
        """Test endpoint for unauthenticated access"""
        
        try:
            # Make request without authentication
            if method == 'GET':
                response = await self.curl.get(url)
            elif method == 'POST':
                response = await self.curl.post(url, data={})
            else:
                response = await self.curl.head(url)
            
            # Check if request was successful
            if response.status_code == 200:
                # Analyze response for sensitive data
                exposed_data = self._analyze_response(response.body)
                
                if exposed_data:
                    # Determine severity based on data type
                    severity = self._calculate_severity(exposed_data)
                    
                    # Extract sample data
                    sample_data = self._extract_sample_data(response.body)
                    
                    return UnauthAccess(
                        url=url,
                        method=method,
                        data_type=', '.join(exposed_data.keys()),
                        exposed_data=list(exposed_data.keys()),
                        sample_data=sample_data,
                        severity=severity,
                        description=self._generate_description(exposed_data, response)
                    )
            
            # Check for partial access (e.g., 403 but still leaks info)
            elif response.status_code in [403, 401]:
                exposed_data = self._analyze_response(response.body)
                
                if exposed_data:
                    return UnauthAccess(
                        url=url,
                        method=method,
                        data_type=', '.join(exposed_data.keys()),
                        exposed_data=list(exposed_data.keys()),
                        sample_data=self._extract_sample_data(response.body),
                        severity='Medium',
                        description=f"Partial access leak (HTTP {response.status_code}) - {', '.join(exposed_data.keys())}"
                    )
        
        except Exception:
            pass
        
        return None
    
    def _analyze_response(self, response_body: str) -> Dict[str, List[str]]:
        """Analyze response body for sensitive data patterns"""
        
        exposed_data = {}
        
        try:
            # Try to parse as JSON
            data = json.loads(response_body)
            json_str = json.dumps(data).lower()
            
            # Check each sensitive pattern
            for data_type, pattern in self.sensitive_patterns.items():
                matches = re.findall(pattern, json_str, re.IGNORECASE)
                
                if matches:
                    # Extract actual values from JSON
                    values = self._extract_values_from_json(data, data_type, pattern)
                    if values:
                        exposed_data[data_type] = values[:5]  # Limit to 5 examples
        
        except json.JSONDecodeError:
            # Analyze as plain text
            body_lower = response_body.lower()
            
            for data_type, pattern in self.sensitive_patterns.items():
                matches = re.findall(pattern, body_lower, re.IGNORECASE)
                if matches:
                    exposed_data[data_type] = matches[:3]  # Limit to 3 examples
        
        return exposed_data
    
    def _extract_values_from_json(self, data: Any, data_type: str, pattern: str) -> List[str]:
        """Extract specific values from JSON based on pattern"""
        
        values = []
        
        def extract_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    key_lower = key.lower()
                    
                    # Check if key matches pattern
                    if data_type == 'emails' and 'email' in key_lower:
                        if isinstance(value, str):
                            values.append(value)
                    elif data_type == 'user_ids' and 'id' in key_lower:
                        if isinstance(value, (str, int)):
                            values.append(str(value))
                    elif data_type == 'personal_info' and any(term in key_lower for term in ['name', 'phone', 'address']):
                        if isinstance(value, str):
                            values.append(value)
                    elif data_type == 'financial' and any(term in key_lower for term in ['card', 'payment', 'billing', 'amount']):
                        if isinstance(value, (str, int, float)):
                            values.append(str(value))
                    elif data_type == 'tokens' and any(term in key_lower for term in ['token', 'jwt', 'bearer']):
                        if isinstance(value, str):
                            values.append(value[:50] + '...' if len(value) > 50 else value)
                    elif data_type == 'api_keys' and any(term in key_lower for term in ['key', 'secret', 'api']):
                        if isinstance(value, str):
                            values.append(value[:20] + '...' if len(value) > 20 else value)
                    
                    # Recurse into nested objects
                    if isinstance(value, (dict, list)):
                        extract_recursive(value)
            
            elif isinstance(obj, list) and obj:
                for item in obj:
                    extract_recursive(item)
        
        extract_recursive(data)
        return values
    
    def _extract_sample_data(self, response_body: str) -> Dict[str, Any]:
        """Extract sample data for PoC"""
        
        try:
            data = json.loads(response_body)
            
            # Limit the sample data size
            sample = self._limit_data_size(data)
            return sample
        
        except json.JSONDecodeError:
            # Return first 500 characters of text response
            return {'text_sample': response_body[:500] + '...' if len(response_body) > 500 else response_body}
    
    def _limit_data_size(self, data: Any, max_size: int = 1000) -> Any:
        """Recursively limit data size for sample"""
        
        if isinstance(data, dict):
            limited = {}
            for key, value in list(data.items())[:10]:  # Limit to 10 keys
                limited[key] = self._limit_data_size(value, max_size // 2)
            return limited
        
        elif isinstance(data, list):
            limited = []
            for item in data[:5]:  # Limit to 5 items
                limited.append(self._limit_data_size(item, max_size // 2))
            return limited
        
        elif isinstance(data, str) and len(data) > 100:
            return data[:100] + '...'
        
        else:
            return data
    
    def _calculate_severity(self, exposed_data: Dict[str, List[str]]) -> str:
        """Calculate severity based on exposed data types"""
        
        # Critical data types
        critical_types = ['financial', 'health', 'tokens', 'api_keys']
        if any(data_type in exposed_data for data_type in critical_types):
            return 'Critical'
        
        # High severity data types
        high_types = ['emails', 'personal_info', 'internal_data']
        if any(data_type in exposed_data for data_type in high_types):
            return 'High'
        
        # Medium severity
        medium_types = ['user_ids', 'location']
        if any(data_type in exposed_data for data_type in medium_types):
            return 'Medium'
        
        return 'Low'
    
    def _generate_description(self, exposed_data: Dict[str, List[str]], response: CurlResponse) -> str:
        """Generate finding description"""
        
        data_types = list(exposed_data.keys())
        description = f"Unauthenticated access exposing: {', '.join(data_types)}"
        
        # Add response size indicator
        if response.content_length > 10000:
            description += f" | Large response ({response.content_length} bytes)"
        
        # Add content type
        if 'json' in response.content_type:
            description += " | JSON API"
        
        return description
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    def get_critical_findings(self) -> List[UnauthAccess]:
        """Get critical and high severity findings"""
        
        return [finding for finding in self.findings 
                if finding.severity in ['Critical', 'High']]
    
    def generate_poc_commands(self, finding: UnauthAccess) -> List[str]:
        """Generate PoC commands for the finding"""
        
        commands = []
        
        base_command = f"curl -s -X {finding.method} '{finding.url}'"
        
        if finding.method == 'POST':
            base_command += " -H 'Content-Type: application/json' -d '{}'"
        
        commands.append(base_command)
        
        # Add variations for testing
        if 'users' in finding.url.lower():
            commands.append(f"curl -s '{finding.url}?limit=1000'")
            commands.append(f"curl -s '{finding.url}/1'")
        
        return commands
