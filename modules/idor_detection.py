"""
IDOR Detection Engine - Detect Insecure Direct Object Reference vulnerabilities
"""

import asyncio
import json
import re
import random
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass

from core.curl_engine import CurlEngine, CurlResponse
from core.utils import Colors, PayloadGenerator


@dataclass
class IDORFinding:
    """IDOR vulnerability finding"""
    url: str
    method: str
    parameter: str
    vulnerable_value: str
    original_value: str
    response_diff: Dict[str, Any]
    severity: str
    description: str
    poc_commands: List[str]


class IDORDetection:
    """Advanced IDOR detection engine"""
    
    def __init__(self, curl_engine: CurlEngine):
        self.curl = curl_engine
        self.findings: List[IDORFinding] = []
        
        # Common IDOR parameter patterns
        self.idor_params = [
            'id', 'user_id', 'userid', 'uid', 'customer_id', 'account_id',
            'profile_id', 'order_id', 'transaction_id', 'payment_id',
            'file_id', 'document_id', 'message_id', 'comment_id',
            'post_id', 'article_id', 'product_id', 'item_id',
            'session_id', 'booking_id', 'reservation_id', 'ticket_id'
        ]
        
        # Test values for IDOR
        self.test_values = {
            'sequential': ['1', '2', '3', '10', '11', '12', '99', '100', '101'],
            'uuid': [
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
                '12345678-1234-1234-1234-123456789012',
                'ffffffff-ffff-ffff-ffff-ffffffffffff'
            ],
            'common': ['0', 'admin', 'test', 'guest', 'demo', 'null', 'undefined']
        }
    
    async def scan_endpoints(self, base_url: str, discovered_endpoints: List[str] = None) -> List[IDORFinding]:
        """Scan endpoints for IDOR vulnerabilities"""
        
        print(f"{Colors.YELLOW}[*] Scanning for IDOR vulnerabilities on: {base_url}{Colors.RESET}")
        
        # Normalize base URL
        base_url = self._normalize_url(base_url)
        
        # Test discovered endpoints
        if discovered_endpoints:
            await self._test_discovered_endpoints(discovered_endpoints)
        
        # Test common IDOR patterns
        await self._test_common_patterns(base_url)
        
        # Test API endpoints specifically
        await self._test_api_endpoints(base_url)
        
        print(f"{Colors.GREEN}[+] Found {len(self.findings)} IDOR vulnerabilities{Colors.RESET}")
        return self.findings
    
    async def _test_discovered_endpoints(self, endpoints: List[str]):
        """Test discovered endpoints for IDOR"""
        
        tasks = []
        
        for endpoint in endpoints:
            # Extract parameters from URL
            params = self._extract_url_parameters(endpoint)
            
            if params:
                task = asyncio.create_task(self._test_endpoint_idor(endpoint, params))
                tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, IDORFinding):
                self.findings.append(result)
    
    async def _test_common_patterns(self, base_url: str):
        """Test common IDOR patterns"""
        
        # Common IDOR endpoint patterns
        patterns = [
            '/api/users/{id}',
            '/api/v1/users/{id}',
            '/api/v2/users/{id}',
            '/rest/users/{id}',
            '/api/customers/{id}',
            '/api/orders/{id}',
            '/api/transactions/{id}',
            '/api/profiles/{id}',
            '/api/files/{id}',
            '/api/messages/{id}',
            '/user/{id}',
            '/profile/{id}',
            '/order/{id}',
            '/file/{id}',
            '/document/{id}',
            '/data/{id}'
        ]
        
        for pattern in patterns:
            await self._test_pattern_idor(base_url, pattern)
    
    async def _test_api_endpoints(self, base_url: str):
        """Test API endpoints for IDOR"""
        
        # API-specific patterns
        api_patterns = [
            '/api/users',
            '/api/v1/users',
            '/api/v2/users',
            '/rest/users',
            '/api/customers',
            '/api/orders',
            '/api/transactions'
        ]
        
        for pattern in api_patterns:
            # Test with ID parameter
            await self._test_with_id_parameter(base_url, pattern)
    
    async def _test_pattern_idor(self, base_url: str, pattern: str):
        """Test a specific pattern for IDOR"""
        
        # Generate test values
        test_ids = self.test_values['sequential'][:5]  # Limit for performance
        
        for test_id in test_ids:
            test_url = base_url + pattern.replace('{id}', test_id)
            
            # Compare responses for different IDs
            result = await self._compare_id_responses(test_url, 'id', test_id)
            
            if result:
                self.findings.append(result)
    
    async def _test_with_id_parameter(self, base_url: str, endpoint: str):
        """Test endpoint with ID parameter"""
        
        full_url = urljoin(base_url, endpoint)
        
        # Test with different ID parameters
        for param in self.idor_params[:5]:  # Limit for performance
            for test_id in self.test_values['sequential'][:3]:
                test_url = f"{full_url}?{param}={test_id}"
                
                result = await self._compare_id_responses(test_url, param, test_id)
                
                if result:
                    self.findings.append(result)
    
    async def _test_endpoint_idor(self, url: str, params: Dict[str, str]) -> Optional[IDORFinding]:
        """Test specific endpoint for IDOR with given parameters"""
        
        for param_name, param_value in params.items():
            # Only test IDOR-like parameters
            if not self._is_idor_parameter(param_name):
                continue
            
            # Generate test values
            test_values = self._generate_test_values(param_value)
            
            for test_value in test_values:
                # Create test URL
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={test_value}")
                
                # Compare responses
                result = await self._compare_id_responses(test_url, param_name, test_value, param_value)
                
                if result:
                    return result
        
        return None
    
    async def _compare_id_responses(self, test_url: str, param: str, test_value: str, 
                                   original_value: str = None) -> Optional[IDORFinding]:
        """Compare responses to detect IDOR"""
        
        try:
            # Get response for test value
            test_response = await self.curl.get(test_url)
            
            # If we have original value, compare with original response
            if original_value:
                original_url = test_url.replace(f"{param}={test_value}", f"{param}={original_value}")
                original_response = await self.curl.get(original_url)
                
                # Compare responses
                diff = self._compare_responses(original_response, test_response)
                
                if self._is_idor_detected(diff):
                    return IDORFinding(
                        url=test_url,
                        method='GET',
                        parameter=param,
                        vulnerable_value=test_value,
                        original_value=original_value,
                        response_diff=diff,
                        severity=self._calculate_severity(diff),
                        description=self._generate_description(param, diff),
                        poc_commands=self._generate_poc_commands(test_url, param, test_value)
                    )
            else:
                # Analyze single response for IDOR indicators
                if self._has_idor_indicators(test_response):
                    return IDORFinding(
                        url=test_url,
                        method='GET',
                        parameter=param,
                        vulnerable_value=test_value,
                        original_value="N/A",
                        response_diff={'status_code': test_response.status_code},
                        severity='Medium',
                        description=f"Potential IDOR: {param}={test_value} returns data",
                        poc_commands=self._generate_poc_commands(test_url, param, test_value)
                    )
        
        except Exception:
            pass
        
        return None
    
    def _extract_url_parameters(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        
        params = {}
        
        # Parse query parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for key, values in query_params.items():
            if values:
                params[key] = values[0]
        
        # Extract path parameters (e.g., /users/123)
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if part.isdigit() and i > 0:
                # Assume the previous part is the parameter name
                param_name = path_parts[i-1]
                params[param_name] = part
        
        return params
    
    def _is_idor_parameter(self, param_name: str) -> bool:
        """Check if parameter is likely an IDOR parameter"""
        
        param_lower = param_name.lower()
        
        # Direct matches
        if param_lower in self.idor_params:
            return True
        
        # Pattern matches
        idor_patterns = ['id', 'uid', 'user', 'customer', 'account', 'order', 'transaction']
        
        return any(pattern in param_lower for pattern in idor_patterns)
    
    def _generate_test_values(self, original_value: str) -> List[str]:
        """Generate test values with payload limits"""
        
        # Get payload limit based on endpoint characteristics
        payload_limit = self._get_payload_limit()
        
        test_values = []
        
        # If original looks like number, test sequential
        if original_value.isdigit():
            test_values.extend(self.test_values['sequential'][:payload_limit//2])
        
        # If original looks like UUID, test UUID patterns
        if len(original_value) == 36 and '-' in original_value:
            test_values.extend(self.test_values['uuid'][:payload_limit//2])
        
        # Add common test values
        test_values.extend(self.test_values['common'][:payload_limit//2])
        
        return list(set(test_values))[:payload_limit]
    
    def _get_payload_limit(self) -> int:
        """Get payload limit based on endpoint characteristics"""
        
        # This would be enhanced to use endpoint analysis from context
        # For now, return a conservative default
        return 20
    
    async def _compare_responses(self, original: CurlResponse, test: CurlResponse) -> Dict[str, Any]:
        """Compare two responses for meaningful differences"""
        
        diff = {}
        
        # Generate fingerprints for comparison
        original_fingerprint = self._generate_response_fingerprint(original)
        test_fingerprint = self._generate_response_fingerprint(test)
        
        # Compare status codes
        if original.status_code != test.status_code:
            diff['status_code'] = {
                'original': original.status_code,
                'test': test.status_code
            }
        
        # Compare response sizes (significant difference only)
        size_diff = abs(original.content_length - test.content_length)
        if size_diff > 100:  # Only consider differences > 100 bytes
            diff['content_length'] = {
                'original': original.content_length,
                'test': test.content_length,
                'difference': size_diff
            }
        
        # Compare JSON content for meaningful differences
        try:
            original_data = json.loads(original.body)
            test_data = json.loads(test.body)
            
            content_diff = self._compare_json_content_meaningful(original_data, test_data)
            if content_diff:
                diff['content'] = content_diff
                diff['fingerprint_changed'] = original_fingerprint != test_fingerprint
        
        except json.JSONDecodeError:
            # Compare text content
            if original.body != test.body:
                # Calculate similarity ratio
                similarity = self._calculate_text_similarity(original.body, test.body)
                if similarity < 0.8:  # Less than 80% similar
                    diff['text_different'] = True
                    diff['similarity'] = similarity
                    diff['fingerprint_changed'] = original_fingerprint != test_fingerprint
        
        return diff
    
    def _generate_response_fingerprint(self, response: CurlResponse) -> str:
        """Generate fingerprint for response comparison"""
        
        import hashlib
        
        # Create fingerprint based on key response characteristics
        fingerprint_data = {
            'status_code': response.status_code,
            'content_type': response.content_type,
            'content_length': response.content_length,
            'headers_hash': self._hash_headers(response.headers),
            'body_hash': hashlib.md5(response.body.encode()).hexdigest()[:16]
        }
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.md5(fingerprint_str.encode()).hexdigest()
    
    def _hash_headers(self, headers: Dict[str, str]) -> str:
        """Hash relevant headers for fingerprinting"""
        
        relevant_headers = [
            'content-type', 'content-length', 'server', 'x-powered-by',
            'cache-control', 'set-cookie', 'location', 'www-authenticate'
        ]
        
        header_data = {}
        for header in relevant_headers:
            if header in headers:
                header_data[header] = headers[header]
        
        return hashlib.md5(json.dumps(header_data, sort_keys=True).encode()).hexdigest()
    
    def _compare_json_content_meaningful(self, original: Any, test: Any) -> Dict[str, Any]:
        """Compare JSON content for meaningful differences"""
        
        diff = {}
        
        # If both are dictionaries
        if isinstance(original, dict) and isinstance(test, dict):
            # Check for different user data
            user_fields = ['id', 'user_id', 'email', 'name', 'username', 'profile']
            
            for field in user_fields:
                if field in original and field in test:
                    if original[field] != test[field]:
                        # Check if it's a meaningful difference (not just timestamps)
                        if not self._is_timestamp_field(field):
                            diff[field] = {
                                'original': original[field],
                                'test': test[field]
                            }
        
        # If both are lists, compare first items
        elif isinstance(original, list) and isinstance(test, list):
            if original and test:
                item_diff = self._compare_json_content_meaningful(original[0], test[0])
                if item_diff:
                    diff['list_items'] = item_diff
        
        return diff
    
    def _is_timestamp_field(self, field: str) -> bool:
        """Check if field is likely a timestamp"""
        
        timestamp_fields = [
            'created_at', 'updated_at', 'timestamp', 'date', 'time',
            'last_modified', 'expires_at', 'issued_at'
        ]
        
        return any(ts_field in field.lower() for ts_field in timestamp_fields)
    
    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts"""
        
        # Simple similarity based on common substrings
        if not text1 or not text2:
            return 0.0
        
        # Use sequence matcher for better accuracy
        try:
            from difflib import SequenceMatcher
            return SequenceMatcher(None, text1, text2).ratio()
        except ImportError:
            # Fallback to simple character comparison
            common_chars = set(text1) & set(text2)
            total_chars = set(text1) | set(text2)
            return len(common_chars) / len(total_chars) if total_chars else 0.0
    
    def _is_idor_detected(self, diff: Dict[str, Any]) -> bool:
        """Determine if IDOR is detected based on meaningful response differences"""
        
        # Require fingerprint change for IDOR detection
        if not diff.get('fingerprint_changed', False):
            return False
        
        # Status code changes
        if 'status_code' in diff:
            orig_status = diff['status_code']['original']
            test_status = diff['status_code']['test']
            
            # Both successful but different content
            if orig_status == 200 and test_status == 200:
                return True
            
            # One forbidden, one successful
            if (orig_status == 403 and test_status == 200) or (orig_status == 200 and test_status == 403):
                return True
        
        # Content differences with fingerprint change
        if 'content' in diff:
            user_fields = ['id', 'user_id', 'email', 'name', 'profile', 'personal']
            if any(field in diff['content'] for field in user_fields):
                return True
        
        # Significant content length difference with fingerprint change
        if 'content_length' in diff:
            length_diff = diff['content_length']['difference']
            if length_diff > 500:  # Significant difference
                return True
        
        return False
    
    def _has_idor_indicators(self, response: CurlResponse) -> bool:
        """Check if response indicates IDOR vulnerability"""
        
        # Successful response
        if response.status_code == 200:
            # Check for user data in response
            try:
                data = json.loads(response.body)
                
                # Look for user-specific data
                user_indicators = ['id', 'user_id', 'email', 'name', 'profile']
                
                def check_user_data(obj):
                    if isinstance(obj, dict):
                        return any(key in obj for key in user_indicators)
                    elif isinstance(obj, list) and obj:
                        return check_user_data(obj[0])
                    return False
                
                return check_user_data(data)
            
            except json.JSONDecodeError:
                pass
        
        return False
    
    def _calculate_severity(self, diff: Dict[str, Any]) -> str:
        """Calculate severity based on differences"""
        
        # High severity: Different user data exposed
        if 'content' in diff:
            user_fields = ['email', 'name', 'profile', 'personal']
            if any(field in diff['content'] for field in user_fields):
                return 'High'
        
        # Medium severity: Status code manipulation
        if 'status_code' in diff:
            return 'Medium'
        
        # Low severity: Content length differences only
        if 'content_length' in diff:
            return 'Low'
        
        return 'Medium'
    
    def _generate_description(self, param: str, diff: Dict[str, Any]) -> str:
        """Generate finding description"""
        
        description = f"IDOR vulnerability in parameter: {param}"
        
        if 'content' in diff:
            exposed_fields = list(diff['content'].keys())
            description += f" | Exposed data: {', '.join(exposed_fields)}"
        
        if 'status_code' in diff:
            description += f" | Status code manipulation detected"
        
        return description
    
    def _generate_poc_commands(self, url: str, param: str, test_value: str) -> List[str]:
        """Generate PoC commands"""
        
        commands = []
        
        base_command = f"curl -s '{url}'"
        commands.append(base_command)
        
        # Generate variations
        if test_value.isdigit():
            for offset in [-1, 1, 10, 100]:
                test_id = str(int(test_value) + offset)
                variant_url = url.replace(f"{param}={test_value}", f"{param}={test_id}")
                commands.append(f"curl -s '{variant_url}'")
        
        return commands
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    def get_critical_findings(self) -> List[IDORFinding]:
        """Get critical and high severity findings"""
        
        return [finding for finding in self.findings 
                if finding.severity in ['High', 'Critical']]
