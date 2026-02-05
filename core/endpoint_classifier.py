"""
Endpoint Classifier - Advanced API endpoint analysis and sensitivity classification
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
from urllib.parse import urlparse

from core.curl_engine import CurlResponse
from core.utils import Colors


class EndpointSensitivity(Enum):
    """Endpoint sensitivity classification"""
    PUBLIC_INFO = "public_info"
    AUTH_RELATED = "auth_related"
    USER_DATA = "user_data"
    ADMIN = "admin"
    INTERNAL = "internal"


@dataclass
class EndpointAnalysis:
    """Detailed endpoint analysis results"""
    url: str
    sensitivity: EndpointSensitivity
    functional_indicators: List[str]
    data_structures: List[str]
    stability_score: float
    exploitability_score: float
    recommended_modules: List[str]
    blocked_modules: List[str]


class EndpointClassifier:
    """Advanced API endpoint analysis and classification"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        
        # Functional API indicators
        self.functional_indicators = {
            'json_objects': [
                r'\{[^}]*"id"[^}]*\}',  # Objects with ID
                r'\{[^}]*"data"[^}]*\}',  # Objects with data
                r'\{[^}]*"user"[^}]*\}',  # Objects with user
                r'\{[^}]*"items"[^}]*\}',  # Objects with items
                r'\{[^}]*"results"[^}]*\}',  # Objects with results
            ],
            'data_arrays': [
                r'\[[^\]]*\{[^}]*\}[^\]]*\]',  # Array of objects
                r'"items":\s*\[',  # Items array
                r'"data":\s*\[',  # Data array
                r'"users":\s*\[',  # Users array
                r'"results":\s*\[',  # Results array
            ],
            'user_objects': [
                r'"email":\s*"[^"]*"',  # Email field
                r'"username":\s*"[^"]*"',  # Username field
                r'"name":\s*"[^"]*"',  # Name field
                r'"profile":\s*\{',  # Profile object
                r'"account":\s*\{',  # Account object
            ],
            'list_endpoints': [
                r'/api/v\d+/[^/]+$',  # List endpoints
                r'/api/[^/]+$',  # Simple list endpoints
                r'/rest/[^/]+$',  # REST list endpoints
            ],
            'resource_structures': [
                r'"total":\s*\d+',  # Total count
                r'"count":\s*\d+',  # Count field
                r'"page":\s*\d+',  # Pagination
                r'"limit":\s*\d+',  # Limit field
                r'"offset":\s*\d+',  # Offset field
            ]
        }
        
        # Sensitivity patterns
        self.sensitivity_patterns = {
            EndpointSensitivity.PUBLIC_INFO: [
                r'/health', r'/status', r'/ping', r'/version',
                r'/info', r'/about', r'/public', r'/docs',
                r'/swagger', r'/openapi', r'/metrics'
            ],
            EndpointSensitivity.AUTH_RELATED: [
                r'/auth', r'/login', r'/logout', r'/token',
                r'/oauth', r'/signin', r'/signup', r'/register',
                r'/password', r'/reset', r'/verify', r'/2fa'
            ],
            EndpointSensitivity.USER_DATA: [
                r'/user', r'/profile', r'/account', r'/settings',
                r'/data', r'/files', r'/uploads', r'/downloads',
                r'/messages', r'/notifications', r'/history'
            ],
            EndpointSensitivity.ADMIN: [
                r'/admin', r'/manage', r'/control', r'/system',
                r'/config', r'/logs', r'/audit', r'/monitor',
                r'/backup', r'/restore', r'/maintenance'
            ],
            EndpointSensitivity.INTERNAL: [
                r'/internal', r'/private', r'/dev', r'/test',
                r'/debug', r'/staging', r'/beta', r'/alpha'
            ]
        }
        
        # Module permissions by sensitivity
        self.module_permissions = {
            EndpointSensitivity.PUBLIC_INFO: {
                'allowed': ['token_leakage'],
                'blocked': ['unauth_api', 'idor_detection']
            },
            EndpointSensitivity.AUTH_RELATED: {
                'allowed': ['unauth_api', 'token_leakage'],
                'blocked': ['idor_detection']
            },
            EndpointSensitivity.USER_DATA: {
                'allowed': ['unauth_api', 'idor_detection', 'token_leakage'],
                'blocked': []
            },
            EndpointSensitivity.ADMIN: {
                'allowed': ['unauth_api', 'idor_detection', 'token_leakage'],
                'blocked': []
            },
            EndpointSensitivity.INTERNAL: {
                'allowed': ['token_leakage'],
                'blocked': ['unauth_api', 'idor_detection']
            }
        }
    
    def analyze_endpoint(self, url: str, response: CurlResponse) -> EndpointAnalysis:
        """Comprehensive endpoint analysis"""
        
        # Check functional indicators
        functional_indicators = self._check_functional_indicators(response)
        
        # Classify sensitivity
        sensitivity = self._classify_sensitivity(url, response)
        
        # Identify data structures
        data_structures = self._identify_data_structures(response)
        
        # Calculate scores
        stability_score = self._calculate_stability_score(response)
        exploitability_score = self._calculate_exploitability_score(
            sensitivity, functional_indicators, data_structures
        )
        
        # Determine module permissions
        recommended_modules = self.module_permissions[sensitivity]['allowed']
        blocked_modules = self.module_permissions[sensitivity]['blocked']
        
        analysis = EndpointAnalysis(
            url=url,
            sensitivity=sensitivity,
            functional_indicators=functional_indicators,
            data_structures=data_structures,
            stability_score=stability_score,
            exploitability_score=exploitability_score,
            recommended_modules=recommended_modules,
            blocked_modules=blocked_modules
        )
        
        if self.debug:
            self._debug_analysis(analysis)
        
        return analysis
    
    def _check_functional_indicators(self, response: CurlResponse) -> List[str]:
        """Check for functional API indicators"""
        
        indicators = []
        body = response.body.lower()
        
        # Check JSON objects
        for pattern in self.functional_indicators['json_objects']:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append('json_objects')
                break
        
        # Check data arrays
        for pattern in self.functional_indicators['data_arrays']:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append('data_arrays')
                break
        
        # Check user objects
        for pattern in self.functional_indicators['user_objects']:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append('user_objects')
                break
        
        # Check list endpoints (from URL)
        url_lower = response.url.lower()
        for pattern in self.functional_indicators['list_endpoints']:
            if re.search(pattern, url_lower, re.IGNORECASE):
                indicators.append('list_endpoints')
                break
        
        # Check resource structures
        for pattern in self.functional_indicators['resource_structures']:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append('resource_structures')
                break
        
        return indicators
    
    def _classify_sensitivity(self, url: str, response: CurlResponse) -> EndpointSensitivity:
        """Classify endpoint sensitivity"""
        
        url_lower = url.lower()
        body_lower = response.body.lower()
        
        # Check each sensitivity level
        for sensitivity, patterns in self.sensitivity_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower, re.IGNORECASE):
                    return sensitivity
                if re.search(pattern, body_lower, re.IGNORECASE):
                    return sensitivity
        
        # Default classification based on content
        if self._contains_sensitive_data(response):
            return EndpointSensitivity.USER_DATA
        
        return EndpointSensitivity.PUBLIC_INFO
    
    def _contains_sensitive_data(self, response: CurlResponse) -> bool:
        """Check if response contains sensitive user data"""
        
        sensitive_patterns = [
            r'"email":\s*"[^"]*"',
            r'"phone":\s*"[^"]*"',
            r'"address":\s*"[^"]*"',
            r'"ssn":\s*"[^"]*"',
            r'"credit_card":\s*"[^"]*"',
            r'"password":\s*"[^"]*"',
            r'"token":\s*"[^"]*"',
            r'"secret":\s*"[^"]*"'
        ]
        
        body_lower = response.body.lower()
        for pattern in sensitive_patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _identify_data_structures(self, response: CurlResponse) -> List[str]:
        """Identify data structures in response"""
        
        structures = []
        
        try:
            data = json.loads(response.body)
            
            if isinstance(data, dict):
                # Check for common structures
                if 'data' in data:
                    structures.append('data_wrapper')
                if 'items' in data or isinstance(data.get('data'), list):
                    structures.append('list_structure')
                if 'pagination' in data or 'page' in data or 'total' in data:
                    structures.append('paginated')
                if 'user' in data or 'users' in data:
                    structures.append('user_data')
                if 'error' in data or 'errors' in data:
                    structures.append('error_response')
                if 'success' in data or 'status' in data:
                    structures.append('status_response')
            
            elif isinstance(data, list):
                structures.append('array_response')
                if data and isinstance(data[0], dict):
                    structures.append('object_array')
        
        except json.JSONDecodeError:
            # Not JSON, check for other structures
            if '<html' in response.body.lower():
                structures.append('html_response')
            elif response.body.strip().startswith('{') or response.body.strip().startswith('['):
                structures.append('malformed_json')
        
        return structures
    
    def _calculate_stability_score(self, response: CurlResponse) -> float:
        """Calculate endpoint stability score"""
        
        score = 0.0
        
        # Status code stability
        if 200 <= response.status_code < 300:
            score += 0.4
        elif response.status_code == 404:
            score -= 0.3
        elif response.status_code >= 500:
            score -= 0.2
        
        # Content consistency
        if response.content_length > 100:
            score += 0.2
        elif response.content_length < 20:
            score -= 0.2
        
        # Content type reliability
        if 'application/json' in response.content_type.lower():
            score += 0.3
        elif 'text/html' in response.content_type.lower():
            score += 0.1
        
        # Response time (if available)
        if hasattr(response, 'response_time'):
            if response.response_time < 2.0:
                score += 0.1
            elif response.response_time > 10.0:
                score -= 0.1
        
        return max(0.0, min(1.0, score))
    
    def _calculate_exploitability_score(self, sensitivity: EndpointSensitivity, 
                                      functional_indicators: List[str], 
                                      data_structures: List[str]) -> float:
        """Calculate exploitability score"""
        
        score = 0.0
        
        # Sensitivity scoring
        sensitivity_scores = {
            EndpointSensitivity.PUBLIC_INFO: 0.1,
            EndpointSensitivity.AUTH_RELATED: 0.6,
            EndpointSensitivity.USER_DATA: 0.8,
            EndpointSensitivity.ADMIN: 0.9,
            EndpointSensitivity.INTERNAL: 0.4
        }
        score += sensitivity_scores.get(sensitivity, 0.1)
        
        # Functional indicators scoring
        indicator_scores = {
            'json_objects': 0.2,
            'data_arrays': 0.3,
            'user_objects': 0.4,
            'list_endpoints': 0.3,
            'resource_structures': 0.2
        }
        
        for indicator in functional_indicators:
            score += indicator_scores.get(indicator, 0.1)
        
        # Data structure scoring
        structure_scores = {
            'data_wrapper': 0.2,
            'list_structure': 0.3,
            'paginated': 0.2,
            'user_data': 0.4,
            'array_response': 0.2,
            'object_array': 0.3
        }
        
        for structure in data_structures:
            score += structure_scores.get(structure, 0.1)
        
        return max(0.0, min(1.0, score))
    
    def _debug_analysis(self, analysis: EndpointAnalysis):
        """Print debug information"""
        
        print(f"{Colors.CYAN}[DEBUG] Endpoint Analysis: {analysis.url}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Sensitivity: {analysis.sensitivity.value}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Functional Indicators: {', '.join(analysis.functional_indicators)}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Data Structures: {', '.join(analysis.data_structures)}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Stability Score: {analysis.stability_score:.2f}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Exploitability Score: {analysis.exploitability_score:.2f}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Recommended Modules: {', '.join(analysis.recommended_modules)}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Blocked Modules: {', '.join(analysis.blocked_modules)}{Colors.RESET}")
    
    def should_proceed_to_vulnerability_testing(self, analysis: EndpointAnalysis) -> bool:
        """Determine if endpoint should proceed to vulnerability testing"""
        
        # Must have functional indicators
        if not analysis.functional_indicators:
            return False
        
        # Must have minimum stability
        if analysis.stability_score < 0.3:
            return False
        
        # Must have minimum exploitability
        if analysis.exploitability_score < 0.4:
            return False
        
        # Cannot be public info only
        if analysis.sensitivity == EndpointSensitivity.PUBLIC_INFO:
            return False
        
        return True
    
    def get_payload_limit(self, analysis: EndpointAnalysis) -> int:
        """Get payload limit based on endpoint type"""
        
        if analysis.sensitivity == EndpointSensitivity.PUBLIC_INFO:
            return 5  # Very limited
        elif analysis.sensitivity == EndpointSensitivity.AUTH_RELATED:
            return 15  # Limited
        elif analysis.sensitivity == EndpointSensitivity.USER_DATA:
            return 25  # Moderate
        elif analysis.sensitivity == EndpointSensitivity.ADMIN:
            return 30  # Higher
        else:  # INTERNAL
            return 10  # Limited
