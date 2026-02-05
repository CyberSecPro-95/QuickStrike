"""
Target Context - Per-target scanning context with validated endpoints and results
"""

import asyncio
import hashlib
import json
import time
import random
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.curl_engine import CurlResponse
from core.endpoint_classifier import EndpointClassifier, EndpointAnalysis, EndpointSensitivity
from core.utils import Colors


@dataclass
class ValidatedEndpoint:
    """Validated API endpoint with confidence scoring"""
    url: str
    method: str
    status_code: int
    content_type: str
    response_size: int
    confidence_score: float
    response_fingerprint: str
    auth_required: bool = False
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    discovery_time: float = field(default_factory=time.time)
    analysis: Optional[EndpointAnalysis] = None
    stability_verified: bool = False
    
    def __hash__(self):
        """Hash for deduplication"""
        return hash(self.url + self.method)


@dataclass
class TargetContext:
    """Per-target scanning context"""
    
    target: str
    base_url: str
    mode: str
    debug: bool = False
    
    # Validated endpoints
    validated_endpoints: List[ValidatedEndpoint] = field(default_factory=list)
    endpoint_hash_set: Set[str] = field(default_factory=set)
    
    # Module results (only confirmed exploitable findings)
    confirmed_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    
    # Request tracking for rate limiting
    request_times: List[float] = field(default_factory=list)
    last_request_time: float = 0.0
    
    # Statistics
    total_requests: int = 0
    successful_requests: int = 0
    scan_start_time: float = field(default_factory=time.time)
    
    # Attack surface and escalation data
    attack_surface_graph: Optional[Any] = None
    escalation_decision: Optional[Any] = None
    
    def __post_init__(self):
        """Initialize context"""
        self.base_url = self._normalize_base_url(self.target)
        self.classifier = EndpointClassifier(debug=self.debug)
    
    def _normalize_base_url(self, url: str) -> str:
        """Normalize base URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Remove trailing slash
        if url.endswith('/'):
            url = url[:-1]
        
        return url
    
    def normalize_endpoint_url(self, url: str) -> str:
        """Normalize endpoint URL for deduplication"""
        
        # Parse URL
        parsed = urlparse(url)
        
        # Normalize path
        path = parsed.path
        
        # Remove duplicate slashes
        path = '//' + path if path.startswith('//') else path
        path = path.replace('//', '/')
        
        # Remove trailing slash unless it's root
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        
        # Reconstruct URL
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        return normalized
    
    def is_endpoint_duplicate(self, url: str) -> bool:
        """Check if endpoint is duplicate"""
        
        normalized_url = self.normalize_endpoint_url(url)
        url_hash = hashlib.md5(normalized_url.encode()).hexdigest()
        
        return url_hash in self.endpoint_hash_set
    
    def add_validated_endpoint(self, endpoint: ValidatedEndpoint) -> bool:
        """Add validated endpoint if not duplicate"""
        
        normalized_url = self.normalize_endpoint_url(endpoint.url)
        url_hash = hashlib.md5(normalized_url.encode()).hexdigest()
        
        if url_hash in self.endpoint_hash_set:
            return False
        
        self.endpoint_hash_set.add(url_hash)
        endpoint.url = normalized_url
        self.validated_endpoints.append(endpoint)
        
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG] Added validated endpoint: {endpoint.url} (confidence: {endpoint.confidence_score:.2f}){Colors.RESET}")
        
        return True
    
    async def verify_endpoint_stability(self, endpoint: ValidatedEndpoint, curl_engine) -> bool:
        """Verify endpoint stability with baseline requests"""
        
        if self.debug:
            print(f"{Colors.YELLOW}[DEBUG] Verifying stability for: {endpoint.url}{Colors.RESET}")
        
        try:
            # Make 2 baseline requests
            response1 = await curl_engine.get(endpoint.url)
            self.track_request(response1)
            
            # Add small delay
            await asyncio.sleep(0.5)
            
            response2 = await curl_engine.get(endpoint.url)
            self.track_request(response2)
            
            # Compare fingerprints
            fingerprint1 = self.generate_response_fingerprint(response1)
            fingerprint2 = self.generate_response_fingerprint(response2)
            
            stability = fingerprint1 == fingerprint2
            
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG] Stability check: {fingerprint1 == fingerprint2} ({fingerprint1[:8]}... vs {fingerprint2[:8]}...){Colors.RESET}")
            
            endpoint.stability_verified = stability
            return stability
            
        except Exception as e:
            if self.debug:
                print(f"{Colors.RED}[DEBUG] Stability verification failed: {e}{Colors.RESET}")
            return False
    
    def get_exploitable_endpoints(self) -> List[ValidatedEndpoint]:
        """Get endpoints that should proceed to vulnerability testing"""
        
        exploitable = []
        
        for endpoint in self.validated_endpoints:
            # Must have analysis
            if not endpoint.analysis:
                continue
            
            # Must be stable
            if not endpoint.stability_verified:
                continue
            
            # Must pass classifier verification
            if not self.classifier.should_proceed_to_vulnerability_testing(endpoint.analysis):
                continue
            
            exploitable.append(endpoint)
        
        return exploitable
    
    def get_endpoints_by_sensitivity(self, sensitivity: EndpointSensitivity) -> List[ValidatedEndpoint]:
        """Get endpoints by sensitivity level"""
        
        return [
            ep for ep in self.validated_endpoints
            if ep.analysis and ep.analysis.sensitivity == sensitivity and ep.stability_verified
        ]
    
    def get_endpoints_for_module(self, module_name: str) -> List[ValidatedEndpoint]:
        """Get endpoints that are allowed for specific module"""
        
        allowed_endpoints = []
        
        for endpoint in self.validated_endpoints:
            if not endpoint.analysis or not endpoint.stability_verified:
                continue
            
            # Check if module is allowed for this endpoint
            if module_name in endpoint.analysis.recommended_modules:
                allowed_endpoints.append(endpoint)
            elif module_name in endpoint.analysis.blocked_modules:
                continue
            else:
                # Default allow if not explicitly blocked
                allowed_endpoints.append(endpoint)
        
        return allowed_endpoints
    
    def has_exploitable_endpoints(self) -> bool:
        """Check if target has any exploitable endpoints"""
        
        return len(self.get_exploitable_endpoints()) > 0
    
    def should_terminate_early(self) -> bool:
        """Determine if scanning should terminate early"""
        
        # If no exploitable endpoints found, terminate early
        if not self.has_exploitable_endpoints():
            if self.debug:
                print(f"{Colors.YELLOW}[DEBUG] No exploitable endpoints found - terminating early{Colors.RESET}")
            return True
        
        return False
    
    def calculate_confidence_score(self, response: CurlResponse) -> float:
        """Calculate confidence score for endpoint"""
        
        score = 0.0
        
        # Status code scoring
        if response.status_code == 200:
            score += 0.4
        elif response.status_code in [201, 202, 301, 302]:
            score += 0.3
        elif response.status_code in [400, 401, 403]:
            score += 0.2
        elif response.status_code == 404:
            score -= 0.5
        elif response.status_code >= 500:
            score -= 0.3
        
        # Content type scoring
        content_type = response.content_type.lower()
        if 'application/json' in content_type:
            score += 0.3
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            score += 0.25
        elif 'text/html' in content_type:
            score += 0.1
        
        # Response size scoring
        if response.content_length > 1000:
            score += 0.2
        elif response.content_length > 100:
            score += 0.1
        elif response.content_length < 50:
            score -= 0.1
        
        # API indicators in response
        body_lower = response.body.lower()
        api_indicators = [
            '"id":', '"data":', '"results":', '"items":',
            '"error":', '"message":', '"status":', '"code":',
            '{"success":', '{"total":', '{"count":'
        ]
        
        api_matches = sum(1 for indicator in api_indicators if indicator in body_lower)
        score += min(api_matches * 0.1, 0.3)
        
        # URL pattern scoring
        url_lower = response.url.lower()
        if any(pattern in url_lower for pattern in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']):
            score += 0.2
        
        # Ensure score is between 0 and 1
        return max(0.0, min(1.0, score))
    
    def generate_response_fingerprint(self, response: CurlResponse) -> str:
        """Generate fingerprint for response comparison"""
        
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
    
    def add_confirmed_vulnerability(self, vulnerability: Dict[str, Any]):
        """Add confirmed exploitable vulnerability"""
        
        # Only add high-confidence findings
        if vulnerability.get('severity') in ['Critical', 'High']:
            self.confirmed_vulnerabilities.append(vulnerability)
            
            if self.debug:
                print(f"{Colors.RED}[DEBUG] Added confirmed vulnerability: {vulnerability.get('type')} - {vulnerability.get('severity')}{Colors.RESET}")
    
    def should_rate_limit(self, min_delay: float = 0.5) -> bool:
        """Check if we should rate limit requests"""
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < min_delay:
            return True
        
        return False
    
    def add_request_delay(self, min_delay: float = 0.5, max_delay: float = 2.0):
        """Add randomized delay between requests"""
        
        delay = random.uniform(min_delay, max_delay)
        
        if self.debug:
            print(f"{Colors.YELLOW}[DEBUG] Adding delay: {delay:.2f}s{Colors.RESET}")
        
        time.sleep(delay)
        self.last_request_time = time.time()
    
    def track_request(self, response: CurlResponse):
        """Track request statistics"""
        
        self.total_requests += 1
        self.request_times.append(time.time())
        
        if response.status_code < 500:
            self.successful_requests += 1
        
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG] Request #{self.total_requests}: {response.url} -> {response.status_code} ({response.content_length} bytes){Colors.RESET}")
    
    def get_high_confidence_endpoints(self, min_confidence: float = 0.6) -> List[ValidatedEndpoint]:
        """Get endpoints with confidence above threshold"""
        
        return [ep for ep in self.validated_endpoints if ep.confidence_score >= min_confidence]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        
        elapsed = time.time() - self.scan_start_time
        
        return {
            'target': self.target,
            'scan_duration': elapsed,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'validated_endpoints': len(self.validated_endpoints),
            'high_confidence_endpoints': len(self.get_high_confidence_endpoints()),
            'confirmed_vulnerabilities': len(self.confirmed_vulnerabilities),
            'success_rate': (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0
        }
    
    def export_context(self) -> Dict[str, Any]:
        """Export context for serialization"""
        
        data = {
            'target': self.target,
            'base_url': self.base_url,
            'mode': self.mode,
            'validated_endpoints': [
                {
                    'url': ep.url,
                    'method': ep.method,
                    'status_code': ep.status_code,
                    'content_type': ep.content_type,
                    'response_size': ep.response_size,
                    'confidence_score': ep.confidence_score,
                    'auth_required': ep.auth_required,
                    'parameters': ep.parameters
                }
                for ep in self.validated_endpoints
            ],
            'confirmed_vulnerabilities': self.confirmed_vulnerabilities,
            'statistics': self.get_statistics()
        }
        
        # Add attack surface data if available
        if self.attack_surface_graph:
            from core.attack_surface import AttackSurfaceMapper
            mapper = AttackSurfaceMapper()
            data['attack_surface'] = mapper.export_to_json(self.attack_surface_graph)
        
        # Add escalation decision if available
        if self.escalation_decision:
            data['escalation'] = {
                'should_escalate': self.escalation_decision.should_escalate,
                'level': self.escalation_decision.level.value if self.escalation_decision.level else None,
                'reason': self.escalation_decision.reason,
                'triggered_by': [t.value for t in self.escalation_decision.triggered_by],
                'recommended_modules': self.escalation_decision.recommended_modules
            }
        
        return data
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate vulnerability summary"""
        
        total_vulns = len(self.confirmed_vulnerabilities)
        high_risk_count = 0
        by_severity = {}
        by_type = {}
        
        for vuln in self.confirmed_vulnerabilities:
            # Count by severity
            severity = vuln.get('severity', 'Unknown')
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # Count by type
            vuln_type = vuln.get('type', 'Unknown')
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
            
            # Count high-risk findings
            if severity.lower() in ['critical', 'high']:
                high_risk_count += 1
        
        return {
            'total_vulnerabilities': total_vulns,
            'high_risk_findings': high_risk_count,
            'by_severity': by_severity,
            'by_type': by_type
        }
