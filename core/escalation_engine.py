"""
Escalation Engine - Automatic escalation logic for Critical/High severity findings
"""

import asyncio
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum, IntEnum
from urllib.parse import urlparse, parse_qs

from core.curl_engine import CurlEngine
from core.target_context import TargetContext
from core.endpoint_classifier import EndpointSensitivity
from core.attack_surface import AttackSurfaceGraph, AttackSurfaceMapper
from core.utils import Colors


class EscalationTrigger(Enum):
    """Triggers for escalation"""
    CRITICAL_VULNERABILITY = "critical_vulnerability"
    HIGH_VULNERABILITY = "high_vulnerability"
    MULTIPLE_VULNS = "multiple_vulnerabilities"
    CRITICAL_ASSET_EXPOSED = "critical_asset_exposed"
    ADMIN_ACCESS = "admin_access"


class EscalationLevel(IntEnum):
    """Escalation levels"""
    LEVEL_1 = 1  # enhanced_scanning      # Deeper parameter analysis
    LEVEL_2 = 2  # aggressive_testing      # More payload variations
    LEVEL_3 = 3  # comprehensive_assault  # Full attack surface mapping


@dataclass
class EscalationRule:
    """Escalation rule definition"""
    trigger: EscalationTrigger
    level: EscalationLevel
    condition: str
    modules: List[str]
    description: str


@dataclass
class EscalationDecision:
    """Escalation decision result"""
    should_escalate: bool
    level: Optional[EscalationLevel]
    reason: str
    triggered_by: List[EscalationTrigger]
    recommended_modules: List[str]


class EscalationEngine:
    """Intelligent escalation engine for vulnerability findings"""
    
    def __init__(self, curl_engine: CurlEngine, debug: bool = False):
        self.curl = curl_engine
        self.debug = debug
        self.attack_mapper = AttackSurfaceMapper(debug=debug)
        
        # Escalation rules
        self.escalation_rules = [
            EscalationRule(
                trigger=EscalationTrigger.CRITICAL_VULNERABILITY,
                level=EscalationLevel.LEVEL_3,
                condition="severity == 'Critical'",
                modules=['deep_idor', 'auth_bypass', 'privilege_escalation'],
                description="Critical vulnerability detected - full assault"
            ),
            EscalationRule(
                trigger=EscalationTrigger.HIGH_VULNERABILITY,
                level=EscalationLevel.LEVEL_2,
                condition="severity == 'High'",
                modules=['enhanced_idor', 'advanced_auth', 'parameter_analysis'],
                description="High severity vulnerability - aggressive testing"
            ),
            EscalationRule(
                trigger=EscalationTrigger.MULTIPLE_VULNS,
                level=EscalationLevel.LEVEL_2,
                condition="vulnerability_count >= 3",
                modules=['comprehensive_scan', 'correlation_analysis'],
                description="Multiple vulnerabilities - comprehensive analysis"
            ),
            EscalationRule(
                trigger=EscalationTrigger.CRITICAL_ASSET_EXPOSED,
                level=EscalationLevel.LEVEL_3,
                condition="critical_asset_exposed",
                modules=['asset_focused_scan', 'data_extraction'],
                description="Critical asset exposed - focused assault"
            ),
            EscalationRule(
                trigger=EscalationTrigger.ADMIN_ACCESS,
                level=EscalationLevel.LEVEL_3,
                condition="admin_endpoint_vulnerable",
                modules=['admin_exploitation', 'privilege_escalation'],
                description="Admin access possible - full exploitation"
            )
        ]
    
    async def analyze_and_escalate(self, context: TargetContext) -> EscalationDecision:
        """Analyze findings and determine if escalation is needed"""
        
        if self.debug:
            print(f"{Colors.YELLOW}[DEBUG] Analyzing escalation triggers for {context.target}{Colors.RESET}")
        
        # Get current findings
        vulnerabilities = context.confirmed_vulnerabilities
        exploitable_endpoints = context.get_exploitable_endpoints()
        
        # Create attack surface graph
        attack_graph = self.attack_mapper.create_attack_surface_graph(
            context.target, 
            exploitable_endpoints, 
            vulnerabilities
        )
        
        # Check escalation triggers
        triggered_rules = []
        
        for rule in self.escalation_rules:
            if self._evaluate_rule(rule, vulnerabilities, exploitable_endpoints, attack_graph):
                triggered_rules.append(rule)
        
        # Make escalation decision
        decision = self._make_escalation_decision(triggered_rules, attack_graph)
        
        if self.debug:
            self._debug_escalation_decision(decision, attack_graph)
        
        return decision
    
    def _evaluate_rule(self, rule: EscalationRule, 
                       vulnerabilities: List[Dict[str, Any]], 
                       endpoints: List[Any], 
                       attack_graph: AttackSurfaceGraph) -> bool:
        """Evaluate if escalation rule is triggered"""
        
        condition = rule.condition.lower()
        
        # Check severity conditions
        if 'critical' in condition:
            if any(v.get('severity') == 'Critical' for v in vulnerabilities):
                return True
        
        if 'high' in condition:
            if any(v.get('severity') == 'High' for v in vulnerabilities):
                return True
        
        # Check count conditions
        if 'vulnerability_count' in condition:
            count = len(vulnerabilities)
            if '>= 3' in condition and count >= 3:
                return True
            if '>= 2' in condition and count >= 2:
                return True
        
        # Check critical asset conditions
        if 'critical_asset' in condition:
            if attack_graph.critical_assets:
                # Check if any critical asset has vulnerabilities
                for asset in attack_graph.critical_assets:
                    asset_url = asset['url']
                    if any(v.get('url') == asset_url for v in vulnerabilities):
                        return True
        
        # Check admin access conditions
        if 'admin' in condition:
            for vuln in vulnerabilities:
                if 'admin' in vuln.get('url', '').lower():
                    return True
        
        return False
    
    def _make_escalation_decision(self, triggered_rules: List[EscalationRule], 
                                 attack_graph: AttackSurfaceGraph) -> EscalationDecision:
        """Make final escalation decision"""
        
        if not triggered_rules:
            return EscalationDecision(
                should_escalate=False,
                level=None,
                reason="No escalation triggers met",
                triggered_by=[],
                recommended_modules=[]
            )
        
        # Find highest escalation level
        highest_level = max(rule.level for rule in triggered_rules)
        
        # Combine all recommended modules
        all_modules = []
        triggered_by = []
        
        for rule in triggered_rules:
            all_modules.extend(rule.modules)
            triggered_by.append(rule.trigger)
        
        # Remove duplicates
        all_modules = list(set(all_modules))
        
        # Generate reason
        rule_descriptions = [rule.description for rule in triggered_rules]
        reason = f"Escalation triggered: {'; '.join(rule_descriptions)}"
        
        return EscalationDecision(
            should_escalate=True,
            level=highest_level,
            reason=reason,
            triggered_by=triggered_by,
            recommended_modules=all_modules
        )
    
    async def execute_escalation(self, context: TargetContext, 
                               decision: EscalationDecision) -> List[Dict[str, Any]]:
        """Execute escalation with additional scanning modules"""
        
        if not decision.should_escalate:
            return []
        
        print(f"{Colors.RED}[!] ESCALATION TRIGGERED: {decision.reason}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Escalation Level: LEVEL_{decision.level}{Colors.RESET}")
        
        escalated_findings = []
        
        # Execute escalation modules based on level
        if decision.level == EscalationLevel.LEVEL_1:
            escalated_findings.extend(await self._execute_level_1(context))
        elif decision.level == EscalationLevel.LEVEL_2:
            escalated_findings.extend(await self._execute_level_2(context))
        elif decision.level == EscalationLevel.LEVEL_3:
            escalated_findings.extend(await self._execute_level_3(context))
        
        print(f"{Colors.GREEN}[+] Escalation completed: {len(escalated_findings)} additional findings{Colors.RESET}")
        
        return escalated_findings
    
    async def _execute_level_1(self, context: TargetContext) -> List[Dict[str, Any]]:
        """Execute Level 1 escalation - Enhanced scanning"""
        
        print(f"{Colors.YELLOW}    [*] Level 1 Escalation: Enhanced parameter analysis{Colors.RESET}")
        
        findings = []
        
        # Enhanced parameter analysis
        exploitable_endpoints = context.get_exploitable_endpoints()
        
        for endpoint in exploitable_endpoints:
            # Deep parameter discovery
            deep_params = await self._discover_deep_parameters(endpoint.url)
            
            if deep_params:
                finding = {
                    'type': 'Deep Parameter Discovery',
                    'severity': 'Medium',
                    'url': endpoint.url,
                    'description': f"Discovered {len(deep_params)} additional parameters",
                    'parameters': deep_params,
                    'escalation_level': 'LEVEL_1'
                }
                findings.append(finding)
        
        return findings
    
    async def _execute_level_2(self, context: TargetContext) -> List[Dict[str, Any]]:
        """Execute Level 2 escalation - Aggressive testing"""
        
        print(f"{Colors.YELLOW}    [*] Level 2 Escalation: Aggressive payload testing{Colors.RESET}")
        
        findings = []
        
        # Aggressive IDOR testing
        exploitable_endpoints = context.get_exploitable_endpoints()
        
        for endpoint in exploitable_endpoints:
            # Extended payload testing
            extended_findings = await self._extended_payload_testing(endpoint)
            findings.extend(extended_findings)
        
        # Authentication bypass attempts
        auth_findings = await self._advanced_auth_testing(context)
        findings.extend(auth_findings)
        
        return findings
    
    async def _execute_level_3(self, context: TargetContext) -> List[Dict[str, Any]]:
        """Execute Level 3 escalation - Comprehensive assault"""
        
        print(f"{Colors.YELLOW}    [*] Level 3 Escalation: Comprehensive assault{Colors.RESET}")
        
        findings = []
        
        # Execute all lower levels
        findings.extend(await self._execute_level_1(context))
        findings.extend(await self._execute_level_2(context))
        
        # Additional Level 3 specific tests
        comprehensive_findings = await self._comprehensive_assault(context)
        findings.extend(comprehensive_findings)
        
        return findings
    
    async def _discover_deep_parameters(self, url: str) -> List[str]:
        """Discover additional parameters through analysis"""
        
        # This would implement advanced parameter discovery
        # For now, return common hidden parameters
        hidden_params = [
            'admin', 'debug', 'test', 'dev', 'beta', 'internal',
            'backup', 'old', 'legacy', 'temp', 'cache'
        ]
        
        # Filter based on URL patterns
        discovered = []
        url_lower = url.lower()
        
        for param in hidden_params:
            if param not in url_lower:
                discovered.append(param)
        
        return discovered[:5]  # Limit to 5 new parameters
    
    async def _extended_payload_testing(self, endpoint: Any) -> List[Dict[str, Any]]:
        """Extended payload testing for endpoints"""
        
        findings = []
        
        # SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users--"
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>", "javascript:alert('XSS')", "<img src=x onerror=alert('XSS')>"
        ]
        
        # Test payloads (simplified)
        for payload in sqli_payloads[:2]:  # Limit for safety
            try:
                test_url = f"{endpoint.url}?id={payload}"
                response = await self.curl.get(test_url)
                
                # Check for SQL injection indicators
                if 'sql' in response.body.lower() or 'mysql' in response.body.lower():
                    finding = {
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'url': test_url,
                        'description': 'Potential SQL injection vulnerability',
                        'payload': payload,
                        'escalation_level': 'LEVEL_2'
                    }
                    findings.append(finding)
                    break  # Stop after first finding
            
            except Exception:
                continue
        
        return findings
    
    async def _advanced_auth_testing(self, context: TargetContext) -> List[Dict[str, Any]]:
        """Advanced authentication bypass testing"""
        
        findings = []
        
        # Test common auth bypass techniques
        auth_endpoints = context.get_endpoints_by_sensitivity(EndpointSensitivity.AUTH_RELATED)
        
        for endpoint in auth_endpoints:
            # Test for JWT None algorithm
            jwt_payloads = [
                '{"alg":"none","typ":"JWT"}.{"admin":true}.'
            ]
            
            for payload in jwt_payloads:
                try:
                    response = await self.curl.get(
                        endpoint.url,
                        headers={'Authorization': f'Bearer {payload}'}
                    )
                    
                    if response.status_code == 200:
                        finding = {
                            'type': 'JWT Algorithm None',
                            'severity': 'Critical',
                            'url': endpoint.url,
                            'description': 'JWT algorithm None vulnerability',
                            'payload': payload,
                            'escalation_level': 'LEVEL_2'
                        }
                        findings.append(finding)
                        break
                
                except Exception:
                    continue
        
        # Test AJAX parameter manipulation for access control bypass
        ajax_endpoints = [ep for ep in context.get_exploitable_endpoints() if 'search' in ep.url]
        
        for endpoint in ajax_endpoints:
            # Test hidden AJAX actions for privilege escalation
            test_actions = [
                'admin', 'export', 'download', 'backup', 'config', 'debug',
                'users', 'login', 'logout', 'profile', 'account', 'settings',
                'dashboard', 'manage', 'edit', 'delete', 'update', 'create',
                'list', 'view', 'import', 'upload', 'remove', 'add'
            ]
            
            for action in test_actions:
                try:
                    test_url = f"{endpoint.url}?do={action}"
                    response = await self.curl.get(
                        test_url,
                        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'}
                    )
                    
                    # Check for unauthorized access or information disclosure
                    if response.status_code == 200 and len(response.body) > 50:
                        # Look for sensitive data in response
                        sensitive_patterns = [
                            'admin', 'user', 'password', 'token', 'key',
                            'email', 'id', 'role', 'permission', 'config'
                        ]
                        
                        response_lower = response.body.lower()
                        if any(pattern in response_lower for pattern in sensitive_patterns):
                            finding = {
                                'type': 'AJAX Parameter Bypass',
                                'severity': 'High',
                                'url': test_url,
                                'description': f'Potential unauthorized access via do={action} parameter',
                                'parameter': 'do',
                                'action': action,
                                'response_length': len(response.body),
                                'escalation_level': 'LEVEL_2'
                            }
                            findings.append(finding)
                            break
                
                except Exception:
                    continue
        
        # Test selectedTab parameter for role bypass
        for endpoint in ajax_endpoints:
            test_tabs = ['admin', 'manage', 'settings', 'config', 'users', 'dashboard']
            
            for tab in test_tabs:
                try:
                    test_url = f"{endpoint.url}?selectedTab={tab}"
                    response = await self.curl.get(
                        test_url,
                        headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'}
                    )
                    
                    if response.status_code == 200 and len(response.body) > 100:
                        # Check if response differs from normal tab response
                        if 'admin' in response.body.lower() or 'manage' in response.body.lower():
                            finding = {
                                'type': 'Tab Parameter Bypass',
                                'severity': 'Medium',
                                'url': test_url,
                                'description': f'Potential role bypass via selectedTab={tab}',
                                'parameter': 'selectedTab',
                                'tab': tab,
                                'escalation_level': 'LEVEL_1'
                            }
                            findings.append(finding)
                
                except Exception:
                    continue
        
        return findings
    
    async def _comprehensive_assault(self, context: TargetContext) -> List[Dict[str, Any]]:
        """Comprehensive assault on critical assets"""
        
        findings = []
        
        # Focus on critical assets
        exploitable_endpoints = context.get_exploitable_endpoints()
        
        for endpoint in exploitable_endpoints:
            # Check for admin endpoints
            if 'admin' in endpoint.url.lower():
                # Test for privilege escalation
                priv_findings = await self._test_privilege_escalation(endpoint)
                findings.extend(priv_findings)
            
            # Check for data extraction opportunities
            data_findings = await self._test_data_extraction(endpoint)
            findings.extend(data_findings)
        
        return findings
    
    async def _test_privilege_escalation(self, endpoint: Any) -> List[Dict[str, Any]]:
        """Test for privilege escalation vulnerabilities"""
        
        findings = []
        
        # Test admin role parameters
        admin_params = ['role', 'admin', 'privilege', 'level']
        
        for param in admin_params:
            test_url = f"{endpoint.url}?{param}=admin"
            
            try:
                response = await self.curl.get(test_url)
                
                if response.status_code == 200 and 'admin' in response.body.lower():
                    finding = {
                        'type': 'Privilege Escalation',
                        'severity': 'Critical',
                        'url': test_url,
                        'description': 'Potential privilege escalation vulnerability',
                        'parameter': param,
                        'escalation_level': 'LEVEL_3'
                    }
                    findings.append(finding)
                    break
            
            except Exception:
                continue
        
        return findings
    
    async def _test_data_extraction(self, endpoint: Any) -> List[Dict[str, Any]]:
        """Test for data extraction opportunities"""
        
        findings = []
        
        # Test for common data extraction parameters
        extract_params = ['format', 'output', 'export', 'download']
        
        for param in extract_params:
            for value in ['json', 'csv', 'xml', 'raw']:
                test_url = f"{endpoint.url}?{param}={value}"
                
                try:
                    response = await self.curl.get(test_url)
                    
                    if response.status_code == 200 and len(response.body) > 1000:
                        finding = {
                            'type': 'Data Extraction',
                            'severity': 'High',
                            'url': test_url,
                            'description': f'Potential data extraction via {param}={value}',
                            'parameter': param,
                            'escalation_level': 'LEVEL_3'
                        }
                        findings.append(finding)
                        break
                
                except Exception:
                    continue
        
        return findings
    
    def _debug_escalation_decision(self, decision: EscalationDecision, 
                                  attack_graph: AttackSurfaceGraph):
        """Debug escalation decision"""
        
        print(f"{Colors.CYAN}[DEBUG] Escalation Decision:{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Should Escalate: {decision.should_escalate}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Level: {decision.level}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Reason: {decision.reason}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Triggers: {[t.value for t in decision.triggered_by]}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Recommended Modules: {decision.recommended_modules}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Attack Surface Score: {self.attack_mapper._calculate_attack_surface_score(attack_graph)}{Colors.RESET}")
