"""
Main Scanner Coordinator - Orchestrates sequential scanning with strict validation
"""

import asyncio
import os
import json
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime

# Import global shutdown event
from core.shutdown import shutdown_event

from core.curl_engine import CurlEngine
from core.task_engine import TaskEngine, TaskResult
from core.target_context import TargetContext, ValidatedEndpoint
from core.attack_surface import AttackSurfaceMapper, AttackSurfaceGraph
from core.escalation_engine import EscalationEngine, EscalationDecision
from core.utils import Colors, Banner, setup_colors
from modules.api_discovery import APIDiscovery
from modules.unauth_api import UnauthAPIDetection
from modules.idor_detection import IDORDetection
from modules.token_leakage import TokenLeakageScanner
from modules.web_vulns import WebVulnsScanner


class Scanner:
    """Main scanner coordinator"""
    
    def __init__(self, args, output_engine):
        self.args = args
        self.output_engine = output_engine
        
        # Setup colors
        setup_colors(args.silent)
        
        # Initialize curl engine
        self.curl = CurlEngine(
            timeout=args.timeout,
            proxy=args.proxy if hasattr(args, 'proxy') and args.proxy else None,
            debug=getattr(args, 'debug', False)
        )
        
        # Initialize task engine
        self.task_engine = TaskEngine(
            max_workers=args.threads,
            checkpoint_interval=60
        )
        
        # Initialize attack surface mapper
        self.attack_mapper = AttackSurfaceMapper(debug=getattr(args, 'debug', False))
        
        # Initialize escalation engine
        self.escalation_engine = EscalationEngine(self.curl, debug=getattr(args, 'debug', False))
        
        # Initialize scanning modules
        self.modules = {}
        self._initialize_modules()
        
        # Results storage
        self.results = {}
        
    def _initialize_modules(self):
        """Initialize scanning modules based on mode"""
        
        mode_config = self._get_mode_config()
        
        # Initialize required modules
        if 'api_discovery' in mode_config['modules']:
            self.modules['api_discovery'] = APIDiscovery(self.curl)
        
        if 'unauth_api' in mode_config['modules']:
            self.modules['unauth_api'] = UnauthAPIDetection(self.curl)
        
        if 'idor_detection' in mode_config['modules']:
            self.modules['idor_detection'] = IDORDetection(self.curl)
        
        if 'token_leakage' in mode_config['modules']:
            self.modules['token_leakage'] = TokenLeakageScanner(self.curl)
        
        if 'web_vulns' in mode_config['modules']:
            self.modules['web_vulns'] = WebVulnsScanner(self.curl)
    
    def _get_mode_config(self) -> Dict[str, Any]:
        """Get configuration for current scanning mode"""
        
        configs = {
            'fast': {
                'modules': ['token_leakage', 'api_discovery', 'web_vulns'],
                'aggressive': False
            },
            'bounty': {
                'modules': [
                    'api_discovery', 'unauth_api', 'idor_detection', 
                    'token_leakage', 'web_vulns'
                ],
                'aggressive': True
            },
            'deep': {
                'modules': [
                    'api_discovery', 'unauth_api', 'idor_detection', 
                    'token_leakage', 'web_vulns'
                ],
                'aggressive': True,
                'deep_scan': True
            }
        }
        
        return configs.get(self.args.mode, configs['bounty'])
    
    async def scan_targets(self, targets: List[str]) -> Dict[str, Any]:
        """Main scanning method - sequential target processing"""
        
        print(f"{Colors.GREEN}[+] Starting sequential scan in {self.args.mode.upper()} mode{Colors.RESET}")
        
        # Initialize results structure
        for target in targets:
            self.results[target] = {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'mode': self.args.mode,
                'modules': {},
                'vulnerabilities': [],
                'summary': {}
            }
        
        # Process targets sequentially
        for i, target in enumerate(targets, 1):
            print(f"{Colors.CYAN}[*] Processing target {i}/{len(targets)}: {target}{Colors.RESET}")
            
            # Create target context
            context = TargetContext(
                target=target,
                base_url=target,
                mode=self.args.mode,
                debug=getattr(self.args, 'debug', False)
            )
            
            # Run sequential pipeline
            await self._run_sequential_pipeline(target, context)
            
            # Store results
            self.results[target].update(context.export_context())
            self.results[target]['vulnerabilities'] = context.confirmed_vulnerabilities
            self.results[target]['summary'] = context.generate_summary()
        
        # Generate summary
        self._generate_global_summary()
        
        return self.results
    
    async def _run_sequential_pipeline(self, target: str, context: TargetContext):
        """Run sequential scanning pipeline with verification gates and escalation"""
        
        print(f"{Colors.YELLOW}    [*] Starting sequential pipeline for {target}{Colors.RESET}")
        
        # Check for shutdown signal before starting pipeline
        if shutdown_event.is_set():
            return
        
        # Step 1: API Discovery with verification gates
        should_continue = await self._step_api_discovery(context)
        
        if not should_continue:
            print(f"{Colors.YELLOW}    [-] Pipeline terminated early - no exploitable endpoints{Colors.RESET}")
            return
        
        # Check for shutdown signal between steps
        if shutdown_event.is_set():
            return
        
        # Step 2: Auth Testing (only on allowed endpoints)
        await self._step_auth_testing(context)
        
        # Check for shutdown signal between steps
        if shutdown_event.is_set():
            return
        
        # Step 3: IDOR Testing (only on allowed endpoints)
        await self._step_idor_testing(context)
        
        # Check for shutdown signal between steps
        if shutdown_event.is_set():
            return
        
        # Step 4: Token Scanning
        await self._step_token_scanning(context)
        
        # Check for shutdown signal between steps
        if shutdown_event.is_set():
            return
        
        # Step 5: Attack Surface Mapping
        await self._step_attack_surface_mapping(context)
        
        # Check for shutdown signal between steps
        if shutdown_event.is_set():
            return
        
        # Step 6: Escalation Analysis and Execution
        await self._step_escalation_analysis(context)
        
        # Check for shutdown signal between steps
        if shutdown_event.is_set():
            return
        
        # Step 7: Classic Web Vulnerabilities
        await self._step_web_vulnerabilities(context)
        
        print(f"{Colors.GREEN}[+] Pipeline completed for {target}{Colors.RESET}")
    
    async def _step_api_discovery(self, context: TargetContext):
        """Step 1: API Discovery with strict validation and verification gates"""
        
        # Check for shutdown signal
        if shutdown_event.is_set():
            return
        
        print(f"{Colors.YELLOW}        [*] Step 1: API Discovery & Validation{Colors.RESET}")
        
        if 'api_discovery' not in self.modules:
            return
        
        try:
            # Discover endpoints
            discovered_endpoints = await self.modules['api_discovery'].scan_endpoints(context.base_url)
            
            # Validate and analyze each endpoint
            for endpoint in discovered_endpoints:
                if await self._validate_endpoint(context, endpoint):
                    # Get response for analysis
                    response = await self._get_endpoint_response(context, endpoint.url)
                    
                    # Analyze endpoint with classifier
                    analysis = context.classifier.analyze_endpoint(endpoint.url, response)
                    
                    # Create validated endpoint
                    validated = ValidatedEndpoint(
                        url=endpoint.url,
                        method=endpoint.method,
                        status_code=endpoint.status_code,
                        content_type=endpoint.content_type,
                        response_size=endpoint.response_size,
                        confidence_score=context.calculate_confidence_score(response),
                        response_fingerprint=context.generate_response_fingerprint(response),
                        auth_required=endpoint.auth_required,
                        parameters=endpoint.parameters,
                        headers=endpoint.headers,
                        analysis=analysis
                    )
                    
                    context.add_validated_endpoint(validated)
            
            # Verify stability for all endpoints
            print(f"{Colors.YELLOW}        [*] Verifying endpoint stability...{Colors.RESET}")
            stable_count = 0
            for endpoint in context.validated_endpoints:
                if await context.verify_endpoint_stability(endpoint, self.curl):
                    stable_count += 1
            
            # Filter exploitable endpoints
            exploitable = context.get_exploitable_endpoints()
            
            print(f"{Colors.GREEN}        [+] Validated {len(context.validated_endpoints)} endpoints, {stable_count} stable, {len(exploitable)} exploitable{Colors.RESET}")
            
            # Early termination check
            if context.should_terminate_early():
                print(f"{Colors.YELLOW}        [-] No exploitable endpoints found - continuing with all endpoints for testing{Colors.RESET}")
                # Don't terminate - continue with all endpoints for authorization testing
            
            return True  # Continue with vulnerability testing
            
        except asyncio.TimeoutError as e:
            print(f"{Colors.RED}[!] API discovery timeout: {e}{Colors.RESET}")
            return False
        except ConnectionError as e:
            print(f"{Colors.RED}[!] API discovery connection failed: {e}{Colors.RESET}")
            return False
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[!] API discovery malformed response: {e}{Colors.RESET}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[!] API discovery failed: {e}{Colors.RESET}")
            return False
    
    async def _validate_endpoint(self, context: TargetContext, endpoint) -> bool:
        """Strict endpoint validation"""
        
        try:
            # Rate limiting
            if context.should_rate_limit():
                context.add_request_delay()
            
            # Make request
            response = await self.curl.get(endpoint.url)
            context.track_request(response)
            
            # Check for rate limiting errors and handle adaptively
            if response.status_code in [429, 503]:
                self.task_engine.handle_rate_limit_error(response.status_code)
            elif response.status_code < 400:
                self.task_engine.handle_success_response()
            
            # Strict validation criteria
            if response.status_code == 404:
                return False
            
            if response.status_code >= 500:
                return False
            
            # Content type validation
            content_type = response.content_type.lower()
            valid_types = [
                'application/json', 'application/xml', 'text/xml',
                'application/vnd.api+json', 'text/plain', 'text/html'
            ]
            
            if not any(valid_type in content_type for valid_type in valid_types):
                if context.debug:
                    print(f"{Colors.RED}[DEBUG] Invalid content type for {endpoint.url}: {content_type}{Colors.RESET}")
                return False
            
            # Response size validation
            if response.content_length < 20:  # Too small to be meaningful
                return False
            
            # Debug output
            if context.debug:
                print(f"{Colors.CYAN}[DEBUG] Validated: {endpoint.url} -> {response.status_code} ({response.content_length} bytes, {content_type}){Colors.RESET}")
            
            return True
            
        except asyncio.TimeoutError as e:
            if context.debug:
                print(f"{Colors.RED}[DEBUG] Validation timeout for {endpoint.url}: {e}{Colors.RESET}")
            return False
        except ConnectionError as e:
            if context.debug:
                print(f"{Colors.RED}[DEBUG] Validation connection failed for {endpoint.url}: {e}{Colors.RESET}")
            return False
        except json.JSONDecodeError as e:
            if context.debug:
                print(f"{Colors.RED}[DEBUG] Validation malformed response for {endpoint.url}: {e}{Colors.RESET}")
            return False
        except Exception as e:
            if context.debug:
                print(f"{Colors.RED}[DEBUG] Validation failed for {endpoint.url}: {e}{Colors.RESET}")
            return False
    
    async def _get_endpoint_response(self, context: TargetContext, url: str):
        """Get endpoint response for confidence scoring"""
        
        try:
            if context.should_rate_limit():
                context.add_request_delay()
            
            response = await self.curl.get(url)
            context.track_request(response)
            
            # Check for rate limiting errors and handle adaptively
            if response.status_code in [429, 503]:
                self.task_engine.handle_rate_limit_error(response.status_code)
            elif response.status_code < 400:
                self.task_engine.handle_success_response()
            
            return response
            
        except asyncio.TimeoutError as e:
            if context.debug:
                print(f"{Colors.RED}[DEBUG] Endpoint response timeout for {url}: {e}{Colors.RESET}")
        except ConnectionError as e:
            if context.debug:
                print(f"{Colors.RED}[DEBUG] Endpoint connection failed for {url}: {e}{Colors.RESET}")
        except json.JSONDecodeError as e:
            if context.debug:
                print(f"{Colors.RED}[DEBUG] Endpoint malformed JSON for {url}: {e}{Colors.RESET}")
        except Exception as e:
            # Return empty response on error
            if context.debug:
                print(f"{Colors.RED}[DEBUG] Endpoint error for {url}: {e}{Colors.RESET}")
            from core.curl_engine import CurlResponse
            return CurlResponse(
                url=url, status_code=0, headers={}, body="", response_time=0,
                redirect_url="", content_length=0, content_type=""
            )
    
    async def _step_auth_testing(self, context: TargetContext):
        """Step 2: Authentication Testing with endpoint filtering"""
        
        # Check for shutdown signal
        if shutdown_event.is_set():
            return
        
        print(f"{Colors.YELLOW}        [*] Step 2: Authentication Testing{Colors.RESET}")
        
        if 'unauth_api' not in self.modules:
            return
        
        # Check for exploitable endpoints
        exploitable_endpoints = context.get_exploitable_endpoints()
        
        if not exploitable_endpoints:
            print(f"{Colors.YELLOW}        [-] No exploitable endpoints found - continuing with basic endpoints{Colors.RESET}")
            # Continue with all discovered endpoints for testing
            exploitable_endpoints = context.validated_endpoints
        
        try:
            endpoint_urls = [ep.url for ep in exploitable_endpoints]
            unauth_findings = await self.modules['unauth_api'].scan_endpoints(context.base_url, endpoint_urls)
            
            # Add confirmed vulnerabilities
            for finding in unauth_findings:
                if finding.severity in ['Critical', 'High']:
                    vuln = {
                        'type': 'Unauthenticated API Access',
                        'severity': finding.severity,
                        'url': finding.url,
                        'description': finding.description,
                        'data': finding.sample_data,
                        'module': 'auth_testing'
                    }
                    context.add_confirmed_vulnerability(vuln)
            
            print(f"{Colors.GREEN}        [+] Found {len([f for f in unauth_findings if f.severity in ['Critical', 'High']])} confirmed auth issues{Colors.RESET}")
            
        except asyncio.TimeoutError as e:
            print(f"{Colors.RED}[!] Auth testing timeout: {e}{Colors.RESET}")
        except ConnectionError as e:
            print(f"{Colors.RED}[!] Auth testing connection failed: {e}{Colors.RESET}")
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[!] Auth testing malformed response: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Auth testing failed: {e}{Colors.RESET}")
    
    async def _step_idor_testing(self, context: TargetContext):
        """Step 3: IDOR Testing with endpoint filtering"""
        
        # Check for shutdown signal
        if shutdown_event.is_set():
            return
        
        print(f"{Colors.YELLOW}        [*] Step 3: IDOR Testing{Colors.RESET}")
        
        if 'idor_detection' not in self.modules:
            return
        
        # Get endpoints allowed for IDOR testing
        idor_endpoints = context.get_endpoints_for_module('idor_detection')
        
        if not idor_endpoints:
            print(f"{Colors.YELLOW}        [-] No endpoints allowed for IDOR testing{Colors.RESET}")
            return
        
        try:
            endpoint_urls = [ep.url for ep in idor_endpoints]
            idor_findings = await self.modules['idor_detection'].scan_endpoints(context.base_url, endpoint_urls)
            
            # Add confirmed vulnerabilities
            for finding in idor_findings:
                if finding.severity in ['Critical', 'High']:
                    vuln = {
                        'type': 'IDOR',
                        'severity': finding.severity,
                        'url': finding.url,
                        'description': finding.description,
                        'parameter': finding.parameter,
                        'module': 'idor_testing'
                    }
                    context.add_confirmed_vulnerability(vuln)
            
            print(f"{Colors.GREEN}        [+] Found {len([f for f in idor_findings if f.severity in ['Critical', 'High']])} confirmed IDOR issues{Colors.RESET}")
            
        except asyncio.TimeoutError as e:
            print(f"{Colors.RED}[!] IDOR testing timeout: {e}{Colors.RESET}")
        except ConnectionError as e:
            print(f"{Colors.RED}[!] IDOR testing connection failed: {e}{Colors.RESET}")
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[!] IDOR testing malformed response: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] IDOR testing failed: {e}{Colors.RESET}")
    
    async def _step_token_scanning(self, context: TargetContext):
        """Step 4: Token Scanning"""
        
        # Check for shutdown signal
        if shutdown_event.is_set():
            return
        
        print(f"{Colors.YELLOW}        [*] Step 4: Token Leakage Scanning{Colors.RESET}")
        
        if 'token_leakage' not in self.modules:
            return
        
        try:
            # Scan main target and high-confidence endpoints
            high_conf_endpoints = context.get_high_confidence_endpoints(min_confidence=0.6)
            endpoint_urls = [ep.url for ep in high_conf_endpoints]
            
            token_findings = await self.modules['token_leakage'].scan_target(context.base_url, endpoint_urls)
            
            # Add confirmed vulnerabilities
            for finding in token_findings:
                if finding.severity in ['Critical', 'High']:
                    vuln = {
                        'type': 'Token Leakage',
                        'severity': finding.severity,
                        'url': finding.url,
                        'description': finding.description,
                        'token_type': finding.token_type,
                        'module': 'token_scanning'
                    }
                    context.add_confirmed_vulnerability(vuln)
            
            print(f"{Colors.GREEN}        [+] Found {len([f for f in token_findings if f.severity in ['Critical', 'High']])} confirmed token leaks{Colors.RESET}")
            
        except asyncio.TimeoutError as e:
            print(f"{Colors.RED}[!] Token scanning timeout: {e}{Colors.RESET}")
        except ConnectionError as e:
            print(f"{Colors.RED}[!] Token scanning connection failed: {e}{Colors.RESET}")
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[!] Token scanning malformed response: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Token scanning failed: {e}{Colors.RESET}")
    
    async def _step_attack_surface_mapping(self, context: TargetContext):
        """Step 5: Attack Surface Mapping"""
        
        # Check for shutdown signal
        if shutdown_event.is_set():
            return
        
        print(f"{Colors.YELLOW}        [*] Step 5: Attack Surface Mapping{Colors.RESET}")
        
        try:
            # Get exploitable endpoints and vulnerabilities
            exploitable_endpoints = context.get_exploitable_endpoints()
            vulnerabilities = context.confirmed_vulnerabilities
            
            # Create attack surface graph
            attack_graph = self.attack_mapper.create_attack_surface_graph(
                context.target,
                exploitable_endpoints,
                vulnerabilities
            )
            
            # Store attack surface in context
            context.attack_surface_graph = attack_graph
            
            # Print statistics
            stats = self.attack_mapper._calculate_graph_statistics(attack_graph)
            print(f"{Colors.GREEN}        [+] Attack Surface: {stats['endpoint_nodes']} endpoints, {stats['vulnerability_nodes']} vulnerabilities{Colors.RESET}")
            print(f"{Colors.GREEN}        [+] Critical Assets: {len(attack_graph.critical_assets)}, Attack Paths: {len(attack_graph.attack_paths)}{Colors.RESET}")
            print(f"{Colors.GREEN}        [+] Attack Surface Score: {stats['attack_surface_score']}{Colors.RESET}")
            
        except asyncio.TimeoutError as e:
            print(f"{Colors.RED}[!] Attack surface mapping timeout: {e}{Colors.RESET}")
        except ConnectionError as e:
            print(f"{Colors.RED}[!] Attack surface mapping connection failed: {e}{Colors.RESET}")
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[!] Attack surface mapping malformed response: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Attack surface mapping failed: {e}{Colors.RESET}")
    
    async def _step_escalation_analysis(self, context: TargetContext):
        """Step 6: Escalation Analysis and Execution"""
        
        # Check for shutdown signal
        if shutdown_event.is_set():
            return
        
        print(f"{Colors.YELLOW}        [*] Step 6: Escalation Analysis{Colors.RESET}")
        
        try:
            # Analyze for escalation triggers
            escalation_decision = await self.escalation_engine.analyze_and_escalate(context)
            
            # Store escalation decision in context
            context.escalation_decision = escalation_decision
            
            # Execute escalation if triggered
            if escalation_decision.should_escalate:
                escalated_findings = await self.escalation_engine.execute_escalation(context, escalation_decision)
                
                # Add escalated findings to context
                for finding in escalated_findings:
                    context.add_confirmed_vulnerability(finding)
                
                print(f"{Colors.GREEN}        [+] Escalation added {len(escalated_findings)} new findings{Colors.RESET}")
            else:
                print(f"{Colors.CYAN}        [-] No escalation needed{Colors.RESET}")
            
        except asyncio.TimeoutError as e:
            print(f"{Colors.RED}[!] Escalation analysis timeout: {e}{Colors.RESET}")
        except ConnectionError as e:
            print(f"{Colors.RED}[!] Escalation analysis connection failed: {e}{Colors.RESET}")
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[!] Escalation analysis malformed response: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Escalation analysis failed: {e}{Colors.RESET}")
    
    def _serialize_finding(self, finding) -> Dict[str, Any]:
        """Serialize finding object to dictionary"""
        
        if hasattr(finding, '__dict__'):
            return {k: v for k, v in finding.__dict__.items() 
                   if not k.startswith('_') and not callable(v)}
        else:
            return {'data': str(finding)}
    
    def _generate_target_summary(self, target_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for target"""
        
        vulnerabilities = target_results.get('vulnerabilities', [])
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': {},
            'by_type': {},
            'high_risk_findings': 0
        }
        
        # Count by severity
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            if severity in ['Critical', 'High']:
                summary['high_risk_findings'] += 1
        
        # Count by type
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
        
        return summary
    
    async def _step_web_vulnerabilities(self, context: TargetContext):
        """Step 7: Classic Web Vulnerability Scanning"""
        
        # Check for shutdown signal
        if shutdown_event.is_set():
            return
        
        print(f"{Colors.YELLOW}        [*] Step 7: Classic Web Vulnerability Scanning{Colors.RESET}")
        
        if 'web_vulns' not in self.modules:
            return
        
        try:
            # Scan for classic web vulnerabilities
            web_findings = await self.modules['web_vulns'].scan_target(context.base_url)
            
            # Convert findings to standard format
            for finding in web_findings:
                vuln = {
                    'type': finding.vuln_type,
                    'severity': finding.severity,
                    'url': finding.url,
                    'description': finding.description,
                    'parameter': finding.parameter,
                    'payload': finding.payload,
                    'evidence': finding.evidence,
                    'module': 'web_vulns'
                }
                context.add_confirmed_vulnerability(vuln)
            
            high_risk_count = len([f for f in web_findings if f.severity in ['Critical', 'High']])
            print(f"{Colors.GREEN}        [+] Found {high_risk_count} high-risk classic web vulnerabilities{Colors.RESET}")
            
        except asyncio.TimeoutError as e:
            print(f"{Colors.RED}[!] Web vulnerability scanning timeout: {e}{Colors.RESET}")
        except ConnectionError as e:
            print(f"{Colors.RED}[!] Web vulnerability scanning connection failed: {e}{Colors.RESET}")
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[!] Web vulnerability scanning malformed response: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Web vulnerability scanning failed: {e}{Colors.RESET}")
    
    def _generate_global_summary(self):
        """Generate global summary across all targets"""
        
        total_vulnerabilities = 0
        total_high_risk = 0
        global_by_severity = {}
        global_by_type = {}
        
        for target, results in self.results.items():
            summary = results.get('summary', {})
            
            total_vulnerabilities += summary.get('total_vulnerabilities', 0)
            total_high_risk += summary.get('high_risk_findings', 0)
            
            # Aggregate severity counts
            for severity, count in summary.get('by_severity', {}).items():
                global_by_severity[severity] = global_by_severity.get(severity, 0) + count
            
            # Aggregate type counts
            for vuln_type, count in summary.get('by_type', {}).items():
                global_by_type[vuln_type] = global_by_type.get(vuln_type, 0) + count
        
        # Store global summary
        self.results['global_summary'] = {
            'total_targets': len([t for t in self.results.keys() if t != 'global_summary']),
            'total_vulnerabilities': total_vulnerabilities,
            'total_high_risk_findings': total_high_risk,
            'by_severity': global_by_severity,
            'by_type': global_by_type,
            'scan_time': datetime.now().isoformat()
        }
    
    async def shutdown(self):
        """Shutdown scanner gracefully"""
        
        print(f"{Colors.YELLOW}[*] Shutting down scanner...{Colors.RESET}")
        await self.task_engine.shutdown(graceful=True)
        print(f"{Colors.GREEN}[+] Scanner shutdown complete{Colors.RESET}")
