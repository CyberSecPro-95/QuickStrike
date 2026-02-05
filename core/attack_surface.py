"""
Attack Surface Graph - JSON-based endpoint relationship and vulnerability mapping
"""

import json
import hashlib
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime

from core.curl_engine import CurlResponse
from core.endpoint_classifier import EndpointAnalysis, EndpointSensitivity
from core.utils import Colors


class NodeType(Enum):
    """Node types in attack surface graph"""
    ENDPOINT = "endpoint"
    VULNERABILITY = "vulnerability"
    PARAMETER = "parameter"
    DATA_FLOW = "data_flow"


class EdgeType(Enum):
    """Edge types in attack surface graph"""
    CONTAINS = "contains"
    DEPENDS_ON = "depends_on"
    VULNERABLE_TO = "vulnerable_to"
    EXPOSES = "exposes"
    AUTHENTICATES = "authenticates"


@dataclass
class GraphNode:
    """Node in attack surface graph"""
    id: str
    type: NodeType
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Edge in attack surface graph"""
    source: str
    target: str
    type: EdgeType
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSurfaceGraph:
    """Complete attack surface graph structure"""
    target: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    attack_paths: List[List[str]] = field(default_factory=list)
    critical_assets: List[str] = field(default_factory=list)


class AttackSurfaceMapper:
    """Maps attack surface from discovered endpoints and vulnerabilities"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        
        # Endpoint relationship patterns
        self.relationship_patterns = {
            'authentication': [
                r'/auth', r'/login', r'/token', r'/oauth', r'/signin'
            ],
            'user_data': [
                r'/user', r'/profile', r'/account', r'/settings'
            ],
            'admin_functions': [
                r'/admin', r'/manage', r'/control', r'/system'
            ],
            'api_resources': [
                r'/api/v\d+/[^/]+/[^/]+',  # /api/v1/users/123
                r'/rest/[^/]+/[^/]+',       # /rest/users/123
            ]
        }
        
        # Critical asset patterns
        self.critical_patterns = {
            'admin_panel': [r'/admin', r'/manage', r'/dashboard'],
            'user_data': [r'/users/\d+', r'/profile', r'/account'],
            'payment': [r'/payment', r'/billing', r'/subscription'],
            'config': [r'/config', r'/settings', r'/system'],
            'database': [r'/db', r'/database', r'/backup']
        }
    
    def create_attack_surface_graph(self, target: str, 
                                  endpoints: List[Any], 
                                  vulnerabilities: List[Dict[str, Any]]) -> AttackSurfaceGraph:
        """Create complete attack surface graph"""
        
        graph = AttackSurfaceGraph(
            target=target,
            metadata={
                'created_at': self._get_timestamp(),
                'total_endpoints': len(endpoints),
                'total_vulnerabilities': len(vulnerabilities),
                'scan_mode': 'enhanced'
            }
        )
        
        # Create endpoint nodes
        endpoint_nodes = self._create_endpoint_nodes(endpoints)
        graph.nodes.extend(endpoint_nodes)
        
        # Create vulnerability nodes
        vulnerability_nodes = self._create_vulnerability_nodes(vulnerabilities)
        graph.nodes.extend(vulnerability_nodes)
        
        # Create parameter nodes
        parameter_nodes = self._create_parameter_nodes(endpoints)
        graph.nodes.extend(parameter_nodes)
        
        # Create relationships
        self._create_endpoint_relationships(graph, endpoint_nodes)
        self._create_vulnerability_relationships(graph, endpoint_nodes, vulnerability_nodes)
        self._create_parameter_relationships(graph, endpoint_nodes, parameter_nodes)
        
        # Identify critical assets
        graph.critical_assets = self._identify_critical_assets(endpoint_nodes)
        
        # Generate attack paths
        graph.attack_paths = self._generate_attack_paths(graph)
        
        if self.debug:
            self._debug_graph_creation(graph)
        
        return graph
    
    def _create_endpoint_nodes(self, endpoints: List[Any]) -> List[GraphNode]:
        """Create nodes for endpoints"""
        
        nodes = []
        
        for endpoint in endpoints:
            # Generate unique ID
            node_id = self._generate_node_id('endpoint', endpoint.url)
            
            # Extract properties
            properties = {
                'url': endpoint.url,
                'method': getattr(endpoint, 'method', 'GET'),
                'status_code': getattr(endpoint, 'status_code', 200),
                'content_type': getattr(endpoint, 'content_type', ''),
                'confidence_score': getattr(endpoint, 'confidence_score', 0.0),
                'sensitivity': getattr(endpoint.analysis, 'sensitivity', EndpointSensitivity.PUBLIC_INFO).value if hasattr(endpoint, 'analysis') else 'unknown'
            }
            
            # Create label
            label = self._create_endpoint_label(endpoint)
            
            # Create node
            node = GraphNode(
                id=node_id,
                type=NodeType.ENDPOINT,
                label=label,
                properties=properties,
                metadata={
                    'discovered_at': getattr(endpoint, 'discovery_time', None),
                    'stability_verified': getattr(endpoint, 'stability_verified', False),
                    'functional_indicators': getattr(endpoint.analysis, 'functional_indicators', []) if hasattr(endpoint, 'analysis') else []
                }
            )
            
            nodes.append(node)
        
        return nodes
    
    def _create_vulnerability_nodes(self, vulnerabilities: List[Dict[str, Any]]) -> List[GraphNode]:
        """Create nodes for vulnerabilities"""
        
        nodes = []
        
        for vuln in vulnerabilities:
            # Generate unique ID
            vuln_id = self._generate_node_id('vulnerability', vuln.get('url', '') + vuln.get('type', ''))
            
            # Extract properties
            properties = {
                'type': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'Medium'),
                'url': vuln.get('url', ''),
                'description': vuln.get('description', ''),
                'parameter': vuln.get('parameter', ''),
                'confidence_score': vuln.get('confidence_score', 0.0)
            }
            
            # Create label
            label = f"{properties['severity']}: {properties['type']}"
            
            # Create node
            node = GraphNode(
                id=vuln_id,
                type=NodeType.VULNERABILITY,
                label=label,
                properties=properties,
                metadata={
                    'module': vuln.get('module', 'unknown'),
                    'exploitable': properties['severity'] in ['Critical', 'High']
                }
            )
            
            nodes.append(node)
        
        return nodes
    
    def _create_parameter_nodes(self, endpoints: List[Any]) -> List[GraphNode]:
        """Create nodes for parameters"""
        
        nodes = []
        seen_params = set()
        
        for endpoint in endpoints:
            # Extract parameters from URL
            params = self._extract_parameters(endpoint.url)
            
            # Extract parameters from analysis
            if hasattr(endpoint, 'parameters'):
                params.extend(endpoint.parameters)
            
            for param in params:
                if param not in seen_params:
                    # Generate unique ID
                    param_id = self._generate_node_id('parameter', param)
                    
                    # Create node
                    node = GraphNode(
                        id=param_id,
                        type=NodeType.PARAMETER,
                        label=f"Param: {param}",
                        properties={
                            'name': param,
                            'type': self._classify_parameter(param)
                        },
                        metadata={
                            'sensitive': self._is_sensitive_parameter(param)
                        }
                    )
                    
                    nodes.append(node)
                    seen_params.add(param)
        
        return nodes
    
    def _create_endpoint_relationships(self, graph: AttackSurfaceGraph, endpoint_nodes: List[GraphNode]):
        """Create relationships between endpoints"""
        
        for i, node1 in enumerate(endpoint_nodes):
            for j, node2 in enumerate(endpoint_nodes):
                if i >= j:  # Avoid duplicates
                    continue
                
                relationship = self._analyze_endpoint_relationship(
                    node1.properties['url'], 
                    node2.properties['url']
                )
                
                if relationship:
                    edge = GraphEdge(
                        source=node1.id,
                        target=node2.id,
                        type=EdgeType.DEPENDS_ON,
                        weight=relationship['weight'],
                        properties=relationship
                    )
                    graph.edges.append(edge)
    
    def _create_vulnerability_relationships(self, graph: AttackSurfaceGraph, 
                                           endpoint_nodes: List[GraphNode], 
                                           vulnerability_nodes: List[GraphNode]):
        """Create relationships between endpoints and vulnerabilities"""
        
        for vuln_node in vulnerability_nodes:
            vuln_url = vuln_node.properties['url']
            
            # Find associated endpoint
            for endpoint_node in endpoint_nodes:
                if endpoint_node.properties['url'] == vuln_url:
                    edge = GraphEdge(
                        source=endpoint_node.id,
                        target=vuln_node.id,
                        type=EdgeType.VULNERABLE_TO,
                        weight=self._calculate_vulnerability_weight(vuln_node.properties),
                        properties={
                            'severity': vuln_node.properties['severity'],
                            'exploitable': vuln_node.metadata['exploitable']
                        }
                    )
                    graph.edges.append(edge)
                    break
    
    def _create_parameter_relationships(self, graph: AttackSurfaceGraph, 
                                       endpoint_nodes: List[GraphNode], 
                                       parameter_nodes: List[GraphNode]):
        """Create relationships between endpoints and parameters"""
        
        for endpoint_node in endpoint_nodes:
            endpoint_url = endpoint_node.properties['url']
            params = self._extract_parameters(endpoint_url)
            
            for param in params:
                for param_node in parameter_nodes:
                    if param_node.properties['name'] == param:
                        edge = GraphEdge(
                            source=endpoint_node.id,
                            target=param_node.id,
                            type=EdgeType.CONTAINS,
                            weight=1.0,
                            properties={
                                'parameter_type': param_node.properties['type'],
                                'sensitive': param_node.metadata['sensitive']
                            }
                        )
                        graph.edges.append(edge)
    
    def _analyze_endpoint_relationship(self, url1: str, url2: str) -> Optional[Dict[str, Any]]:
        """Analyze relationship between two endpoints"""
        
        # Check for authentication flow
        if self._is_auth_flow(url1, url2):
            return {'type': 'auth_flow', 'weight': 0.8}
        
        # Check for data flow
        if self._is_data_flow(url1, url2):
            return {'type': 'data_flow', 'weight': 0.6}
        
        # Check for API hierarchy
        if self._is_api_hierarchy(url1, url2):
            return {'type': 'api_hierarchy', 'weight': 0.4}
        
        return None
    
    def _is_auth_flow(self, url1: str, url2: str) -> bool:
        """Check if endpoints form authentication flow"""
        
        auth_patterns = self.relationship_patterns['authentication']
        user_patterns = self.relationship_patterns['user_data']
        
        # One endpoint is auth, other is user data
        url1_auth = any(re.search(pattern, url1, re.IGNORECASE) for pattern in auth_patterns)
        url2_auth = any(re.search(pattern, url2, re.IGNORECASE) for pattern in auth_patterns)
        
        url1_user = any(re.search(pattern, url1, re.IGNORECASE) for pattern in user_patterns)
        url2_user = any(re.search(pattern, url2, re.IGNORECASE) for pattern in user_patterns)
        
        return (url1_auth and url2_user) or (url2_auth and url1_user)
    
    def _is_data_flow(self, url1: str, url2: str) -> bool:
        """Check if endpoints have data flow relationship"""
        
        # Check for resource hierarchy
        # e.g., /api/users and /api/users/123
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        
        path1 = parsed1.path.rstrip('/')
        path2 = parsed2.path.rstrip('/')
        
        # One path is prefix of other
        if path1.startswith(path2) or path2.startswith(path1):
            return True
        
        return False
    
    def _is_api_hierarchy(self, url1: str, url2: str) -> bool:
        """Check if endpoints are in same API hierarchy"""
        
        api_patterns = self.relationship_patterns['api_resources']
        
        for pattern in api_patterns:
            if re.search(pattern, url1, re.IGNORECASE) and re.search(pattern, url2, re.IGNORECASE):
                return True
        
        return False
    
    def _identify_critical_assets(self, endpoint_nodes: List[GraphNode]) -> List[str]:
        """Identify critical assets in the attack surface"""
        
        critical_assets = []
        
        for node in endpoint_nodes:
            url = node.properties['url']
            
            for asset_type, patterns in self.critical_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        critical_assets.append({
                            'node_id': node.id,
                            'asset_type': asset_type,
                            'url': url,
                            'sensitivity': node.properties['sensitivity']
                        })
                        break
        
        return critical_assets
    
    def _generate_attack_paths(self, graph: AttackSurfaceGraph) -> List[List[str]]:
        """Generate potential attack paths"""
        
        attack_paths = []
        
        # Find paths to critical assets
        for asset in graph.critical_assets:
            asset_node_id = asset['node_id']
            
            # Find vulnerabilities that can reach this asset
            for edge in graph.edges:
                if edge.target == asset_node_id and edge.type == EdgeType.VULNERABLE_TO:
                    # Find source endpoint
                    source_node = next((n for n in graph.nodes if n.id == edge.source), None)
                    if source_node and source_node.type == NodeType.ENDPOINT:
                        path = [source_node.properties['url'], asset['url']]
                        attack_paths.append({
                            'path': path,
                            'asset_type': asset['asset_type'],
                            'vulnerability': edge.properties.get('severity', 'Unknown'),
                            'weight': edge.weight
                        })
        
        return attack_paths
    
    def _generate_node_id(self, node_type: str, identifier: str) -> str:
        """Generate unique node ID"""
        
        hash_input = f"{node_type}:{identifier}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]
    
    def _create_endpoint_label(self, endpoint: Any) -> str:
        """Create label for endpoint node"""
        
        url = endpoint.url
        method = getattr(endpoint, 'method', 'GET')
        sensitivity = getattr(endpoint.analysis, 'sensitivity', EndpointSensitivity.PUBLIC_INFO).value if hasattr(endpoint, 'analysis') else 'unknown'
        
        # Extract path from URL
        parsed = urlparse(url)
        path = parsed.path
        
        # Create concise label
        return f"{method} {path} ({sensitivity})"
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        
        parsed = urlparse(url)
        params = []
        
        # Query parameters
        if parsed.query:
            query_params = parse_qs(parsed.query)
            params.extend(query_params.keys())
        
        # Path parameters (simple detection)
        path_parts = parsed.path.split('/')
        for part in path_parts:
            if part.isdigit() or (len(part) == 36 and '-' in part):  # UUID
                # This might be a parameter value
                idx = path_parts.index(part)
                if idx > 0:
                    param_name = path_parts[idx - 1]
                    params.append(param_name)
        
        return list(set(params))
    
    def _classify_parameter(self, param: str) -> str:
        """Classify parameter type"""
        
        param_lower = param.lower()
        
        if param_lower in ['id', 'user_id', 'userid', 'uid']:
            return 'identifier'
        elif param_lower in ['token', 'access_token', 'auth_token']:
            return 'authentication'
        elif param_lower in ['email', 'username', 'password']:
            return 'credential'
        elif param_lower in ['page', 'limit', 'offset']:
            return 'pagination'
        else:
            return 'general'
    
    def _is_sensitive_parameter(self, param: str) -> bool:
        """Check if parameter is sensitive"""
        
        sensitive_params = [
            'id', 'user_id', 'token', 'password', 'email',
            'admin', 'role', 'permission', 'key', 'secret'
        ]
        
        return param.lower() in sensitive_params
    
    def _calculate_vulnerability_weight(self, vuln_properties: Dict[str, Any]) -> float:
        """Calculate weight for vulnerability edge"""
        
        severity_weights = {
            'Critical': 1.0,
            'High': 0.8,
            'Medium': 0.5,
            'Low': 0.3,
            'Info': 0.1
        }
        
        severity = vuln_properties.get('severity', 'Medium')
        return severity_weights.get(severity, 0.5)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _debug_graph_creation(self, graph: AttackSurfaceGraph):
        """Debug graph creation process"""
        
        print(f"{Colors.CYAN}[DEBUG] Attack Surface Graph Created:{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Nodes: {len(graph.nodes)}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Edges: {len(graph.edges)}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Critical Assets: {len(graph.critical_assets)}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG]   Attack Paths: {len(graph.attack_paths)}{Colors.RESET}")
    
    def export_to_json(self, graph: AttackSurfaceGraph) -> Dict[str, Any]:
        """Export graph to JSON structure"""
        
        return {
            'target': graph.target,
            'metadata': graph.metadata,
            'nodes': [
                {
                    'id': node.id,
                    'type': node.type.value,
                    'label': node.label,
                    'properties': node.properties,
                    'metadata': node.metadata
                }
                for node in graph.nodes
            ],
            'edges': [
                {
                    'source': edge.source,
                    'target': edge.target,
                    'type': edge.type.value,
                    'weight': edge.weight,
                    'properties': edge.properties
                }
                for edge in graph.edges
            ],
            'critical_assets': graph.critical_assets,
            'attack_paths': graph.attack_paths,
            'statistics': self._calculate_graph_statistics(graph)
        }
    
    def _calculate_graph_statistics(self, graph: AttackSurfaceGraph) -> Dict[str, Any]:
        """Calculate graph statistics"""
        
        endpoint_nodes = [n for n in graph.nodes if n.type == NodeType.ENDPOINT]
        vulnerability_nodes = [n for n in graph.nodes if n.type == NodeType.VULNERABILITY]
        
        severity_counts = {}
        for vuln_node in vulnerability_nodes:
            severity = vuln_node.properties['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_nodes': len(graph.nodes),
            'total_edges': len(graph.edges),
            'endpoint_nodes': len(endpoint_nodes),
            'vulnerability_nodes': len(vulnerability_nodes),
            'parameter_nodes': len([n for n in graph.nodes if n.type == NodeType.PARAMETER]),
            'severity_distribution': severity_counts,
            'critical_vulnerabilities': severity_counts.get('Critical', 0),
            'high_vulnerabilities': severity_counts.get('High', 0),
            'attack_surface_score': self._calculate_attack_surface_score(graph)
        }
    
    def _calculate_attack_surface_score(self, graph: AttackSurfaceGraph) -> float:
        """Calculate overall attack surface score"""
        
        score = 0.0
        
        # Base score from number of endpoints
        endpoint_nodes = [n for n in graph.nodes if n.type == NodeType.ENDPOINT]
        score += len(endpoint_nodes) * 0.1
        
        # Add vulnerability scores
        vulnerability_nodes = [n for n in graph.nodes if n.type == NodeType.VULNERABILITY]
        for vuln in vulnerability_nodes:
            severity = vuln.properties['severity']
            if severity == 'Critical':
                score += 2.0
            elif severity == 'High':
                score += 1.5
            elif severity == 'Medium':
                score += 1.0
            elif severity == 'Low':
                score += 0.5
        
        # Add critical asset multiplier
        score *= (1 + len(graph.critical_assets) * 0.2)
        
        return round(score, 2)
