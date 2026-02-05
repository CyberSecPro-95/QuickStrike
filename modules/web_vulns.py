"""
Classic Web Vulnerabilities Scanner
Detects traditional web vulnerabilities like SQLi, XSS, etc.
"""

import re
import html
import urllib.parse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from core.curl_engine import CurlEngine, CurlResponse


@dataclass
class WebVulnerability:
    """Classic web vulnerability finding"""
    vuln_type: str
    severity: str
    url: str
    parameter: str
    payload: str
    evidence: str
    description: str


class WebVulnsScanner:
    """Classic web vulnerabilities scanner"""
    
    def __init__(self, curl_engine: CurlEngine):
        self.curl = curl_engine
        
        # SQL Error patterns
        self.sql_error_patterns = [
            r"mysql_fetch_array\(\)",
            r"mysql_fetch_assoc\(\)",
            r"mysql_num_rows\(\)",
            r"You have an error in your SQL syntax",
            r"MySQL server error",
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"org\.gjt\.mm\.mysql",
            r"mysql.*driver",
            r"mysql.*exception",
            r"PostgreSQL query failed",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"PostgreSQL.*ERROR",
            r"pg_.*error",
            r"PG::SyntaxError",
            r"org\.postgresql",
            r"psql\.exception",
            r"SQLServer JDBC Driver",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"SQLSTATE",
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
            r"SQLite\.JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]"
        ]
        
        # XSS detection patterns
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "';alert(1);//",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)"
        ]
        
        # Common parameter names for testing
        self.test_params = ['id', 'cat', 'page', 'user', 'search', 'q', 'action', 'view', 'type', 'item']
    
    async def scan_target(self, target_url: str) -> List[WebVulnerability]:
        """Scan target for classic web vulnerabilities"""
        findings = []
        
        # Try both HTTP and HTTPS
        urls_to_test = [target_url]
        if target_url.startswith('https://'):
            urls_to_test.append(target_url.replace('https://', 'http://'))
        elif not target_url.startswith('http://'):
            urls_to_test.append(f'http://{target_url}')
            urls_to_test.append(f'https://{target_url}')
        
        for test_url in urls_to_test:
            print(f"[*] Scanning for classic web vulnerabilities on: {test_url}")
            
            # First, get the homepage to find parameters
            homepage_response = await self.curl.get(test_url)
            
            print(f"[*] Homepage response: {homepage_response.status_code} ({homepage_response.content_length} bytes)")
            
            if homepage_response.status_code not in [200, 301, 302]:
                print(f"[-] Could not access homepage: {homepage_response.status_code}")
                if homepage_response.error:
                    print(f"[-] Error: {homepage_response.error}")
                continue  # Try next URL
            
            # Find parameters in HTML content
            parameters = self._extract_parameters(homepage_response.body, homepage_response.url)
            
            if not parameters:
                print(f"[-] No parameters found for testing")
                # Try some common parameters anyway
                parameters = [{'name': param, 'url': test_url} for param in ['id', 'page', 'cat', 'user']]
            
            print(f"[*] Found {len(parameters)} parameters to test")
            
            # Test each parameter for SQLi
            for param_info in parameters:
                param_name = param_info['name']
                base_url = param_info['url']
                
                # Test SQLi
                sqli_findings = await self._test_sqli(base_url, param_name)
                findings.extend(sqli_findings)
                
                # Test XSS
                xss_findings = await self._test_xss(base_url, param_name)
                findings.extend(xss_findings)
            
            # If we found vulnerabilities, return them
            if findings:
                print(f"[+] Found {len(findings)} classic web vulnerabilities")
                return findings
        
        print(f"[+] No classic web vulnerabilities found on any URL")
        return findings
    
    def _extract_parameters(self, html_content: str, base_url: str) -> List[Dict[str, str]]:
        """Extract parameters from HTML content"""
        parameters = []
        
        # Find form inputs
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for action, form_content in forms:
            # Extract input names
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\']'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_name in inputs:
                if input_name.lower() in self.test_params:
                    form_url = urllib.parse.urljoin(base_url, action)
                    parameters.append({'name': input_name, 'url': form_url})
        
        # Find links with parameters
        link_pattern = r'<a[^>]*href=["\']([^"\']*\?[^"\']*)["\']'
        links = re.findall(link_pattern, html_content, re.IGNORECASE)
        
        for link in links:
            full_url = urllib.parse.urljoin(base_url, link)
            parsed = urllib.parse.urlparse(full_url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            for param_name in query_params:
                if param_name.lower() in self.test_params:
                    parameters.append({'name': param_name, 'url': full_url})
        
        # Remove duplicates
        unique_params = []
        seen = set()
        for param in parameters:
            key = (param['name'], param['url'])
            if key not in seen:
                seen.add(key)
                unique_params.append(param)
        
        return unique_params
    
    async def _test_sqli(self, base_url: str, param_name: str) -> List[WebVulnerability]:
        """Test parameter for SQL injection"""
        findings = []
        
        # SQLi payloads
        sqli_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR 1=1 --",
            "' UNION SELECT NULL --",
            "' AND 1=CONVERT(int, (SELECT @@version)) --"
        ]
        
        for payload in sqli_payloads:
            try:
                # Inject payload
                test_url = self._inject_payload(base_url, param_name, payload)
                response = await self.curl.get(test_url)
                
                # Check for SQL errors
                if response.status_code == 200:
                    for pattern in self.sql_error_patterns:
                        if re.search(pattern, response.body, re.IGNORECASE):
                            finding = WebVulnerability(
                                vuln_type="SQL Injection",
                                severity="High",
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                evidence=self._extract_error_snippet(response.body, pattern),
                                description=f"SQL injection vulnerability detected in parameter '{param_name}'"
                            )
                            findings.append(finding)
                            print(f"[+] SQLi found: {param_name} -> {payload[:20]}...")
                            break  # Found SQLi, no need to check other patterns
                            
            except Exception as e:
                print(f"[-] Error testing SQLi on {param_name}: {e}")
        
        return findings
    
    async def _test_xss(self, base_url: str, param_name: str) -> List[WebVulnerability]:
        """Test parameter for XSS"""
        findings = []
        
        for payload in self.xss_payloads:
            try:
                # Inject payload
                test_url = self._inject_payload(base_url, param_name, payload)
                response = await self.curl.get(test_url)
                
                # Check if payload is reflected unescaped
                if response.status_code == 200:
                    # Check for exact payload match
                    if payload in response.body:
                        # Additional check: ensure it's not in a quoted/escaped context
                        if self._is_xss_executable(response.body, payload):
                            finding = WebVulnerability(
                                vuln_type="Cross-Site Scripting (XSS)",
                                severity="High",
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                evidence=self._extract_xss_snippet(response.body, payload),
                                description=f"XSS vulnerability detected in parameter '{param_name}' - payload reflected unescaped"
                            )
                            findings.append(finding)
                            print(f"[+] XSS found: {param_name} -> {payload[:30]}...")
                            
            except Exception as e:
                print(f"[-] Error testing XSS on {param_name}: {e}")
        
        return findings
    
    def _inject_payload(self, base_url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(base_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Add/replace parameter with payload
        query_params[param_name] = [payload]
        
        # Rebuild URL
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url
    
    def _extract_error_snippet(self, body: str, pattern: str) -> str:
        """Extract error snippet from response body"""
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(body), match.end() + 50)
            return body[start:end].strip()
        return "Error pattern matched"
    
    def _extract_xss_snippet(self, body: str, payload: str) -> str:
        """Extract XSS snippet from response body"""
        index = body.find(payload)
        if index != -1:
            start = max(0, index - 30)
            end = min(len(body), index + len(payload) + 30)
            return body[start:end].strip()
        return "Payload reflected in response"
    
    def _is_xss_executable(self, body: str, payload: str) -> bool:
        """Check if XSS payload is in executable context"""
        index = body.find(payload)
        if index == -1:
            return False
        
        # Get context around payload
        start = max(0, index - 100)
        end = min(len(body), index + len(payload) + 100)
        context = body[start:end]
        
        # Check if payload is escaped
        escaped_patterns = [
            r"&lt;",
            r"&gt;",
            r"&amp;",
            r"&quot;",
            r"&#x",
            r"\\&lt;",
            r"\\&gt;",
            r"\\&amp;",
            r"\\&quot;"
        ]
        
        for pattern in escaped_patterns:
            if re.search(pattern, context):
                return False
        
        # Check if payload is in quotes (basic check)
        if payload in context:
            # Look for the payload and check surrounding characters
            payload_index = context.find(payload)
            before = context[:payload_index]
            after = context[payload_index + len(payload):]
            
            # If surrounded by quotes without proper escaping, it might be executable
            if not (before.endswith('"') or before.endswith("'") or 
                   after.startswith('"') or after.startswith("'")):
                return True
        
        return True
