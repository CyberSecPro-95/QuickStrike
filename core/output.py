"""
Output Engine - Rich formatting, exports, and report generation
"""

import os
import json
import time
import html
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Try to import rich for enhanced console output
try:
    from rich.console import Console
    from rich.style import Style
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None
    Style = None

from core.utils import Colors, FileHelper, ProgressTracker


def show_startup_banner(silent: bool = False):
    """Display professional startup banner"""
    if silent:
        return
    
    # Initialize rich console if available, otherwise use basic print
    if RICH_AVAILABLE:
        console = Console()
        
        # Read banner from assets directory
        banner_path = Path(__file__).parent.parent / "assets" / "banner.txt"
        
        if banner_path.exists():
            with open(banner_path, 'r', encoding='utf-8') as f:
                banner_content = f.read().strip()
            
            # Display banner in bold blue
            banner_style = Style(color="blue", bold=True)
            console.print(banner_content, style=banner_style)
            
            # Display sub-header with different colors
            version_style = Style(color="cyan", bold=True)
            desc_style = Style(color="bright_black")  # Use bright_black instead of dim
            
            console.print()
            console.print("     QUICKSTRIKE ", end="", style=version_style)
            console.print("v2.0.0", end="", style=version_style)
            console.print(" | ", end="", style=desc_style)
            console.print("Offensive Recon Framework", style=desc_style)
            console.print()
        else:
            # Fallback if banner file not found
            console.print("[bold blue]QUICKSTRIKE v2.0.0[/bold blue] | [bright_black]Offensive Recon Framework[/bright_black]")
    else:
        # Fallback without rich
        print(f"{Colors.BOLD}{Colors.BLUE}QUICKSTRIKE v2.0.0{Colors.RESET} | {Colors.DIM}Offensive Recon Framework{Colors.RESET}")


class OutputEngine:
    """Professional output engine with multiple format support"""
    
    def __init__(self, args):
        self.args = args
        self.results_dir = "results"
        self.start_time = time.time()
        
        # Ensure results directory exists
        FileHelper.ensure_directory(self.results_dir)
    
    async def generate_results(self, results: Dict[str, Any]):
        """Generate output in specified format"""
        
        print(f"{Colors.GREEN}[+] Generating results...{Colors.RESET}")
        
        # Generate console output
        if not self.args.silent:
            self._print_console_results(results)
        
        # Generate file output
        if self.args.json or self.args.markdown:
            await self._generate_file_output(results)
        
        # Generate per-domain folders with PoC files
        await self._generate_domain_reports(results)
        
        # Print summary
        self._print_final_summary(results)
    
    def _print_console_results(self, results: Dict[str, Any]):
        """Print results to console with rich formatting"""
        
        print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}║                              QUICKSTRIKE RESULTS                              ║{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
        
        # Global summary
        global_summary = results.get('global_summary', {})
        if global_summary:
            self._print_global_summary(global_summary)
        
        # Per-target results
        for target, target_data in results.items():
            if target == 'global_summary':
                continue
            
            self._print_target_results(target, target_data)
    
    def _print_global_summary(self, summary: Dict[str, Any]):
        """Print global summary"""
        
        print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}📊 GLOBAL SUMMARY{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Targets Scanned: {Colors.YELLOW}{summary.get('total_targets', 0)}{Colors.RESET}")
        print(f"Total Vulnerabilities: {Colors.YELLOW}{summary.get('total_vulnerabilities', 0)}{Colors.RESET}")
        print(f"High-Risk Findings: {Colors.RED}{summary.get('total_high_risk_findings', 0)}{Colors.RESET}")
        
        # Severity breakdown
        by_severity = summary.get('by_severity', {})
        if by_severity:
            print(f"\n{Colors.BRIGHT_YELLOW}Severity Breakdown:{Colors.RESET}")
            
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = by_severity.get(severity, 0)
                if count > 0:
                    color = self._get_severity_color(severity)
                    print(f"  {color}{severity}: {count}{Colors.RESET}")
        
        # Type breakdown
        by_type = summary.get('by_type', {})
        if by_type:
            print(f"\n{Colors.BRIGHT_YELLOW}Vulnerability Types:{Colors.RESET}")
            for vuln_type, count in by_type.items():
                print(f"  {Colors.CYAN}{vuln_type}: {count}{Colors.RESET}")
        
        print()
    
    def _print_target_results(self, target: str, target_data: Dict[str, Any]):
        """Print results for specific target"""
        
        print(f"{Colors.BRIGHT_MAGENTA}{Colors.BOLD}🎯 TARGET: {target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
        
        # Target summary
        summary = target_data.get('summary', {})
        total_vulns = summary.get('total_vulnerabilities', 0)
        high_risk = summary.get('high_risk_findings', 0)
        
        print(f"Vulnerabilities Found: {Colors.YELLOW}{total_vulns}{Colors.RESET}")
        print(f"High-Risk Findings: {Colors.RED}{high_risk}{Colors.RESET}")
        
        # Module results
        modules = target_data.get('modules', {})
        for module_name, module_data in modules.items():
            if 'error' in module_data:
                print(f"\n{Colors.RED}[!] {module_name.replace('_', ' ').title()}: Error - {module_data['error']}{Colors.RESET}")
            else:
                findings_count = module_data.get('findings_count', 0)
                if findings_count > 0:
                    print(f"\n{Colors.GREEN}[+] {module_name.replace('_', ' ').title()}: {findings_count} findings{Colors.RESET}")
        
        # Detailed vulnerabilities
        vulnerabilities = target_data.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n{Colors.BRIGHT_YELLOW}🔍 DETAILED FINDINGS:{Colors.RESET}")
            
            for i, vuln in enumerate(vulnerabilities[:10], 1):  # Limit to 10 for console
                severity = vuln.get('severity', 'Medium')
                color = self._get_severity_color(severity)
                
                print(f"\n{color}[{i}] {severity.upper()}: {vuln.get('type', 'Unknown')}{Colors.RESET}")
                print(f"    {Colors.CYAN}URL: {Colors.RESET}{html.escape(vuln.get('url', 'N/A'))}")
                print(f"    {Colors.CYAN}Description: {Colors.RESET}{html.escape(vuln.get('description', 'N/A'))}")
                
                if vuln.get('parameter'):
                    print(f"    {Colors.CYAN}Parameter: {Colors.RESET}{html.escape(vuln['parameter'])}")
                
                if vuln.get('token_type'):
                    print(f"    {Colors.CYAN}Token Type: {Colors.RESET}{vuln['token_type']}")
            
            if len(vulnerabilities) > 10:
                print(f"\n{Colors.DIM}... and {len(vulnerabilities) - 10} more findings (see full report){Colors.RESET}")
        
        print(f"\n{Colors.CYAN}{'-'*80}{Colors.RESET}\n")
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        
        colors = {
            'Critical': Colors.BRIGHT_RED,
            'High': Colors.RED,
            'Medium': Colors.YELLOW,
            'Low': Colors.BLUE,
            'Info': Colors.CYAN
        }
        
        return colors.get(severity, Colors.WHITE)
    
    async def _generate_file_output(self, results: Dict[str, Any]):
        """Generate file output in specified format"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if self.args.json:
            json_file = f"{self.results_dir}/quickstrike_results_{timestamp}.json"
            await self._generate_json_output(results, json_file)
            print(f"{Colors.GREEN}[+] JSON report saved: {json_file}{Colors.RESET}")
        
        if self.args.markdown:
            md_file = f"{self.results_dir}/quickstrike_results_{timestamp}.md"
            await self._generate_markdown_output(results, md_file)
            print(f"{Colors.GREEN}[+] Markdown report saved: {md_file}{Colors.RESET}")
    
    async def _generate_json_output(self, results: Dict[str, Any], filepath: str):
        """Generate JSON output"""
        
        # Prepare JSON data
        json_data = {
            'scan_info': {
                'tool': 'QuickStrike',
                'version': '2.0.0',
                'scan_time': datetime.now().isoformat(),
                'mode': self.args.mode,
                'duration_seconds': time.time() - self.start_time
            },
            'results': results
        }
        
        FileHelper.write_json(json_data, filepath)
    
    async def _generate_markdown_output(self, results: Dict[str, Any], filepath: str):
        """Generate Markdown output"""
        
        md_content = self._generate_markdown_content(results)
        FileHelper.write_text(md_content, filepath)
    
    def _generate_markdown_content(self, results: Dict[str, Any]) -> str:
        """Generate markdown content"""
        
        md = []
        
        # Header
        md.append("# QuickStrike Security Assessment Report")
        md.append("")
        md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Mode:** {self.args.mode.upper()}")
        md.append(f"**Duration:** {time.time() - self.start_time:.1f} seconds")
        md.append("")
        
        # Executive Summary
        global_summary = results.get('global_summary', {})
        if global_summary:
            md.append("## 📊 Executive Summary")
            md.append("")
            md.append(f"- **Targets Scanned:** {global_summary.get('total_targets', 0)}")
            md.append(f"- **Total Vulnerabilities:** {global_summary.get('total_vulnerabilities', 0)}")
            md.append(f"- **Critical/High Risk:** {global_summary.get('total_high_risk_findings', 0)}")
            md.append("")
            
            # Severity table
            by_severity = global_summary.get('by_severity', {})
            if by_severity:
                md.append("### Severity Distribution")
                md.append("")
                md.append("| Severity | Count |")
                md.append("|----------|-------|")
                
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = by_severity.get(severity, 0)
                    emoji = self._get_severity_emoji(severity)
                    md.append(f"| {emoji} {severity} | {count} |")
                md.append("")
        
        # Detailed findings
        md.append("## 🔍 Detailed Findings")
        md.append("")
        
        for target, target_data in results.items():
            if target == 'global_summary':
                continue
            
            md.append(f"### 🎯 {target}")
            md.append("")
            
            vulnerabilities = target_data.get('vulnerabilities', [])
            if vulnerabilities:
                for i, vuln in enumerate(vulnerabilities, 1):
                    severity = vuln.get('severity', 'Medium')
                    emoji = self._get_severity_emoji(severity)
                    
                    md.append(f"#### {i}. {emoji} {severity.upper()}: {vuln.get('type', 'Unknown')}")
                    md.append("")
                    md.append(f"**URL:** `{html.escape(vuln.get('url', 'N/A'))}`")
                    md.append("")
                    md.append(f"**Description:** {html.escape(vuln.get('description', 'N/A'))}")
                    md.append("")
                    
                    if vuln.get('parameter'):
                        md.append(f"**Parameter:** `{html.escape(vuln['parameter'])}`")
                        md.append("")
                    
                    if vuln.get('token_type'):
                        md.append(f"**Token Type:** `{html.escape(vuln['token_type'])}`")
                        md.append("")
                    
                    # Add PoC if available
                    poc = self._generate_poc_command(vuln)
                    if poc:
                        md.append("**Proof of Concept:**")
                        md.append("```bash")
                        md.append(poc)
                        md.append("```")
                        md.append("")
                    
                    md.append("---")
                    md.append("")
            else:
                md.append("*No vulnerabilities found*")
                md.append("")
        
        # Recommendations
        md.append("## 🛡️ Recommendations")
        md.append("")
        md.append("### Immediate Actions (Critical/High)")
        md.append("")
        md.append("1. **Rotate Exposed Credentials** - Immediately change any exposed API keys, tokens, or credentials")
        md.append("2. **Implement Authentication** - Add proper authentication to unauthenticated endpoints")
        md.append("3. **Fix IDOR Issues** - Implement proper authorization checks for object access")
        md.append("4. **Remove Sensitive Files** - Delete or secure exposed configuration files")
        md.append("")
        
        md.append("### Long-term Improvements")
        md.append("")
        md.append("1. **API Security Testing** - Implement regular API security testing in CI/CD")
        md.append("2. **Secret Management** - Use proper secret management solutions")
        md.append("3. **Access Controls** - Implement principle of least privilege")
        md.append("4. **Monitoring** - Add logging and monitoring for sensitive data access")
        md.append("")
        
        # Footer
        md.append("---")
        md.append("")
        md.append("*Report generated by [QuickStrike](https://github.com/CyberSecPro-95/QuickStrike) - Professional Offensive Security Framework by Aryan Akbar Joyia (cybersecpro-95)*")
        
        return "\n".join(md)
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        
        emojis = {
            'Critical': '🚨',
            'High': '⚠️',
            'Medium': '⚡',
            'Low': 'ℹ️',
            'Info': '📝'
        }
        
        return emojis.get(severity, '❓')
    
    def _generate_poc_command(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Generate PoC command for vulnerability with confidence threshold"""
        
        # Check confidence score
        confidence = vulnerability.get('confidence_score', 0.0)
        if confidence < 0.8:
            return None  # Skip low-confidence vulnerabilities
        
        url = vulnerability.get('url', '')
        if not url:
            return None
        
        base_command = f"curl -s '{url}'"
        
        # Add specific parameters based on vulnerability type
        vuln_type = vulnerability.get('type', '').lower()
        
        if 'idor' in vuln_type:
            param = vulnerability.get('parameter', 'id')
            base_command += f"?{param}=1"
        
        elif 'unauthenticated' in vuln_type:
            # Add headers to show no auth needed
            base_command += " -H 'Authorization: Bearer INVALID_TOKEN'"
        
        return base_command
    
    async def _generate_domain_reports(self, results: Dict[str, Any]):
        """Generate per-domain report folders with PoC files"""
        
        for target, target_data in results.items():
            if target == 'global_summary':
                continue
            
            # Create domain folder
            domain_dir = f"{self.results_dir}/{FileHelper.safe_filename(target)}"
            FileHelper.ensure_directory(domain_dir)
            
            # Generate report.md
            await self._generate_domain_report(target, target_data, domain_dir)
            
            # Generate poc.txt
            await self._generate_poc_file(target, target_data, domain_dir)
            
            # Generate raw.json
            await self._generate_raw_data(target, target_data, domain_dir)
    
    async def _generate_domain_report(self, target: str, target_data: Dict[str, Any], domain_dir: str):
        """Generate domain-specific markdown report"""
        
        report_content = f"""# {target} - Security Assessment Report

**Scan Date:** {target_data.get('scan_time', 'N/A')}  
**Mode:** {target_data.get('mode', 'N/A')}  
**Total Vulnerabilities:** {len(target_data.get('vulnerabilities', []))}

## Summary

{self._generate_target_summary_markdown(target_data.get('summary', {}))}

## Findings

{self._generate_findings_markdown(target_data.get('vulnerabilities', []))}

## Module Results

{self._generate_modules_markdown(target_data.get('modules', {}))}

---
*Generated by QuickStrike v2.0.0*
"""
        
        report_file = f"{domain_dir}/report.md"
        FileHelper.write_text(report_content, report_file)
    
    async def _generate_poc_file(self, target: str, target_data: Dict[str, Any], domain_dir: str):
        """Generate PoC commands file"""
        
        poc_commands = []
        vulnerabilities = target_data.get('vulnerabilities', [])
        
        for i, vuln in enumerate(vulnerabilities, 1):
            poc_commands.append(f"# {i}. {vuln.get('severity', 'Medium')} - {vuln.get('type', 'Unknown')}")
            poc_commands.append(f"# {html.escape(vuln.get('description', 'N/A'))}")
            
            poc = self._generate_poc_command(vuln)
            if poc:
                poc_commands.append(poc)
            
            poc_commands.append("")
        
        poc_content = f"""# {target} - Proof of Concept Commands

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Mode: {target_data.get('mode', 'N/A')}

{chr(10).join(poc_commands)}
"""
        
        poc_file = f"{domain_dir}/poc.txt"
        FileHelper.write_text(poc_content, poc_file)
    
    async def _generate_raw_data(self, target: str, target_data: Dict[str, Any], domain_dir: str):
        """Generate raw JSON data"""
        
        raw_file = f"{domain_dir}/raw.json"
        FileHelper.write_json(target_data, raw_file)
    
    def _generate_target_summary_markdown(self, summary: Dict[str, Any]) -> str:
        """Generate target summary in markdown"""
        
        if not summary:
            return "No summary available."
        
        md = []
        md.append(f"- **Total Vulnerabilities:** {summary.get('total_vulnerabilities', 0)}")
        md.append(f"- **High-Risk Findings:** {summary.get('high_risk_findings', 0)}")
        
        by_severity = summary.get('by_severity', {})
        if by_severity:
            md.append("\n**Severity Breakdown:**")
            for severity, count in by_severity.items():
                emoji = self._get_severity_emoji(severity)
                md.append(f"- {emoji} {severity}: {count}")
        
        return "\n".join(md)
    
    def _generate_findings_markdown(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate findings in markdown"""
        
        if not vulnerabilities:
            return "No vulnerabilities found."
        
        md = []
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'Medium')
            emoji = self._get_severity_emoji(severity)
            
            md.append(f"### {i}. {emoji} {severity.upper()}: {vuln.get('type', 'Unknown')}")
            md.append(f"**URL:** `{html.escape(vuln.get('url', 'N/A'))}`")
            md.append(f"**Description:** {html.escape(vuln.get('description', 'N/A'))}")
            
            if vuln.get('parameter'):
                md.append(f"**Parameter:** `{html.escape(vuln['parameter'])}`")
            
            md.append("")
        
        return "\n".join(md)
    
    def _generate_modules_markdown(self, modules: Dict[str, Any]) -> str:
        """Generate module results in markdown"""
        
        if not modules:
            return "No module results available."
        
        md = []
        for module_name, module_data in modules.items():
            md.append(f"### {module_name.replace('_', ' ').title()}")
            
            if 'error' in module_data:
                md.append(f"❌ Error: {module_data['error']}")
            else:
                findings_count = module_data.get('findings_count', 0)
                md.append(f"✅ Findings: {findings_count}")
            
            md.append("")
        
        return "\n".join(md)
    
    def _print_final_summary(self, results: Dict[str, Any]):
        """Print final scan summary"""
        
        global_summary = results.get('global_summary', {})
        total_vulns = global_summary.get('total_vulnerabilities', 0)
        high_risk = global_summary.get('total_high_risk_findings', 0)
        duration = time.time() - self.start_time
        
        print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}🎉 SCAN COMPLETED{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Duration: {Colors.YELLOW}{duration:.1f}s{Colors.RESET}")
        print(f"Total Vulnerabilities: {Colors.YELLOW}{total_vulns}{Colors.RESET}")
        print(f"High-Risk Findings: {Colors.RED}{high_risk}{Colors.RESET}")
        
        if high_risk > 0:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠️  CRITICAL FINDINGS DETECTED - IMMEDIATE ATTENTION REQUIRED{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}Results saved to: {self.results_dir}/{Colors.RESET}")
