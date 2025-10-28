#!/usr/bin/env python3
"""
Helper utilities for Linux vulnerability scanner
Provides JSON processing and advanced parsing capabilities
"""

import json
import sys
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

class SecurityScanHelper:
    """Helper class for security scan operations"""
    
    @staticmethod
    def parse_lynis_report(report_path: str) -> Dict[str, Any]:
        """Parse Lynis report and extract findings"""
        try:
            with open(report_path, 'r') as f:
                content = f.read()
            
            findings = {
                'warnings': 0,
                'suggestions': 0,
                'tests_performed': 0,
                'hardening_index': 0
            }
            
            # Extract basic metrics from Lynis report
            warning_match = re.search(r'warnings\\[([0-9]+)\\]', content)
            suggestion_match = re.search(r'suggestions\\[([0-9]+)\\]', content)
            tests_match = re.search(r'tests_performed\\[([0-9]+)\\]', content)
            hardening_match = re.search(r'harden_index\\[([0-9]+)\\]', content)
            
            if warning_match:
                findings['warnings'] = int(warning_match.group(1))
            if suggestion_match:
                findings['suggestions'] = int(suggestion_match.group(1))
            if tests_match:
                findings['tests_performed'] = int(tests_match.group(1))
            if hardening_match:
                findings['hardening_index'] = int(hardening_match.group(1))
            
            return findings
            
        except Exception as e:
            return {'error': f'Failed to parse Lynis report: {str(e)}'}
    
    @staticmethod
    def parse_nmap_xml(xml_path: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        try:
            # This is a simplified parser - in production, use python-libnmap
            with open(xml_path, 'r') as f:
                content = f.read()
            
            ports = []
            open_ports = 0
            
            # Extract port information
            port_matches = re.findall(r'<port protocol="[^"]+" portid="([^"]+)">[\\s\\S]*?<state state="([^"]+)"/>', content)
            
            for port_id, state in port_matches:
                if state == 'open':
                    open_ports += 1
                    ports.append({
                        'port': port_id,
                        'state': state
                    })
            
            return {
                'open_ports': open_ports,
                'ports': ports
            }
            
        except Exception as e:
            return {'error': f'Failed to parse Nmap XML: {str(e)}'}
    
    @staticmethod
    def severity_to_level(severity: str) -> int:
        """Convert severity string to numeric level"""
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0,
            'unknown': 0
        }
        return severity_map.get(severity.lower(), 0)
    
    @staticmethod
    def validate_json_schema(data: Dict[str, Any]) -> bool:
        """Validate scan result JSON schema"""
        required_fields = ['scan_id', 'timestamp', 'host', 'distro', 'scanner_results']
        
        for field in required_fields:
            if field not in data:
                return False
        
        return True

def main():
    """CLI interface for helper functions"""
    if len(sys.argv) < 2:
        print("Usage: helper.py <command> [args]")
        sys.exit(1)
    
    command = sys.argv[1]
    helper = SecurityScanHelper()
    
    try:
        if command == "parse-lynis":
            if len(sys.argv) < 3:
                print("Usage: helper.py parse-lynis <report_file>")
                sys.exit(1)
            result = helper.parse_lynis_report(sys.argv[2])
            print(json.dumps(result))
        
        elif command == "parse-nmap":
            if len(sys.argv) < 3:
                print("Usage: helper.py parse-nmap <xml_file>")
                sys.exit(1)
            result = helper.parse_nmap_xml(sys.argv[2])
            print(json.dumps(result))
        
        elif command == "severity-level":
            if len(sys.argv) < 3:
                print("Usage: helper.py severity-level <severity>")
                sys.exit(1)
            level = helper.severity_to_level(sys.argv[2])
            print(level)
        
        elif command == "validate-schema":
            data = json.loads(sys.stdin.read())
            is_valid = helper.validate_json_schema(data)
            print(json.dumps({"valid": is_valid}))
        
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
