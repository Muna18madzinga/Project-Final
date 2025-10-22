"""
Packet Analyzer

Analyzes network packets for security threats and anomalies.
"""
import re
import socket
import struct
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, deque
import time
import logging

logger = logging.getLogger(__name__)

class PacketAnalyzer:
    """Analyzes network packets for security threats."""
    
    def __init__(self):
        # Known attack patterns
        self.patterns = [
            # SQL Injection
            (rb'\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|XP_|--|#|/\*).*\b', 'SQL Injection'),
            # XSS
            (rb'<script[^>]*>.*</script>', 'Cross-Site Scripting (XSS)'),
            (rb'on\w+\s*=', 'DOM-based XSS'),
            # Command Injection
            (rb'[;&|]\s*\b(?:rm|wget|curl|bash|sh|python|perl|powershell|cmd)\b', 'Command Injection'),
            # Path Traversal
            (rb'(?:\.\./|/\\){2,}', 'Path Traversal'),
            # Sensitive Files
            (rb'/etc/passwd|/etc/shadow|/etc/hosts|/etc/group', 'Sensitive File Access'),
            # Common Exploits
            (rb'wp-.*\.php|/phpmyadmin/|/adminer\.php', 'Common Web Exploit'),
            # Suspicious Headers
            (rb'User-Agent:\s*(nmap|nikto|sqlmap|w3af|acunetix)', 'Scanning Tool'),
            # Malformed Requests
            (rb'GET\s+/(?:cgi-bin/|\S*\.(?:php|asp|aspx|jsp|pl|py|sh|cgi))', 'Suspicious Request'),
            # Shellcode Patterns
            (rb'\x90{10,}|\xcc{5,}|\xcd\x80', 'Shellcode Detected')
        ]
        
        # Compile patterns for better performance
        self.compiled_patterns = [(re.compile(pattern, re.IGNORECASE | re.DOTALL), name) 
                                for pattern, name in self.patterns]
        
        # Rate limiting
        self.alert_history = defaultdict(deque)
        self.rate_limit = {
            'window': 60,  # seconds
            'max_alerts': 5  # max alerts per window
        }
    
    def analyze_payload(self, payload: bytes, src_ip: str) -> List[Tuple[str, str]]:
        """
        Analyze payload for malicious patterns.
        
        Args:
            payload: Raw packet payload
            src_ip: Source IP address
            
        Returns:
            List of (threat_name, matched_pattern) tuples
        """
        if not payload:
            return []
            
        threats = []
        
        try:
            # Convert to string if possible, otherwise analyze as bytes
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                payload_str = str(payload)
            
            # Check each pattern
            for pattern, name in self.compiled_patterns:
                if pattern.search(payload):
                    # Get a sample of the match (first 50 chars)
                    match = pattern.search(payload)
                    sample = match.group(0)[:50].decode('utf-8', errors='ignore')
                    if len(match.group(0)) > 50:
                        sample += '...'
                    
                    # Check rate limiting
                    if not self._is_rate_limited(name, src_ip):
                        threats.append((name, sample))
                        
                        # Log the threat
                        logger.warning(
                            f"Threat detected - Type: {name}, "
                            f"Source: {src_ip}, "
                            f"Sample: {sample}"
                        )
        
        except Exception as e:
            logger.error(f"Error analyzing payload: {e}")
        
        return threats
    
    def _is_rate_limited(self, alert_type: str, src_ip: str) -> bool:
        """Check if we should rate limit this alert."""
        now = time.time()
        key = f"{alert_type}:{src_ip}"
        
        # Remove old entries
        self.alert_history[key] = deque(
            t for t in self.alert_history[key] 
            if now - t < self.rate_limit['window']
        )
        
        # Check if we've exceeded the rate limit
        if len(self.alert_history[key]) >= self.rate_limit['max_alerts']:
            return True
            
        self.alert_history[key].append(now)
        return False
    
    def analyze_connection(self, src_ip: str, dst_ip: str, dst_port: int, 
                          protocol: str, payload_size: int) -> Dict:
        """
        Analyze connection metadata for anomalies.
        
        Returns:
            Dict with analysis results
        """
        result = {
            'anomalies': [],
            'risk_score': 0.0,
            'suspicious': False
        }
        
        try:
            # Check for unusual ports
            if protocol == 'tcp':
                if dst_port < 1024 and dst_port not in [80, 443, 22, 21, 25, 53]:
                    result['anomalies'].append(f"Unusual privileged port: {dst_port}")
                    result['risk_score'] += 0.3
                
                # Check for common attack ports
                suspicious_ports = {
                    22: 'SSH brute force',
                    23: 'Telnet (insecure)',
                    1433: 'SQL Server',
                    3306: 'MySQL',
                    3389: 'RDP',
                    8080: 'Alternative HTTP',
                    8443: 'Alternative HTTPS'
                }
                
                if dst_port in suspicious_ports:
                    result['anomalies'].append(
                        f"Connection to potentially risky service: "
                        f"{suspicious_ports[dst_port]} (port {dst_port})"
                    )
                    result['risk_score'] += 0.2
            
            # Check for unusual payload sizes
            if payload_size > 1500:  # Typical MTU is 1500 bytes
                result['anomalies'].append(f"Large payload size: {payload_size} bytes")
                result['risk_score'] += 0.1
            
            # Check for private IP ranges
            if self._is_private_ip(dst_ip) and not self._is_private_ip(src_ip):
                result['anomalies'].append("External to internal network connection")
                result['risk_score'] += 0.4
            
            # Mark as suspicious if risk score is high
            if result['risk_score'] > 0.5:
                result['suspicious'] = True
            
        except Exception as e:
            logger.error(f"Error analyzing connection: {e}")
        
        return result
    
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if an IP is in private ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
