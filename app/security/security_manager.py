"""
Security Manager

Coordinates all security components including network monitoring, packet analysis,
and firewall management.
"""
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from .network_monitor import NetworkMonitor
from .packet_analyzer import PacketAnalyzer
from .firewall import Firewall

logger = logging.getLogger(__name__)

class SecurityManager:
    """Manages all security components and coordinates their actions."""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the security manager with all security components.
        
        Args:
            config: Configuration dictionary for security components
        """
        self.config = config or {}
        self.running = False
        
        # Initialize components
        self.firewall = Firewall()
        self.packet_analyzer = PacketAnalyzer()
        
        # Network monitor will be initialized on demand
        self.network_monitor = None
        
        # Threat intelligence
        self.known_threats = set()  # Known malicious IPs/hashes/patterns
        self.whitelist = set()      # Trusted IPs/hosts
        
        # Load configuration
        self._load_config()
    
    def _load_config(self):
        """Load configuration for security components."""
        # Default configuration
        self.config.setdefault('monitoring_enabled', True)
        self.config.setdefault('block_malicious', True)
        self.config.setdefault('alert_threshold', 0.7)  # 0-1 threat score
        
        # Initialize network monitor if enabled
        if self.config.get('monitoring_enabled', True):
            self.network_monitor = NetworkMonitor(
                interface=self.config.get('network_interface'),
                detection_thresholds={
                    'port_scan': self.config.get('port_scan_threshold', 10),
                    'ddos': self.config.get('ddos_threshold', 100),
                    'syn_flood': self.config.get('syn_flood_threshold', 50)
                }
            )
    
    def start(self):
        """Start all security components."""
        if self.running:
            logger.warning("Security manager is already running")
            return
            
        try:
            # Start network monitoring
            if self.network_monitor:
                self.network_monitor.start()
                
            # Start cleanup thread
            self.running = True
            self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self.cleanup_thread.start()
            
            logger.info("Security manager started")
            
        except Exception as e:
            logger.error(f"Failed to start security manager: {e}")
            self.running = False
    
    def stop(self):
        """Stop all security components."""
        self.running = False
        
        if self.network_monitor:
            self.network_monitor.stop()
        
        logger.info("Security manager stopped")
    
    def analyze_traffic(self, packet: bytes, src_ip: str, dst_ip: str = None, 
                       dst_port: int = None, protocol: str = None) -> Dict:
        """
        Analyze network traffic for security threats.
        
        Args:
            packet: Raw packet data
            src_ip: Source IP address
            dst_ip: Destination IP address (optional)
            dst_port: Destination port (optional)
            protocol: Network protocol (e.g., 'tcp', 'udp') (optional)
            
        Returns:
            Dict containing analysis results
        """
        result = {
            'threats': [],
            'risk_score': 0.0,
            'action_taken': None,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            # Skip whitelisted IPs
            if src_ip in self.whitelist:
                return result
            
            # Check for known threats
            if src_ip in self.known_threats:
                result['threats'].append({
                    'type': 'known_threat',
                    'severity': 'high',
                    'details': f"Known malicious IP: {src_ip}"
                })
                result['risk_score'] = 1.0
            
            # Analyze packet payload
            payload_threats = self.packet_analyzer.analyze_payload(packet, src_ip)
            for threat_type, sample in payload_threats:
                result['threats'].append({
                    'type': threat_type,
                    'severity': self._get_threat_severity(threat_type),
                    'details': f"Malicious pattern: {sample}"
                })
                result['risk_score'] = max(result['risk_score'], 0.7)  # At least high risk
            
            # Analyze connection metadata if available
            if dst_ip and dst_port and protocol:
                conn_analysis = self.packet_analyzer.analyze_connection(
                    src_ip, dst_ip, dst_port, protocol, len(packet)
                )
                
                if conn_analysis['anomalies']:
                    for anomaly in conn_analysis['anomalies']:
                        result['threats'].append({
                            'type': 'anomaly',
                            'severity': 'medium',
                            'details': anomaly
                        })
                    
                    # Increase risk score based on connection anomalies
                    result['risk_score'] = max(
                        result['risk_score'], 
                        conn_analysis['risk_score']
                    )
            
            # Take action if risk exceeds threshold
            if result['risk_score'] >= self.config['alert_threshold']:
                action = self._take_action(src_ip, result)
                result['action_taken'] = action
        
        except Exception as e:
            logger.error(f"Error analyzing traffic: {e}")
        
        return result
    
    def _take_action(self, ip: str, analysis: Dict) -> str:
        """
        Take appropriate action based on threat analysis.
        
        Args:
            ip: Source IP address
            analysis: Threat analysis results
            
        Returns:
            String describing the action taken
        """
        if not self.config.get('block_malicious', True):
            return "monitor_only"
        
        # Block IP if risk is high
        if analysis['risk_score'] >= 0.8:  # High or critical risk
            duration = 3600  # 1 hour block
            if self.firewall.block_ip(ip, "High risk traffic detected", duration):
                self.known_threats.add(ip)
                return f"blocked_{duration}s"
            return "block_failed"
        
        # Log and monitor for medium risk
        elif analysis['risk_score'] >= 0.5:
            logger.warning(f"Suspicious activity from {ip}: {analysis}")
            return "logged"
        
        return "no_action"
    
    def _get_threat_severity(self, threat_type: str) -> str:
        """Get severity level for a threat type."""
        critical = ['sql_injection', 'remote_code_execution', 'shellcode']
        high = ['xss', 'command_injection', 'path_traversal']
        medium = ['anomaly', 'suspicious_request']
        
        if any(t in threat_type.lower() for t in critical):
            return 'critical'
        elif any(t in threat_type.lower() for t in high):
            return 'high'
        elif any(t in threat_type.lower() for t in medium):
            return 'medium'
        return 'low'
    
    def _cleanup_loop(self):
        """Background thread for periodic cleanup tasks."""
        while self.running:
            try:
                # Clean up expired firewall rules
                self.firewall.cleanup_expired_rules()
                
                # Clean up old known threats (e.g., after 24 hours)
                # This is a placeholder - in a real implementation, you'd track when each was added
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
            
            # Run cleanup every 5 minutes
            time.sleep(300)
    
    def add_to_whitelist(self, ip: str):
        """Add an IP to the whitelist."""
        self.whitelist.add(ip)
        logger.info(f"Added {ip} to whitelist")
    
    def remove_from_whitelist(self, ip: str):
        """Remove an IP from the whitelist."""
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            logger.info(f"Removed {ip} from whitelist")
    
    def get_security_status(self) -> Dict:
        """Get current security status."""
        return {
            'running': self.running,
            'blocked_ips': len(self.firewall.list_blocked_ips()),
            'known_threats': len(self.known_threats),
            'whitelisted_ips': len(self.whitelist),
            'monitoring_enabled': self.network_monitor is not None
        }
