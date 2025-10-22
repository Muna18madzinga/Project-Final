"""
Firewall Management

Manages firewall rules to block malicious traffic and protect the system.
"""
import subprocess
import platform
import logging
from typing import List, Dict, Optional, Tuple
import socket
import time
from threading import Timer

logger = logging.getLogger(__name__)

class Firewall:
    """Manages system firewall rules."""
    
    def __init__(self):
        self.active_rules: Dict[str, Dict] = {}
        self.platform = platform.system().lower()
        self._initialize_firewall()
    
    def _initialize_firewall(self):
        """Initialize firewall with default rules."""
        try:
            if self.platform == 'windows':
                # Enable Windows Firewall if disabled
                subprocess.run(
                    ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'],
                    check=True,
                    capture_output=True
                )
                logger.info("Windows Firewall initialized")
                
            elif self.platform == 'linux':
                # Ensure iptables is available
                try:
                    subprocess.run(
                        ['which', 'iptables'],
                        check=True,
                        capture_output=True
                    )
                    # Set default policies
                    subprocess.run(
                        ['iptables', '-P', 'INPUT', 'ACCEPT'],
                        check=True
                    )
                    subprocess.run(
                        ['iptables', '-P', 'FORWARD', 'DROP'],
                        check=True
                    )
                    subprocess.run(
                        ['iptables', '-P', 'OUTPUT', 'ACCEPT'],
                        check=True
                    )
                    logger.info("iptables firewall initialized")
                except subprocess.CalledProcessError:
                    logger.warning("iptables not found. Using basic firewall rules.")
            
            elif self.platform == 'darwin':  # macOS
                # Enable pfctl if available
                try:
                    subprocess.run(
                        ['which', 'pfctl'],
                        check=True,
                        capture_output=True
                    )
                    # Enable packet filtering
                    subprocess.run(
                        ['sudo', 'pfctl', '-e'],
                        check=True
                    )
                    logger.info("macOS pf firewall initialized")
                except subprocess.CalledProcessError:
                    logger.warning("pfctl not found. Using basic firewall rules.")
            
        except Exception as e:
            logger.error(f"Failed to initialize firewall: {e}")
    
    def block_ip(self, ip: str, reason: str = "", duration: int = 3600) -> bool:
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (0 = permanent)
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self._is_valid_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        try:
            rule_id = f"block_{ip}_{int(time.time())}"
            
            if self.platform == 'windows':
                # Windows Firewall rule
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name="{rule_id}"',
                    'dir=in',
                    'action=block',
                    f'remoteip={ip}'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.error(f"Failed to block IP {ip}: {result.stderr}")
                    return False
            
            elif self.platform in ['linux', 'darwin']:
                # Linux/macOS iptables/pf rule
                if self.platform == 'linux':
                    cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                else:  # macOS
                    cmd = ['sudo', 'pfctl', '-t', 'blocked_ips', '-T', 'add', ip]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.error(f"Failed to block IP {ip}: {result.stderr}")
                    return False
            
            # Store the rule
            self.active_rules[rule_id] = {
                'ip': ip,
                'created_at': time.time(),
                'expires_at': time.time() + duration if duration > 0 else None,
                'platform': self.platform,
                'reason': reason
            }
            
            # Schedule unblock if duration is set
            if duration > 0:
                Timer(duration, self.unblock_ip, args=[ip]).start()
            
            logger.info(f"Blocked IP {ip}. Reason: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock a previously blocked IP address.
        
        Args:
            ip: IP address to unblock
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Find and remove all rules for this IP
            rules_to_remove = [
                (rule_id, rule) 
                for rule_id, rule in self.active_rules.items() 
                if rule['ip'] == ip
            ]
            
            if not rules_to_remove:
                logger.warning(f"No active rules found for IP {ip}")
                return False
            
            success = True
            
            for rule_id, rule in rules_to_remove:
                try:
                    if self.platform == 'windows':
                        cmd = [
                            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            f'name="{rule_id}"'
                        ]
                    elif self.platform == 'linux':
                        cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
                    else:  # macOS
                        cmd = ['sudo', 'pfctl', '-t', 'blocked_ips', '-T', 'delete', ip]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        del self.active_rules[rule_id]
                        logger.info(f"Unblocked IP {ip}")
                    else:
                        logger.error(f"Failed to unblock IP {ip}: {result.stderr}")
                        success = False
                        
                except Exception as e:
                    logger.error(f"Error unblocking IP {ip}: {e}")
                    success = False
            
            return success
            
        except Exception as e:
            logger.error(f"Error in unblock_ip for {ip}: {e}")
            return False
    
    def list_blocked_ips(self) -> List[Dict]:
        """
        Get a list of currently blocked IPs.
        
        Returns:
            List of dictionaries containing blocked IP information
        """
        now = time.time()
        active_blocks = []
        
        for rule_id, rule in list(self.active_rules.items()):
            # Remove expired rules
            if rule['expires_at'] and rule['expires_at'] < now:
                self.unblock_ip(rule['ip'])
                continue
                
            active_blocks.append({
                'ip': rule['ip'],
                'blocked_at': rule['created_at'],
                'expires_at': rule['expires_at'],
                'reason': rule.get('reason', '')
            })
        
        return active_blocks
    
    def cleanup_expired_rules(self):
        """Remove all expired firewall rules."""
        now = time.time()
        for rule in list(self.active_rules.values()):
            if rule['expires_at'] and rule['expires_at'] < now:
                self.unblock_ip(rule['ip'])
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if the given string is a valid IP address."""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
