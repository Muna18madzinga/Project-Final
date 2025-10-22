"""
Network Security Monitor

Monitors network traffic for suspicious activities and potential attacks.
"""
import socket
import struct
import time
import threading
from collections import defaultdict, deque
import logging
import platform
import subprocess
from typing import Dict, Deque, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkMonitor:
    """Monitors network traffic for suspicious activities."""
    
    def __init__(self, interface: str = None):
        self.interface = interface or self._get_default_interface()
        self.running = False
        self.socket = None
        self.whitelist = set()
        self.blacklist = set()
        
        # Detection thresholds
        self.thresholds = {
            'syn_flood': 50,      # Max SYN packets/sec
            'port_scan': 10,      # Max ports scanned/min
            'connection_rate': 30  # Max connections/sec
        }
        
        # Track connections and attacks
        self.syn_requests: Dict[str, Deque[float]] = defaultdict(deque)
        self.blocked_ips: Dict[str, Tuple[float, str]] = {}  # ip: (unblock_time, reason)
        
    def start(self):
        """Start monitoring network traffic."""
        if self.running:
            return
            
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.running = True
            logger.info(f"Monitoring {self.interface}")
            
            # Start monitoring in background
            threading.Thread(target=self._monitor, daemon=True).start()
            threading.Thread(target=self._cleanup, daemon=True).start()
            
        except Exception as e:
            logger.error(f"Start failed: {e}")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.socket:
            self.socket.close()
    
    def _monitor(self):
        """Monitor network packets."""
        while self.running:
            try:
                packet, _ = self.socket.recvfrom(65535)
                self._analyze(packet)
            except Exception as e:
                if self.running:
                    logger.error(f"Packet error: {e}")
    
    def _analyze(self, packet: bytes):
        """Analyze packet for threats."""
        try:
            # Parse Ethernet header
            eth_header = packet[:14]
            eth = struct.unpack('!6s6sH', eth_header)
            proto = socket.ntohs(eth[2])
            
            # IPv4
            if proto == 8:
                ip_header = packet[14:34]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                src_ip = socket.inet_ntoa(iph[8])
                
                # Skip whitelisted IPs
                if src_ip in self.whitelist:
                    return
                    
                # Check if IP is blocked
                if src_ip in self.blocked_ips:
                    if time.time() < self.blocked_ips[src_ip][0]:
                        return
                    del self.blocked_ips[src_ip]
                
                # TCP
                if iph[6] == 6:
                    tcp_header = packet[34:54]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    
                    # SYN flood detection
                    if tcph[5] & 0x12 == 0x02:  # SYN flag only
                        self._check_syn_flood(src_ip)
                        
        except Exception as e:
            logger.debug(f"Analysis error: {e}")
    
    def _check_syn_flood(self, ip: str):
        """Detect SYN flood attacks."""
        now = time.time()
        self.syn_requests[ip].append(now)
        
        # Count SYNs in last second
        recent = [t for t in self.syn_requests[ip] if now - t < 1.0]
        self.syn_requests[ip] = deque(recent, maxlen=1000)
        
        if len(recent) > self.thresholds['syn_flood']:
            self.block_ip(ip, f"SYN flood ({len(recent)}/s)", 300)
    
    def block_ip(self, ip: str, reason: str, duration: int):
        """Block an IP address."""
        if ip in self.whitelist:
            return
            
        unblock_time = time.time() + duration
        self.blocked_ips[ip] = (unblock_time, reason)
        self._update_firewall(ip, 'block')
        
        # Schedule unblock
        threading.Timer(duration, self._unblock_ip, [ip]).start()
        
        logger.warning(f"Blocked {ip}: {reason}")
    
    def _unblock_ip(self, ip: str):
        """Unblock an IP address."""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self._update_firewall(ip, 'unblock')
    
    def _update_firewall(self, ip: str, action: str):
        """Update system firewall rules."""
        try:
            if platform.system() == 'Windows':
                cmd = ['netsh', 'advfirewall', 'firewall']
                if action == 'block':
                    cmd.extend(['add', 'rule', f'name="Block {ip}"', 'dir=in', 'action=block', f'remoteip={ip}'])
                else:
                    cmd.extend(['delete', 'rule', f'name="Block {ip}"'])
            else:
                cmd = ['iptables']
                if action == 'block':
                    cmd.extend(['-A', 'INPUT', '-s', ip, '-j', 'DROP'])
                else:
                    cmd.extend(['-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            
            subprocess.run(cmd, check=True, capture_output=True)
            
        except Exception as e:
            logger.error(f"Firewall {action} failed: {e}")
    
    def _cleanup(self):
        """Clean up old entries."""
        while self.running:
            time.sleep(60)
            now = time.time()
            
            # Clean old SYN requests
            for ip in list(self.syn_requests.keys()):
                self.syn_requests[ip] = deque(
                    t for t in self.syn_requests[ip] 
                    if now - t < 60.0
                )
                if not self.syn_requests[ip]:
                    del self.syn_requests[ip]
            
            # Clean expired blocks
            for ip in list(self.blocked_ips.keys()):
                if now > self.blocked_ips[ip][0]:
                    del self.blocked_ips[ip]
    
    def _get_default_interface(self) -> str:
        """Get default network interface."""
        try:
            if platform.system() == 'Windows':
                return 'Ethernet'  # Default for Windows
            else:
                # Try to get default route interface
                with open('/proc/net/route') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) > 1 and parts[1] == '00000000':
                            return parts[0]
                return 'eth0'  # Fallback
        except:
            return 'eth0'
