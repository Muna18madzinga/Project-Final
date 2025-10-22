"""
Real Live Network Data Collector
Replaces simulated network data with actual network traffic capture and analysis
"""

import logging
import asyncio
import json
import platform
import time
import threading
import psutil
import netifaces
import requests
import socket
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, conf, get_if_list
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

@dataclass
class RealNetworkEvent:
    """Real network event data structure."""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    packet_size: int
    flags: List[str]
    payload_snippet: str
    geo_location: Optional[Dict[str, Any]]
    threat_indicators: List[str]
    flow_id: str

@dataclass
class SystemMetrics:
    """Real system metrics data structure."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_io_read: int
    disk_io_write: int
    network_bytes_sent: int
    network_bytes_recv: int
    active_connections: int
    processes_count: int
    load_average: List[float]

class RealNetworkCollector:
    """Collects real network traffic and system data instead of simulated data."""
    
    def __init__(self, interface: str = "auto", capture_filter: str = None):
        self.interface = interface
        self.capture_filter = capture_filter or "not arp and not icmp"
        self.is_running = False
        self.packet_buffer = deque(maxlen=50000)
        self.flow_tracker = defaultdict(dict)
        self.collection_thread = None
        self._resolved_interface: Optional[str] = None
        
        # Real data collectors
        self.system_metrics_collector = RealSystemMetricsCollector()
        self.threat_intel_collector = LiveThreatIntelCollector()
        
        # Statistics
        self.packets_captured = 0
        self.bytes_captured = 0
        self.start_time = None

    def start_collection(self):
        """Start real network data collection."""
        if self.is_running:
            logger.warning("Collection already running")
            return

        resolved = self._resolve_interface()
        if not resolved:
            logger.error("Failed to resolve network interface for capture")
            return

        self._resolved_interface = resolved
        self.is_running = True
        self.start_time = datetime.now()
        
        # Start collection thread
        self.collection_thread = threading.Thread(target=self._collect_real_network_data)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        
        # Start system metrics collection
        self.system_metrics_collector.start_collection()
        
        # Start threat intel collection
        self.threat_intel_collector.start_collection()
        
        logger.info(f"Real network collection started on interface: {self._resolved_interface}")

    def stop_collection(self):
        """Stop network data collection."""
        self.is_running = False
        
        if self.collection_thread:
            self.collection_thread.join(timeout=10)
        
        self.system_metrics_collector.stop_collection()
        self.threat_intel_collector.stop_collection()
        
        logger.info(f"Network collection stopped. Captured {self.packets_captured} packets, {self.bytes_captured} bytes")

    def _collect_real_network_data(self):
        """Main network data collection loop."""
        try:
            logger.info(f"Starting packet capture on {self._resolved_interface} with filter: {self.capture_filter}")
            
            sniff(
                iface=self._resolved_interface,
                prn=self._process_real_packet,
                filter=self.capture_filter,
                store=False,
                stop_filter=lambda x: not self.is_running,
                timeout=2
            )
        except Exception as e:
            logger.error(f"Network collection error: {e}")
            self.is_running = False

    def _process_real_packet(self, packet):
        """Process real captured network packet."""
        try:
            if not IP in packet:
                return
            
            ip_layer = packet[IP]
            
            # Basic packet information
            packet_data = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'packet_size': len(packet),
                'ttl': ip_layer.ttl,
                'timestamp': datetime.now(timezone.utc)
            }
            
            # Protocol-specific data
            source_port = None
            dest_port = None
            flags = []
            
            if TCP in packet:
                tcp_layer = packet[TCP]
                source_port = tcp_layer.sport
                dest_port = tcp_layer.dport
                packet_data.update({
                    'transport_protocol': 'tcp',
                    'tcp_flags': tcp_layer.flags,
                    'tcp_window': tcp_layer.window,
                    'tcp_seq': tcp_layer.seq,
                    'tcp_ack': tcp_layer.ack
                })
                
                # TCP flag analysis
                if tcp_layer.flags & 0x02:  # SYN
                    flags.append('syn')
                if tcp_layer.flags & 0x10:  # ACK
                    flags.append('ack')
                if tcp_layer.flags & 0x01:  # FIN
                    flags.append('fin')
                if tcp_layer.flags & 0x04:  # RST
                    flags.append('rst')
                    
            elif UDP in packet:
                udp_layer = packet[UDP]
                source_port = udp_layer.sport
                dest_port = udp_layer.dport
                packet_data.update({
                    'transport_protocol': 'udp',
                    'udp_length': udp_layer.len
                })
            
            # Extract payload snippet
            payload_snippet = ""
            try:
                if packet.payload and len(packet.payload) > 0:
                    raw_payload = bytes(packet.payload)
                    payload_snippet = raw_payload[:100].decode('utf-8', errors='replace')
            except Exception:
                pass
            
            # Create flow ID
            flow_id = f"{ip_layer.src}:{source_port}->{ip_layer.dst}:{dest_port}"
            
            # Detect threat indicators
            threat_indicators = self._analyze_packet_threats(packet_data, payload_snippet)
            
            # Get geolocation for external IPs
            geo_location = self._get_geo_location(ip_layer.dst) if not self._is_private_ip(ip_layer.dst) else None
            
            # Create network event
            network_event = RealNetworkEvent(
                timestamp=packet_data['timestamp'],
                source_ip=ip_layer.src,
                dest_ip=ip_layer.dst,
                source_port=source_port,
                dest_port=dest_port,
                protocol=packet_data.get('transport_protocol', 'unknown'),
                packet_size=packet_data['packet_size'],
                flags=flags,
                payload_snippet=payload_snippet,
                geo_location=geo_location,
                threat_indicators=threat_indicators,
                flow_id=flow_id
            )
            
            # Update flow tracking
            self._update_real_flow_stats(flow_id, network_event)
            
            # Add to buffer
            self.packet_buffer.append(network_event)
            
            # Update statistics
            self.packets_captured += 1
            self.bytes_captured += packet_data['packet_size']
            
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    def _analyze_packet_threats(self, packet_data: Dict, payload: str) -> List[str]:
        """Analyze packet for threat indicators."""
        threats = []
        
        # Port-based analysis
        dest_port = packet_data.get('dest_port')
        if dest_port:
            # Common attack ports
            attack_ports = {22: 'ssh_brute_force', 23: 'telnet_attack', 135: 'rpc_exploit',
                           139: 'netbios_attack', 445: 'smb_attack', 1433: 'mssql_attack',
                           3389: 'rdp_attack', 5900: 'vnc_attack'}
            
            if dest_port in attack_ports:
                threats.append(attack_ports[dest_port])
        
        # Payload analysis
        if payload:
            # SQL injection patterns
            sql_patterns = ['union select', 'drop table', '1=1', 'or 1=1', 'waitfor delay']
            if any(pattern in payload.lower() for pattern in sql_patterns):
                threats.append('sql_injection')
            
            # XSS patterns
            xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
            if any(pattern in payload.lower() for pattern in xss_patterns):
                threats.append('xss_attack')
            
            # Command injection patterns
            cmd_patterns = [';cat ', ';ls ', ';rm ', '$(', '`']
            if any(pattern in payload.lower() for pattern in cmd_patterns):
                threats.append('command_injection')
        
        # TCP flag analysis
        tcp_flags = packet_data.get('tcp_flags')
        if tcp_flags:
            # SYN flood detection (multiple SYN packets)
            if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN but no ACK
                threats.append('possible_syn_flood')
            
            # Port scanning detection (RST packets)
            if tcp_flags & 0x04:  # RST flag
                threats.append('possible_port_scan')
        
        return threats

    def _update_real_flow_stats(self, flow_id: str, event: RealNetworkEvent):
        """Update real flow statistics."""
        flow = self.flow_tracker[flow_id]
        
        if 'packet_count' not in flow:
            flow['packet_count'] = 0
            flow['bytes_total'] = 0
            flow['first_seen'] = event.timestamp
            flow['threat_indicators'] = set()
        
        flow['packet_count'] += 1
        flow['bytes_total'] += event.packet_size
        flow['last_seen'] = event.timestamp
        flow['threat_indicators'].update(event.threat_indicators)
        
        # Flow-based anomaly detection
        if flow['packet_count'] > 1000:  # High packet count
            if 'high_packet_volume' not in event.threat_indicators:
                event.threat_indicators.append('high_packet_volume')
        
        if flow['bytes_total'] > 1000000:  # High byte count
            if 'high_data_volume' not in event.threat_indicators:
                event.threat_indicators.append('high_data_volume')

    def _get_geo_location(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geolocation for IP address using free API."""
        try:
            # Use free ipapi.co service (1000 requests/day limit)
            response = requests.get(f"http://ipapi.co/{ip_address}/json/", timeout=2)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'isp': data.get('org'),
                    'threat_level': self._assess_geo_threat(data)
                }
        except Exception as e:
            logger.debug(f"Geolocation lookup failed for {ip_address}: {e}")
        
        return None

    def _assess_geo_threat(self, geo_data: Dict) -> str:
        """Assess threat level based on geolocation."""
        country = geo_data.get('country_name', '').lower()
        
        # High-risk countries (simplified example)
        high_risk_countries = ['china', 'russia', 'north korea', 'iran']
        if any(risk_country in country for risk_country in high_risk_countries):
            return 'high'
        
        # Known bot/VPN hosting countries
        moderate_risk_countries = ['romania', 'ukraine', 'vietnam']
        if any(risk_country in country for risk_country in moderate_risk_countries):
            return 'moderate'
        
        return 'low'

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is private."""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except Exception:
            return False

    def _resolve_interface(self) -> Optional[str]:
        """Resolve network interface for packet capture."""
        if self.interface and self.interface.lower() not in ['auto', 'any']:
            return self.interface
        
        system = platform.system()
        
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            
            # Filter out loopback and inactive interfaces
            active_interfaces = []
            for iface in interfaces:
                if iface.startswith('lo'):  # Skip loopback
                    continue
                
                try:
                    # Check if interface has an IP address
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        active_interfaces.append(iface)
                except Exception:
                    continue
            
            if active_interfaces:
                # Prefer ethernet interfaces over Wi-Fi
                for iface in active_interfaces:
                    if any(prefix in iface.lower() for prefix in ['eth', 'en0', 'ens']):
                        return iface
                
                # Fall back to first active interface
                return active_interfaces[0]
            
            # Last resort - try scapy's default
            if conf.iface:
                return conf.iface
                
        except Exception as e:
            logger.debug(f"Interface resolution error: {e}")
        
        return None

    def get_real_data_batch(self, batch_size: int = 100) -> List[RealNetworkEvent]:
        """Get batch of real network events."""
        batch = []
        for _ in range(min(batch_size, len(self.packet_buffer))):
            if self.packet_buffer:
                batch.append(self.packet_buffer.popleft())
        return batch

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'is_running': self.is_running,
            'interface': self._resolved_interface,
            'packets_captured': self.packets_captured,
            'bytes_captured': self.bytes_captured,
            'uptime_seconds': uptime,
            'packets_per_second': self.packets_captured / max(uptime, 1),
            'buffer_size': len(self.packet_buffer),
            'active_flows': len(self.flow_tracker),
            'system_metrics_active': self.system_metrics_collector.is_running,
            'threat_intel_active': self.threat_intel_collector.is_running
        }


class RealSystemMetricsCollector:
    """Collects real system metrics instead of simulated data."""
    
    def __init__(self, collection_interval: float = 5.0):
        self.collection_interval = collection_interval
        self.is_running = False
        self.metrics_buffer = deque(maxlen=1000)
        self.collection_thread = None

    def start_collection(self):
        """Start system metrics collection."""
        if self.is_running:
            return
        
        self.is_running = True
        self.collection_thread = threading.Thread(target=self._collect_system_metrics)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        logger.info("Real system metrics collection started")

    def stop_collection(self):
        """Stop system metrics collection."""
        self.is_running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("System metrics collection stopped")

    def _collect_system_metrics(self):
        """Collect real system metrics."""
        while self.is_running:
            try:
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                
                # Memory metrics
                memory = psutil.virtual_memory()
                memory_percent = memory.percent
                
                # Disk I/O metrics
                disk_io = psutil.disk_io_counters()
                disk_io_read = disk_io.read_bytes if disk_io else 0
                disk_io_write = disk_io.write_bytes if disk_io else 0
                
                # Network I/O metrics
                net_io = psutil.net_io_counters()
                network_bytes_sent = net_io.bytes_sent if net_io else 0
                network_bytes_recv = net_io.bytes_recv if net_io else 0
                
                # Process and connection metrics
                active_connections = len(psutil.net_connections())
                processes_count = len(psutil.pids())
                
                # Load average (Unix/Linux only)
                try:
                    load_average = list(psutil.getloadavg())
                except AttributeError:
                    # Windows doesn't have load average
                    load_average = [cpu_percent / 100, cpu_percent / 100, cpu_percent / 100]
                
                # Create metrics object
                metrics = SystemMetrics(
                    timestamp=datetime.now(timezone.utc),
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    disk_io_read=disk_io_read,
                    disk_io_write=disk_io_write,
                    network_bytes_sent=network_bytes_sent,
                    network_bytes_recv=network_bytes_recv,
                    active_connections=active_connections,
                    processes_count=processes_count,
                    load_average=load_average
                )
                
                self.metrics_buffer.append(metrics)
                
                time.sleep(self.collection_interval)
                
            except Exception as e:
                logger.error(f"System metrics collection error: {e}")
                time.sleep(self.collection_interval)

    def get_latest_metrics(self) -> Optional[SystemMetrics]:
        """Get latest system metrics."""
        return self.metrics_buffer[-1] if self.metrics_buffer else None

    def get_metrics_batch(self, batch_size: int = 10) -> List[SystemMetrics]:
        """Get batch of system metrics."""
        batch = []
        for _ in range(min(batch_size, len(self.metrics_buffer))):
            if self.metrics_buffer:
                batch.append(self.metrics_buffer.popleft())
        return batch


class LiveThreatIntelCollector:
    """Collects live threat intelligence feeds instead of static data."""
    
    def __init__(self, update_interval: float = 3600.0):  # Update every hour
        self.update_interval = update_interval
        self.is_running = False
        self.threat_intel = {}
        self.collection_thread = None
        
        # Free threat intel sources
        self.sources = {
            'abuse_ch_malware': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
            'phishtank': 'http://data.phishtank.com/data/online-valid.csv',
            'emerging_threats': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'
        }

    def start_collection(self):
        """Start threat intelligence collection."""
        if self.is_running:
            return
        
        self.is_running = True
        self.collection_thread = threading.Thread(target=self._collect_threat_intel)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        logger.info("Live threat intelligence collection started")

    def stop_collection(self):
        """Stop threat intelligence collection."""
        self.is_running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("Threat intelligence collection stopped")

    def _collect_threat_intel(self):
        """Collect threat intelligence from live sources."""
        while self.is_running:
            try:
                # Collect from each source
                for source_name, url in self.sources.items():
                    try:
                        self._fetch_threat_intel(source_name, url)
                        logger.info(f"Updated threat intel from {source_name}")
                    except Exception as e:
                        logger.error(f"Failed to fetch threat intel from {source_name}: {e}")
                
                # Wait for next update
                time.sleep(self.update_interval)
                
            except Exception as e:
                logger.error(f"Threat intel collection error: {e}")
                time.sleep(60)  # Wait 1 minute on error

    def _fetch_threat_intel(self, source_name: str, url: str):
        """Fetch threat intelligence from a specific source."""
        try:
            response = requests.get(url, timeout=30, headers={
                'User-Agent': 'AdaptiveSecuritySuite/1.0'
            })
            response.raise_for_status()
            
            # Parse based on source type
            if source_name == 'abuse_ch_malware':
                self._parse_abuse_ch_data(response.text)
            elif source_name == 'emerging_threats':
                self._parse_emerging_threats_data(response.text)
            # Add more parsers as needed
            
        except Exception as e:
            logger.debug(f"Error fetching from {source_name}: {e}")
            raise

    def _parse_abuse_ch_data(self, data: str):
        """Parse abuse.ch malware data."""
        lines = data.strip().split('\n')
        malware_urls = []
        
        for line in lines[8:]:  # Skip header
            if line and not line.startswith('#'):
                parts = line.split(',')
                if len(parts) >= 3:
                    malware_urls.append({
                        'url': parts[2].strip('"'),
                        'threat_type': 'malware',
                        'source': 'abuse_ch',
                        'timestamp': datetime.now(timezone.utc)
                    })
        
        self.threat_intel['malware_urls'] = malware_urls[:1000]  # Limit to 1000 recent

    def _parse_emerging_threats_data(self, data: str):
        """Parse Emerging Threats IP blacklist."""
        lines = data.strip().split('\n')
        bad_ips = []
        
        for line in lines:
            if line and not line.startswith('#'):
                ip = line.strip()
                if self._is_valid_ip(ip):
                    bad_ips.append({
                        'ip': ip,
                        'threat_type': 'compromised_host',
                        'source': 'emerging_threats',
                        'timestamp': datetime.now(timezone.utc)
                    })
        
        self.threat_intel['compromised_ips'] = bad_ips

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def check_threat_intel(self, indicator: str, indicator_type: str) -> List[Dict[str, Any]]:
        """Check if indicator matches known threats."""
        matches = []
        
        if indicator_type == 'ip' and 'compromised_ips' in self.threat_intel:
            for threat in self.threat_intel['compromised_ips']:
                if threat['ip'] == indicator:
                    matches.append(threat)
        
        elif indicator_type == 'url' and 'malware_urls' in self.threat_intel:
            for threat in self.threat_intel['malware_urls']:
                if indicator in threat['url']:
                    matches.append(threat)
        
        return matches

    def get_threat_intel_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        stats = {
            'is_running': self.is_running,
            'sources_configured': len(self.sources),
            'total_indicators': 0
        }
        
        for intel_type, data in self.threat_intel.items():
            stats[f'{intel_type}_count'] = len(data) if isinstance(data, list) else 1
            stats['total_indicators'] += len(data) if isinstance(data, list) else 1
        
        return stats


# Global collector instance
_real_collector = None

def get_real_network_collector() -> RealNetworkCollector:
    """Get global real network collector instance."""
    global _real_collector
    if _real_collector is None:
        _real_collector = RealNetworkCollector()
    return _real_collector