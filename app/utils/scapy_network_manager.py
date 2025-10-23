"""
Scapy-based Network Traffic Management and Device Detection
Provides comprehensive network scanning, device discovery, and traffic monitoring
"""

import logging
import threading
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
import netifaces
from scapy.all import (
    ARP, Ether, srp, sniff, IP, TCP, UDP, ICMP,
    get_if_list, get_if_addr, get_if_hwaddr, conf
)
from collections import defaultdict

logger = logging.getLogger(__name__)


class ScapyNetworkManager:
    """Manages network scanning and traffic monitoring using Scapy"""

    def __init__(self):
        self.devices = {}
        self.traffic_stats = defaultdict(lambda: {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'protocols': defaultdict(int),
            'last_seen': None
        })
        self.is_monitoring = False
        self.monitor_thread = None
        self._lock = threading.Lock()

        # Get default interface
        self.interface = self._get_default_interface()
        logger.info(f"ScapyNetworkManager initialized with interface: {self.interface}")

    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface"""
        try:
            # Try to get default gateway interface
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                iface_name = gws['default'][netifaces.AF_INET][1]
                return iface_name

            # Fallback to first available interface
            interfaces = get_if_list()
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('Loopback'):
                    return iface

            return None
        except Exception as e:
            logger.error(f"Error getting default interface: {e}")
            return None

    def scan_network(self, timeout: int = 3) -> List[Dict[str, Any]]:
        """
        Scan the local network for active devices using ARP

        Args:
            timeout: Timeout in seconds for the scan

        Returns:
            List of discovered devices with their information
        """
        devices = []

        try:
            if not self.interface:
                logger.warning("No network interface available for scanning")
                return devices

            # Get network range
            network_range = self._get_network_range()
            if not network_range:
                logger.warning("Could not determine network range")
                return devices

            logger.info(f"Scanning network {network_range} on interface {self.interface}")

            # Create ARP request packet
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Send packet and receive response
            answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=False, iface=self.interface)[0]

            # Process responses
            for sent, received in answered_list:
                device = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'name': self._get_device_name(received.psrc, received.hwsrc),
                    'vendor': self._get_vendor(received.hwsrc),
                    'type': self._identify_device_type(received.hwsrc),
                    'status': 'online',
                    'last_seen': datetime.now().isoformat(),
                    'response_time': f"{(time.time() - time.time()):.2f}ms"
                }
                devices.append(device)

                # Cache the device
                with self._lock:
                    self.devices[device['mac']] = device

            logger.info(f"Discovered {len(devices)} devices on network")
            return devices

        except PermissionError:
            logger.error("Permission denied: Scapy requires administrator/root privileges for network scanning")
            return []
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            return []

    def _get_network_range(self) -> Optional[str]:
        """Get the network range for scanning (e.g., 192.168.1.0/24)"""
        try:
            if not self.interface:
                return None

            # Get interface addresses
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET not in addrs:
                return None

            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info.get('addr')
            netmask = ip_info.get('netmask')

            if not ip or not netmask:
                return None

            # Calculate network address
            ip_parts = ip.split('.')
            mask_parts = netmask.split('.')

            network_parts = [
                str(int(ip_parts[i]) & int(mask_parts[i]))
                for i in range(4)
            ]

            # Calculate CIDR notation
            cidr = sum([bin(int(x)).count('1') for x in mask_parts])

            network_range = '.'.join(network_parts) + f'/{cidr}'
            return network_range

        except Exception as e:
            logger.error(f"Error calculating network range: {e}")
            return None

    def _get_device_name(self, ip: str, mac: str) -> str:
        """Generate a friendly device name"""
        # Use MAC vendor as base
        vendor = self._get_vendor(mac)
        if vendor and vendor != "Unknown":
            last_octet = ip.split('.')[-1]
            return f"{vendor}-{last_octet}"
        return f"Device-{ip.split('.')[-1]}"

    def _get_vendor(self, mac: str) -> str:
        """Identify device vendor from MAC address"""
        mac_upper = mac.upper()

        # Common MAC OUI prefixes
        vendors = {
            'DC:A6:32': 'Raspberry Pi',
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:15:5D': 'Microsoft Hyper-V',
            '00:03:FF': 'Microsoft',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:1B:63': 'Apple',
            '00:17:88': 'Apple',
            '00:1C:B3': 'Apple',
            '00:03:93': 'Apple',
            '28:16:AD': 'Apple',
            '00:05:02': 'Apple',
            'AC:DE:48': 'Apple',
            'FC:25:3F': 'Apple',
            '00:1D:4F': 'Apple',
            '00:26:BB': 'Apple',
            '00:50:F2': 'Microsoft',
            '00:E0:4C': 'Realtek',
            '00:13:E0': 'Samsung',
            '00:12:FB': 'Cisco',
        }

        # Check first 8 characters (OUI)
        oui = ':'.join(mac_upper.split(':')[:3])
        return vendors.get(oui, "Unknown")

    def _identify_device_type(self, mac: str) -> str:
        """Identify device type based on MAC address"""
        vendor = self._get_vendor(mac)

        type_mapping = {
            'VMware': 'Virtual Machine',
            'Microsoft Hyper-V': 'Virtual Machine',
            'Microsoft': 'Computer',
            'Raspberry Pi': 'IoT Device',
            'Apple': 'Mobile/Computer',
            'Cisco': 'Network Equipment',
            'Realtek': 'Network Adapter',
            'Samsung': 'Mobile Device'
        }

        return type_mapping.get(vendor, 'Unknown Device')

    def start_traffic_monitoring(self, filter_str: str = "ip", packet_count: int = 0):
        """
        Start monitoring network traffic

        Args:
            filter_str: BPF filter string (e.g., "tcp", "udp", "ip")
            packet_count: Number of packets to capture (0 = infinite)
        """
        if self.is_monitoring:
            logger.warning("Traffic monitoring already running")
            return

        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_traffic,
            args=(filter_str, packet_count),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Started traffic monitoring with filter: {filter_str}")

    def stop_traffic_monitoring(self):
        """Stop traffic monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Stopped traffic monitoring")

    def _monitor_traffic(self, filter_str: str, packet_count: int):
        """Monitor network traffic (runs in separate thread)"""
        try:
            if not self.interface:
                logger.error("No interface available for traffic monitoring")
                return

            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self._process_packet,
                store=False,
                count=packet_count,
                stop_filter=lambda x: not self.is_monitoring
            )
        except PermissionError:
            logger.error("Permission denied: Traffic monitoring requires administrator/root privileges")
        except Exception as e:
            logger.error(f"Traffic monitoring error: {e}")

    def _process_packet(self, packet):
        """Process captured packets"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)

                # Determine protocol
                protocol = "OTHER"
                if TCP in packet:
                    protocol = "TCP"
                elif UDP in packet:
                    protocol = "UDP"
                elif ICMP in packet:
                    protocol = "ICMP"

                # Update statistics
                with self._lock:
                    # Source IP stats
                    self.traffic_stats[src_ip]['packets_sent'] += 1
                    self.traffic_stats[src_ip]['bytes_sent'] += packet_size
                    self.traffic_stats[src_ip]['protocols'][protocol] += 1
                    self.traffic_stats[src_ip]['last_seen'] = datetime.now()

                    # Destination IP stats
                    self.traffic_stats[dst_ip]['packets_received'] += 1
                    self.traffic_stats[dst_ip]['bytes_received'] += packet_size
                    self.traffic_stats[dst_ip]['protocols'][protocol] += 1
                    self.traffic_stats[dst_ip]['last_seen'] = datetime.now()

                # Forward to enhanced traffic analyzer for ML-based detection
                try:
                    from app.utils.enhanced_traffic_analyzer import get_traffic_analyzer
                    analyzer = get_traffic_analyzer()
                    analyzer.analyze_packet(packet)
                except ImportError:
                    pass  # Enhanced analyzer not available
                except Exception as e:
                    logger.debug(f"Error in enhanced analyzer: {e}")

        except Exception as e:
            logger.debug(f"Error processing packet: {e}")

    def get_traffic_stats(self) -> Dict[str, Any]:
        """Get current traffic statistics"""
        with self._lock:
            stats = {
                'total_hosts': len(self.traffic_stats),
                'hosts': {}
            }

            for ip, data in self.traffic_stats.items():
                stats['hosts'][ip] = {
                    'packets_sent': data['packets_sent'],
                    'packets_received': data['packets_received'],
                    'bytes_sent': data['bytes_sent'],
                    'bytes_received': data['bytes_received'],
                    'protocols': dict(data['protocols']),
                    'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
                }

            return stats

    def get_cached_devices(self) -> List[Dict[str, Any]]:
        """Get cached discovered devices"""
        with self._lock:
            return list(self.devices.values())

    def scan_specific_host(self, target_ip: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Scan a specific host for open ports

        Args:
            target_ip: IP address to scan
            ports: List of ports to scan (default: common ports)

        Returns:
            Host information including open ports
        """
        if ports is None:
            # Common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]

        try:
            open_ports = []

            # Create SYN packet for each port
            for port in ports:
                pkt = IP(dst=target_ip)/TCP(dport=port, flags='S')
                resp = srp(Ether()/pkt, timeout=1, verbose=False, iface=self.interface)

                if resp and resp[0]:
                    for sent, received in resp[0]:
                        if received.haslayer(TCP) and received[TCP].flags == 0x12:  # SYN-ACK
                            open_ports.append(port)

            return {
                'ip': target_ip,
                'open_ports': open_ports,
                'total_ports_scanned': len(ports),
                'scan_time': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Host scan error for {target_ip}: {e}")
            return {'ip': target_ip, 'error': str(e)}

    def detect_network_anomalies(self) -> List[Dict[str, Any]]:
        """Detect potential network anomalies"""
        anomalies = []

        with self._lock:
            for ip, stats in self.traffic_stats.items():
                # Check for unusual traffic patterns
                if stats['packets_sent'] > 10000:
                    anomalies.append({
                        'type': 'high_traffic',
                        'ip': ip,
                        'packets': stats['packets_sent'],
                        'severity': 'medium',
                        'message': f"High packet count from {ip}"
                    })

                # Check for port scanning behavior
                if len(stats['protocols']) > 5:
                    anomalies.append({
                        'type': 'multiple_protocols',
                        'ip': ip,
                        'protocols': list(stats['protocols'].keys()),
                        'severity': 'low',
                        'message': f"Multiple protocols detected from {ip}"
                    })

        return anomalies


# Global instance
_network_manager = None


def get_network_manager() -> ScapyNetworkManager:
    """Get or create the global network manager instance"""
    global _network_manager
    if _network_manager is None:
        _network_manager = ScapyNetworkManager()
    return _network_manager
