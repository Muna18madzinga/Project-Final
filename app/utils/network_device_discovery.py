"""
Multi-Method Network Device Discovery System
Combines multiple techniques for robust device detection without requiring admin privileges
"""

import logging
import socket
import subprocess
import platform
import re
import threading
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
import netifaces

logger = logging.getLogger(__name__)


class NetworkDeviceDiscovery:
    """
    Advanced network device discovery using multiple methods:
    1. ARP table parsing (no admin required)
    2. Active pinging (ICMP)
    3. TCP connection attempts
    4. NetBIOS name resolution
    5. Passive traffic monitoring (with admin)
    """

    def __init__(self):
        self.discovered_devices = {}
        self.device_lock = threading.Lock()
        self.passive_monitoring = False
        self.system_os = platform.system()

    def discover_devices(self, methods: List[str] = None) -> List[Dict[str, Any]]:
        """
        Discover devices using multiple methods

        Args:
            methods: List of methods to use ['arp', 'ping', 'tcp', 'netbios', 'scapy']
                    If None, uses all available methods

        Returns:
            List of discovered devices
        """
        if methods is None:
            methods = ['arp', 'ping', 'tcp']

        logger.info(f"Starting device discovery with methods: {methods}")

        # Get network range
        network_range = self._get_network_range()
        if not network_range:
            logger.error("Could not determine network range")
            return []

        # Discover using multiple methods
        all_devices = {}

        if 'arp' in methods:
            arp_devices = self._discover_via_arp()
            self._merge_devices(all_devices, arp_devices)

        if 'ping' in methods:
            ping_devices = self._discover_via_ping(network_range)
            self._merge_devices(all_devices, ping_devices)

        if 'tcp' in methods:
            tcp_devices = self._discover_via_tcp(network_range)
            self._merge_devices(all_devices, tcp_devices)

        if 'netbios' in methods:
            netbios_devices = self._discover_via_netbios(network_range)
            self._merge_devices(all_devices, netbios_devices)

        if 'scapy' in methods:
            scapy_devices = self._discover_via_scapy(network_range)
            self._merge_devices(all_devices, scapy_devices)

        # Add local machine
        all_devices = self._add_local_machine(all_devices)

        # Update cache
        with self.device_lock:
            self.discovered_devices = all_devices

        devices_list = list(all_devices.values())
        logger.info(f"Discovered {len(devices_list)} unique devices")

        return devices_list

    def _get_network_range(self) -> Optional[str]:
        """Get the local network range"""
        try:
            # Get default gateway interface
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                iface = gws['default'][netifaces.AF_INET][1]

                # Get interface addresses
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip = ip_info.get('addr')
                    netmask = ip_info.get('netmask', '255.255.255.0')

                    if ip:
                        # Calculate network range
                        ip_parts = ip.split('.')
                        mask_parts = netmask.split('.')

                        network_parts = [
                            str(int(ip_parts[i]) & int(mask_parts[i]))
                            for i in range(4)
                        ]

                        cidr = sum([bin(int(x)).count('1') for x in mask_parts])
                        return '.'.join(network_parts) + f'/{cidr}'

            return None
        except Exception as e:
            logger.error(f"Error getting network range: {e}")
            return None

    def _discover_via_arp(self) -> Dict[str, Dict[str, Any]]:
        """
        Discover devices via ARP table parsing (no admin privileges required)
        This works on Windows, Linux, and macOS
        """
        devices = {}

        try:
            if self.system_os == "Windows":
                # Windows: use arp -a
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
                output = result.stdout

                # Parse output: Interface: IP on Interface
                # IP address       Physical Address      Type
                for line in output.split('\n'):
                    # Match IP and MAC address
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\s+(\w+)', line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).replace('-', ':')
                        entry_type = match.group(3)

                        # Skip broadcast, multicast, and static entries
                        if self._is_valid_device_ip(ip, mac, entry_type):
                            devices[ip] = {
                                'ip': ip,
                                'mac': mac,
                                'name': self._resolve_hostname(ip),
                                'vendor': self._get_vendor_from_mac(mac),
                                'type': self._identify_device_type(mac),
                                'status': 'online',
                                'last_seen': datetime.now().isoformat(),
                                'discovery_method': 'ARP',
                                'response_time': 'N/A'
                            }

            elif self.system_os in ["Linux", "Darwin"]:
                # Linux/Mac: use arp -an
                result = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=5)
                output = result.stdout

                # Parse output: ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
                for line in output.split('\n'):
                    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)', line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2)

                        devices[ip] = {
                            'ip': ip,
                            'mac': mac,
                            'name': self._resolve_hostname(ip),
                            'vendor': self._get_vendor_from_mac(mac),
                            'type': self._identify_device_type(mac),
                            'status': 'online',
                            'last_seen': datetime.now().isoformat(),
                            'discovery_method': 'ARP',
                            'response_time': 'N/A'
                        }

            logger.info(f"Discovered {len(devices)} devices via ARP table")

        except Exception as e:
            logger.error(f"ARP discovery error: {e}")

        return devices

    def _discover_via_ping(self, network_range: str, timeout: int = 1) -> Dict[str, Dict[str, Any]]:
        """
        Discover devices via ICMP ping sweep
        Fast ping scanning without full Scapy scan
        """
        devices = {}

        try:
            # Parse network range (e.g., 192.168.1.0/24)
            if '/' not in network_range:
                return devices

            network_ip, cidr = network_range.split('/')
            cidr = int(cidr)

            # For /24 networks, scan 1-254
            if cidr == 24:
                network_base = '.'.join(network_ip.split('.')[:-1])

                threads = []
                results = {}

                def ping_host(ip):
                    try:
                        # Use system ping command
                        if self.system_os == "Windows":
                            result = subprocess.run(
                                ['ping', '-n', '1', '-w', str(timeout * 1000), ip],
                                capture_output=True,
                                timeout=timeout + 1
                            )
                        else:
                            result = subprocess.run(
                                ['ping', '-c', '1', '-W', str(timeout), ip],
                                capture_output=True,
                                timeout=timeout + 1
                            )

                        if result.returncode == 0:
                            results[ip] = {
                                'ip': ip,
                                'mac': 'Unknown',
                                'name': self._resolve_hostname(ip),
                                'vendor': 'Unknown',
                                'type': 'Unknown Device',
                                'status': 'online',
                                'last_seen': datetime.now().isoformat(),
                                'discovery_method': 'Ping',
                                'response_time': 'N/A'
                            }
                    except Exception:
                        pass

                # Scan range 1-254 with threading
                for i in range(1, 255):
                    ip = f"{network_base}.{i}"
                    thread = threading.Thread(target=ping_host, args=(ip,))
                    thread.daemon = True
                    threads.append(thread)
                    thread.start()

                    # Limit concurrent threads
                    if len(threads) >= 50:
                        for t in threads:
                            t.join()
                        threads = []

                # Wait for remaining threads
                for t in threads:
                    t.join()

                devices = results
                logger.info(f"Discovered {len(devices)} devices via ping sweep")

        except Exception as e:
            logger.error(f"Ping discovery error: {e}")

        return devices

    def _discover_via_tcp(self, network_range: str) -> Dict[str, Dict[str, Any]]:
        """
        Discover devices via TCP connection attempts on common ports
        """
        devices = {}
        common_ports = [80, 443, 22, 445, 3389, 8080]

        try:
            if '/' not in network_range:
                return devices

            network_ip, cidr = network_range.split('/')
            cidr = int(cidr)

            if cidr == 24:
                network_base = '.'.join(network_ip.split('.')[:-1])

                for i in range(1, 255):
                    ip = f"{network_base}.{i}"

                    for port in common_ports:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.5)
                            result = sock.connect_ex((ip, port))
                            sock.close()

                            if result == 0:
                                if ip not in devices:
                                    devices[ip] = {
                                        'ip': ip,
                                        'mac': 'Unknown',
                                        'name': self._resolve_hostname(ip),
                                        'vendor': 'Unknown',
                                        'type': 'Unknown Device',
                                        'status': 'online',
                                        'last_seen': datetime.now().isoformat(),
                                        'discovery_method': 'TCP',
                                        'open_ports': [port],
                                        'response_time': 'N/A'
                                    }
                                else:
                                    devices[ip].setdefault('open_ports', []).append(port)
                                break  # Found one open port, move to next IP
                        except Exception:
                            continue

                logger.info(f"Discovered {len(devices)} devices via TCP scanning")

        except Exception as e:
            logger.error(f"TCP discovery error: {e}")

        return devices

    def _discover_via_netbios(self, network_range: str) -> Dict[str, Dict[str, Any]]:
        """
        Discover devices via NetBIOS name resolution (Windows networks)
        """
        devices = {}

        try:
            if self.system_os == "Windows":
                # Use nbtstat to discover Windows devices
                result = subprocess.run(['nbtstat', '-n'], capture_output=True, text=True, timeout=5)
                # This is limited but can help identify local Windows machines

        except Exception as e:
            logger.debug(f"NetBIOS discovery error: {e}")

        return devices

    def _discover_via_scapy(self, network_range: str) -> Dict[str, Dict[str, Any]]:
        """
        Discover devices via Scapy ARP scan (requires admin privileges)
        """
        devices = {}

        try:
            from app.utils.scapy_network_manager import get_network_manager

            manager = get_network_manager()
            scapy_devices = manager.scan_network(timeout=3)

            for device in scapy_devices:
                devices[device['ip']] = device
                devices[device['ip']]['discovery_method'] = 'Scapy'

            logger.info(f"Discovered {len(devices)} devices via Scapy")

        except PermissionError:
            logger.warning("Scapy discovery requires administrator privileges")
        except Exception as e:
            logger.debug(f"Scapy discovery error: {e}")

        return devices

    def _merge_devices(self, target: Dict, source: Dict):
        """Merge device information from multiple sources"""
        for ip, device in source.items():
            if ip in target:
                # Merge information, prefer more specific data
                if device.get('mac') and device['mac'] != 'Unknown':
                    target[ip]['mac'] = device['mac']
                if device.get('name') and device['name'] not in ['Unknown', 'N/A']:
                    target[ip]['name'] = device['name']
                if device.get('vendor') and device['vendor'] != 'Unknown':
                    target[ip]['vendor'] = device['vendor']
                if device.get('type') and device['type'] != 'Unknown Device':
                    target[ip]['type'] = device['type']
                if 'open_ports' in device:
                    target[ip].setdefault('open_ports', []).extend(device['open_ports'])

                # Add discovery method
                target[ip]['discovery_method'] = target[ip].get('discovery_method', '') + f",{device.get('discovery_method', '')}"
            else:
                target[ip] = device

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return f"Device-{ip.split('.')[-1]}"

    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor from MAC address OUI"""
        mac_upper = mac.upper()

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
            'F8:1A:67': 'TP-Link',
            '00:D0:2D': 'Cisco Systems',
            '00:1A:A0': 'Dell',
            '00:14:22': 'Dell',
            '70:B3:D5': 'Intel',
            '00:23:24': 'Amazon',
            'FC:EC:DA': 'Amazon',
        }

        oui = ':'.join(mac_upper.split(':')[:3])
        return vendors.get(oui, "Unknown")

    def _identify_device_type(self, mac: str) -> str:
        """Identify device type based on MAC address"""
        vendor = self._get_vendor_from_mac(mac)

        type_mapping = {
            'VMware': 'Virtual Machine',
            'Microsoft Hyper-V': 'Virtual Machine',
            'Microsoft': 'Computer',
            'Raspberry Pi': 'IoT Device',
            'Apple': 'Mobile/Computer',
            'Cisco': 'Network Equipment',
            'Realtek': 'Network Adapter',
            'Samsung': 'Mobile Device',
            'TP-Link': 'Network Equipment',
            'Dell': 'Computer',
            'Intel': 'Computer',
            'Amazon': 'IoT Device'
        }

        return type_mapping.get(vendor, 'Unknown Device')

    def _is_valid_device_ip(self, ip: str, mac: str, entry_type: str = 'dynamic') -> bool:
        """
        Check if an IP/MAC represents a valid network device
        Filters out broadcast, multicast, and invalid addresses
        """
        # Skip broadcast addresses
        if ip.endswith('.255') or ip == '255.255.255.255':
            return False

        # Skip multicast addresses (224.0.0.0 to 239.255.255.255)
        first_octet = int(ip.split('.')[0])
        if 224 <= first_octet <= 239:
            return False

        # Skip broadcast MAC
        if mac.lower() == 'ff:ff:ff:ff:ff:ff':
            return False

        # Skip multicast MACs (01:00:5e:...)
        if mac.lower().startswith('01:00:5e'):
            return False

        # Prefer dynamic entries over static
        if entry_type.lower() == 'static':
            return False

        return True

    def _add_local_machine(self, devices: Dict) -> Dict:
        """Add the local machine to the devices list"""
        try:
            # Get local IP and MAC
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                iface = gws['default'][netifaces.AF_INET][1]

                # Get IP address
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    local_ip = addrs[netifaces.AF_INET][0]['addr']

                    # Get MAC address
                    if netifaces.AF_LINK in addrs:
                        local_mac = addrs[netifaces.AF_LINK][0]['addr']
                    else:
                        local_mac = 'Unknown'

                    # Get hostname
                    import socket
                    hostname = socket.gethostname()

                    devices[local_ip] = {
                        'ip': local_ip,
                        'mac': local_mac,
                        'name': f'{hostname} (This Computer)',
                        'vendor': self._get_vendor_from_mac(local_mac) if local_mac != 'Unknown' else 'Local',
                        'type': 'Computer (Local)',
                        'status': 'online',
                        'last_seen': datetime.now().isoformat(),
                        'discovery_method': 'Local',
                        'response_time': 'N/A'
                    }
        except Exception as e:
            logger.debug(f"Could not add local machine: {e}")

        return devices

    def get_cached_devices(self) -> List[Dict[str, Any]]:
        """Get cached devices"""
        with self.device_lock:
            return list(self.discovered_devices.values())


# Global instance
_device_discovery = None


def get_device_discovery() -> NetworkDeviceDiscovery:
    """Get or create the global device discovery instance"""
    global _device_discovery
    if _device_discovery is None:
        _device_discovery = NetworkDeviceDiscovery()
    return _device_discovery
