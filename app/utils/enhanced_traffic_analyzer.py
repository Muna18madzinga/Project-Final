"""
Enhanced Traffic Analyzer with ML-based Threat Detection
Integrated from unified-ids-and-iot-security-system repository
"""

import time
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional
from threading import Lock
from scapy.all import IP, TCP, UDP, ICMP

logger = logging.getLogger(__name__)


class DeviceProfile:
    """Profile for tracking device behavior"""

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = time.time()
        self.last_seen = time.time()
        self.protocols = defaultdict(int)
        self.connections = set()
        self.suspicious_activity = []

    def update(self, packet_size: int, protocol: str, dst_ip: str = None):
        """Update device profile with new packet"""
        self.packet_count += 1
        self.byte_count += packet_size
        self.last_seen = time.time()
        self.protocols[protocol] += 1

        if dst_ip:
            self.connections.add(dst_ip)

    def get_packet_rate(self) -> float:
        """Calculate packets per second"""
        duration = time.time() - self.start_time
        return self.packet_count / duration if duration > 0 else 0

    def detect_anomaly(self) -> Optional[str]:
        """Detect suspicious behavior patterns"""
        packet_rate = self.get_packet_rate()

        # High packet rate (potential DoS)
        if packet_rate > 100:
            return f"High packet rate: {packet_rate:.2f} pkt/s"

        # Port scanning behavior (many unique connections)
        if len(self.connections) > 50:
            return f"Port scanning detected: {len(self.connections)} unique connections"

        # Protocol diversity (potential reconnaissance)
        if len(self.protocols) > 5:
            return f"Multiple protocols: {list(self.protocols.keys())}"

        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary"""
        return {
            'device_id': self.device_id,
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'packet_rate': self.get_packet_rate(),
            'duration': time.time() - self.start_time,
            'protocols': dict(self.protocols),
            'unique_connections': len(self.connections),
            'last_seen': datetime.fromtimestamp(self.last_seen).isoformat(),
            'suspicious_activity': self.suspicious_activity
        }


class FlowTracker:
    """Track network flows for analysis"""

    def __init__(self):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'bytes': 0,
            'protocol': None,
            'flags': set()
        })
        self.lock = Lock()

    def add_packet(self, key: tuple, packet, packet_size: int, protocol: str):
        """Add packet to flow"""
        with self.lock:
            flow = self.flows[key]

            if flow['start_time'] is None:
                flow['start_time'] = time.time()

            flow['packets'].append(packet)
            flow['bytes'] += packet_size
            flow['protocol'] = protocol

            # Track TCP flags
            if TCP in packet:
                flow['flags'].add(str(packet[TCP].flags))

    def get_flow(self, key: tuple) -> Dict[str, Any]:
        """Get flow information"""
        with self.lock:
            return self.flows.get(key, {})

    def get_all_flows(self) -> List[Dict[str, Any]]:
        """Get all active flows"""
        with self.lock:
            flows_list = []
            for key, flow in self.flows.items():
                if flow['start_time']:
                    duration = time.time() - flow['start_time']
                    flows_list.append({
                        'src_ip': key[0],
                        'dst_ip': key[1],
                        'src_port': key[2],
                        'protocol': flow['protocol'],
                        'packets': len(flow['packets']),
                        'bytes': flow['bytes'],
                        'duration': duration,
                        'packet_rate': len(flow['packets']) / duration if duration > 0 else 0,
                        'flags': list(flow['flags'])
                    })
            return flows_list

    def cleanup_old_flows(self, max_age: int = 300):
        """Remove flows older than max_age seconds"""
        with self.lock:
            current_time = time.time()
            keys_to_remove = []

            for key, flow in self.flows.items():
                if flow['start_time'] and (current_time - flow['start_time']) > max_age:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.flows[key]

            if keys_to_remove:
                logger.info(f"Cleaned up {len(keys_to_remove)} old flows")


class EnhancedTrafficAnalyzer:
    """Enhanced traffic analyzer with threat detection"""

    def __init__(self):
        self.device_profiles = {}
        self.flow_tracker = FlowTracker()
        self.alerts = []
        self.statistics = {
            'total_packets': 0,
            'total_bytes': 0,
            'packets_by_protocol': defaultdict(int),
            'alerts_count': 0,
            'start_time': time.time()
        }
        self.lock = Lock()

    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze a packet and update statistics"""
        try:
            if IP not in packet:
                return None

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)

            # Determine protocol
            protocol = "OTHER"
            sport = 0
            dport = 0

            if TCP in packet:
                protocol = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"

            # Update global statistics
            with self.lock:
                self.statistics['total_packets'] += 1
                self.statistics['total_bytes'] += packet_size
                self.statistics['packets_by_protocol'][protocol] += 1

            # Update device profiles
            self._update_device_profile(src_ip, packet_size, protocol, dst_ip)

            # Track flow
            flow_key = (src_ip, dst_ip, sport, packet[IP].proto)
            self.flow_tracker.add_packet(flow_key, packet, packet_size, protocol)

            # Check for anomalies every 10 packets
            if self.statistics['total_packets'] % 10 == 0:
                self._check_anomalies(src_ip)

            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'size': packet_size,
                'timestamp': time.time()
            }

        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
            return None

    def _update_device_profile(self, device_id: str, packet_size: int,
                               protocol: str, dst_ip: str = None):
        """Update or create device profile"""
        with self.lock:
            if device_id not in self.device_profiles:
                self.device_profiles[device_id] = DeviceProfile(device_id)

            self.device_profiles[device_id].update(packet_size, protocol, dst_ip)

    def _check_anomalies(self, device_id: str):
        """Check for anomalies in device behavior"""
        with self.lock:
            if device_id not in self.device_profiles:
                return

            profile = self.device_profiles[device_id]
            anomaly = profile.detect_anomaly()

            if anomaly:
                alert = {
                    'type': 'anomaly',
                    'device_id': device_id,
                    'description': anomaly,
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'medium',
                    'packet_count': profile.packet_count,
                    'byte_count': profile.byte_count
                }

                self.alerts.append(alert)
                profile.suspicious_activity.append(anomaly)
                self.statistics['alerts_count'] += 1

                logger.warning(f"Anomaly detected for {device_id}: {anomaly}")

    def get_device_profiles(self) -> List[Dict[str, Any]]:
        """Get all device profiles"""
        with self.lock:
            return [profile.to_dict() for profile in self.device_profiles.values()]

    def get_device_profile(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get specific device profile"""
        with self.lock:
            profile = self.device_profiles.get(device_id)
            return profile.to_dict() if profile else None

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        with self.lock:
            return self.alerts[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get traffic statistics"""
        with self.lock:
            duration = time.time() - self.statistics['start_time']
            return {
                'total_packets': self.statistics['total_packets'],
                'total_bytes': self.statistics['total_bytes'],
                'packets_by_protocol': dict(self.statistics['packets_by_protocol']),
                'alerts_count': self.statistics['alerts_count'],
                'duration': duration,
                'packet_rate': self.statistics['total_packets'] / duration if duration > 0 else 0,
                'byte_rate': self.statistics['total_bytes'] / duration if duration > 0 else 0,
                'devices_tracked': len(self.device_profiles)
            }

    def get_flows(self) -> List[Dict[str, Any]]:
        """Get all active flows"""
        return self.flow_tracker.get_all_flows()

    def cleanup(self):
        """Cleanup old data"""
        self.flow_tracker.cleanup_old_flows()

        # Remove inactive devices (not seen in 10 minutes)
        with self.lock:
            current_time = time.time()
            devices_to_remove = []

            for device_id, profile in self.device_profiles.items():
                if (current_time - profile.last_seen) > 600:
                    devices_to_remove.append(device_id)

            for device_id in devices_to_remove:
                del self.device_profiles[device_id]

            if devices_to_remove:
                logger.info(f"Removed {len(devices_to_remove)} inactive devices")


# Global analyzer instance
_traffic_analyzer = None


def get_traffic_analyzer() -> EnhancedTrafficAnalyzer:
    """Get or create the global traffic analyzer instance"""
    global _traffic_analyzer
    if _traffic_analyzer is None:
        _traffic_analyzer = EnhancedTrafficAnalyzer()
    return _traffic_analyzer
