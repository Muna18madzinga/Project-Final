"""
Telemetry Collection Layer - Chapter 3.3 System Architecture
Software agents for data collection from virtual endpoints, networks, and applications.
Combines inputs into Kafka-based stream for real-time processing.
"""

import logging
import asyncio
import json
import platform
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, AsyncGenerator
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import threading
import queue
from scapy.all import sniff, IP, TCP, UDP, conf, get_if_list  # type: ignore[import]
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

@dataclass
class TelemetryData:
    """Telemetry data structure for collected metrics."""
    source: str
    timestamp: datetime
    data_type: str
    payload: Dict[str, Any]
    metadata: Dict[str, Any]
    risk_indicators: List[str]

class NetworkTelemetryAgent:
    """Network traffic monitoring agent using software-based collection."""

    def __init__(self, interface: str = "any"):
        self.interface = interface
        self.is_running = False
        self.packet_buffer = deque(maxlen=10000)
        self.flow_tracker = defaultdict(dict)
        self.collection_thread = None
        self._resolved_interface: Optional[str] = None

    def start_collection(self):
        """Start network telemetry collection."""
        if self.is_running:
            return

        resolved = self._resolve_interface()
        if not resolved:
            logger.warning(
                "Network telemetry disabled: no suitable interface could be resolved for capture"
            )
            return

        self._resolved_interface = resolved
        self.is_running = True
        self.collection_thread = threading.Thread(target=self._collect_network_data)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        logger.info(
            "Network telemetry collection started on interface: %s",
            self._resolved_interface,
        )

    def stop_collection(self):
        """Stop network telemetry collection."""
        self.is_running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("Network telemetry collection stopped")

    def _collect_network_data(self):
        """Collect network packet data."""
        try:
            # Use scapy for packet capture in software simulation mode
            sniff(
                iface=self._resolved_interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_running,
                timeout=1
            )
        except Exception as e:
            logger.error(f"Network collection error: {e}")
            logger.debug("Network collection failure details", exc_info=e)
            self.is_running = False

    def _process_packet(self, packet):
        """Process captured network packet."""
        try:
            if IP in packet:
                ip_layer = packet[IP]

                # Extract flow information
                flow_key = f"{ip_layer.src}:{ip_layer.dst}"

                # Basic packet features
                packet_data = {
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'packet_size': len(packet),
                    'ttl': ip_layer.ttl,
                    'flags': ip_layer.flags if hasattr(ip_layer, 'flags') else 0,
                }

                # Transport layer information
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_data.update({
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'tcp_flags': tcp_layer.flags,
                        'tcp_window': tcp_layer.window,
                    })
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_data.update({
                        'src_port': udp_layer.sport,
                        'dst_port': udp_layer.dport,
                    })

                # Update flow tracking
                self._update_flow_stats(flow_key, packet_data)

                # Create telemetry data
                telemetry = TelemetryData(
                    source="network_agent",
                    timestamp=datetime.now(),
                    data_type="network_packet",
                    payload=packet_data,
                    metadata={
                        'interface': self.interface,
                        'flow_key': flow_key,
                    },
                    risk_indicators=self._detect_packet_anomalies(packet_data)
                )

                self.packet_buffer.append(telemetry)

        except Exception as e:
            logger.error(f"Packet processing error: {e}")

    def _update_flow_stats(self, flow_key: str, packet_data: Dict):
        """Update flow statistics for network behavior analysis."""
        flow = self.flow_tracker[flow_key]

        if 'packet_count' not in flow:
            flow['packet_count'] = 0
            flow['bytes_total'] = 0
            flow['first_seen'] = datetime.now()
            flow['protocol_distribution'] = defaultdict(int)

        flow['packet_count'] += 1
        flow['bytes_total'] += packet_data['packet_size']
        flow['last_seen'] = datetime.now()
        flow['protocol_distribution'][packet_data['protocol']] += 1

    def _detect_packet_anomalies(self, packet_data: Dict) -> List[str]:
        """Detect anomalies in packet data."""
        anomalies = []

        # Large packet size
        if packet_data['packet_size'] > 9000:
            anomalies.append("oversized_packet")

        # Suspicious ports
        suspicious_ports = {22, 23, 135, 139, 445, 1433, 3389, 5900}
        if packet_data.get('dst_port') in suspicious_ports:
            anomalies.append("suspicious_port_access")

        # Private IP to public IP communication patterns
        src_ip = packet_data['src_ip']
        dst_ip = packet_data['dst_ip']

        if (src_ip.startswith('192.168.') or src_ip.startswith('10.') or
            src_ip.startswith('172.')):
            if not (dst_ip.startswith('192.168.') or dst_ip.startswith('10.') or
                   dst_ip.startswith('172.')):
                anomalies.append("internal_to_external_communication")

        return anomalies

    def get_telemetry_batch(self, batch_size: int = 100) -> List[TelemetryData]:
        """Get batch of telemetry data."""
        batch = []
        for _ in range(min(batch_size, len(self.packet_buffer))):
            if self.packet_buffer:
                batch.append(self.packet_buffer.popleft())
        return batch

    def _resolve_interface(self) -> Optional[str]:
        """Determine the appropriate network interface for packet capture."""
        requested = (self.interface or "").strip().lower()

        if requested and requested not in {"any", "auto"}:
            return self.interface

        system = platform.system()

        try:
            if system == "Windows":
                # On Windows, scapy defaults to the primary WinPcap/Npcap interface.
                if conf.iface:
                    return conf.iface

                # Fallback to first available adapter if default not set.
                interfaces = get_if_list()
                if interfaces:
                    return interfaces[0]

            else:
                # Non-Windows platforms support the special "any" interface.
                return "any"
        except Exception as exc:
            logger.debug("Failed to resolve network interface automatically: %s", exc)

        return None

class EndpointTelemetryAgent:
    """Endpoint monitoring agent for system and application telemetry."""

    def __init__(self):
        self.is_running = False
        self.collection_interval = 5.0  # seconds
        self.telemetry_buffer = deque(maxlen=5000)
        self.collection_thread = None

    def start_collection(self):
        """Start endpoint telemetry collection."""
        if self.is_running:
            return

        self.is_running = True
        self.collection_thread = threading.Thread(target=self._collect_endpoint_data)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        logger.info("Endpoint telemetry collection started")

    def stop_collection(self):
        """Stop endpoint telemetry collection."""
        self.is_running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("Endpoint telemetry collection stopped")

    def _collect_endpoint_data(self):
        """Collect endpoint system metrics."""
        while self.is_running:
            try:
                # Simulate system metrics collection
                system_metrics = self._collect_system_metrics()
                process_metrics = self._collect_process_metrics()
                security_events = self._collect_security_events()

                # Create telemetry entries
                for metrics, data_type in [
                    (system_metrics, "system_metrics"),
                    (process_metrics, "process_metrics"),
                    (security_events, "security_events")
                ]:
                    if metrics:
                        telemetry = TelemetryData(
                            source="endpoint_agent",
                            timestamp=datetime.now(),
                            data_type=data_type,
                            payload=metrics,
                            metadata={
                                'hostname': 'virtual_endpoint',
                                'agent_version': '1.0.0'
                            },
                            risk_indicators=self._detect_endpoint_anomalies(metrics, data_type)
                        )
                        self.telemetry_buffer.append(telemetry)

                time.sleep(self.collection_interval)

            except Exception as e:
                logger.error(f"Endpoint collection error: {e}")
                time.sleep(self.collection_interval)

    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system performance metrics."""
        # Simulate system metrics
        return {
            'cpu_usage': np.random.uniform(0.1, 0.9),
            'memory_usage': np.random.uniform(0.2, 0.8),
            'disk_io_read': np.random.uniform(100, 10000),
            'disk_io_write': np.random.uniform(50, 5000),
            'network_connections': np.random.randint(10, 200),
            'uptime': np.random.uniform(3600, 2592000),  # 1 hour to 30 days
        }

    def _collect_process_metrics(self) -> Dict[str, Any]:
        """Collect process-level metrics."""
        # Simulate process metrics
        return {
            'active_processes': np.random.randint(50, 300),
            'suspicious_processes': np.random.randint(0, 5),
            'new_processes': np.random.randint(0, 10),
            'process_network_activity': np.random.uniform(0, 100),
            'privilege_escalations': np.random.randint(0, 2),
        }

    def _collect_security_events(self) -> Dict[str, Any]:
        """Collect security-related events."""
        # Simulate security events
        event_types = ['login_attempt', 'file_access', 'registry_modification',
                      'network_connection', 'process_creation']

        return {
            'total_events': np.random.randint(100, 1000),
            'failed_logins': np.random.randint(0, 20),
            'suspicious_file_access': np.random.randint(0, 10),
            'registry_changes': np.random.randint(0, 50),
            'outbound_connections': np.random.randint(5, 100),
            'event_distribution': {
                event_type: np.random.randint(0, 100)
                for event_type in event_types
            }
        }

    def _detect_endpoint_anomalies(self, metrics: Dict, data_type: str) -> List[str]:
        """Detect anomalies in endpoint metrics."""
        anomalies = []

        if data_type == "system_metrics":
            if metrics.get('cpu_usage', 0) > 0.9:
                anomalies.append("high_cpu_usage")
            if metrics.get('memory_usage', 0) > 0.9:
                anomalies.append("high_memory_usage")
            if metrics.get('network_connections', 0) > 500:
                anomalies.append("excessive_network_connections")

        elif data_type == "process_metrics":
            if metrics.get('suspicious_processes', 0) > 0:
                anomalies.append("suspicious_processes_detected")
            if metrics.get('privilege_escalations', 0) > 0:
                anomalies.append("privilege_escalation_detected")

        elif data_type == "security_events":
            if metrics.get('failed_logins', 0) > 10:
                anomalies.append("excessive_failed_logins")
            if metrics.get('suspicious_file_access', 0) > 5:
                anomalies.append("suspicious_file_access")

        return anomalies

    def get_telemetry_batch(self, batch_size: int = 100) -> List[TelemetryData]:
        """Get batch of telemetry data."""
        batch = []
        for _ in range(min(batch_size, len(self.telemetry_buffer))):
            if self.telemetry_buffer:
                batch.append(self.telemetry_buffer.popleft())
        return batch

class TelemetryStreamProcessor:
    """Kafka-like stream processor for real-time telemetry ingestion."""

    def __init__(self):
        self.stream_buffer = queue.Queue(maxsize=100000)
        self.subscribers = []
        self.is_running = False
        self.processing_thread = None

        # Initialize agents
        self.network_agent = NetworkTelemetryAgent()
        self.endpoint_agent = EndpointTelemetryAgent()

    def start_stream_processing(self):
        """Start telemetry stream processing."""
        if self.is_running:
            return

        self.is_running = True

        # Start collection agents
        self.network_agent.start_collection()
        self.endpoint_agent.start_collection()

        # Start stream processing
        self.processing_thread = threading.Thread(target=self._process_telemetry_stream)
        self.processing_thread.daemon = True
        self.processing_thread.start()

        logger.info("Telemetry stream processing started")

    def stop_stream_processing(self):
        """Stop telemetry stream processing."""
        self.is_running = False

        # Stop collection agents
        self.network_agent.stop_collection()
        self.endpoint_agent.stop_collection()

        # Stop processing thread
        if self.processing_thread:
            self.processing_thread.join(timeout=5)

        logger.info("Telemetry stream processing stopped")

    def _process_telemetry_stream(self):
        """Process incoming telemetry data stream."""
        while self.is_running:
            try:
                # Collect data from agents
                network_batch = self.network_agent.get_telemetry_batch(50)
                endpoint_batch = self.endpoint_agent.get_telemetry_batch(50)

                # Process batches
                all_telemetry = network_batch + endpoint_batch

                for telemetry in all_telemetry:
                    # Add to stream buffer
                    if not self.stream_buffer.full():
                        self.stream_buffer.put(telemetry)

                    # Notify subscribers
                    self._notify_subscribers(telemetry)

                time.sleep(0.1)  # Process every 100ms

            except Exception as e:
                logger.error(f"Stream processing error: {e}")
                time.sleep(1)

    def _notify_subscribers(self, telemetry: TelemetryData):
        """Notify all subscribers of new telemetry data."""
        for subscriber in self.subscribers:
            try:
                subscriber(telemetry)
            except Exception as e:
                logger.error(f"Subscriber notification error: {e}")

    def subscribe(self, callback_func):
        """Subscribe to telemetry stream."""
        self.subscribers.append(callback_func)
        logger.info(f"New subscriber added: {callback_func.__name__}")

    def get_stream_data(self, timeout: float = 1.0) -> Optional[TelemetryData]:
        """Get data from telemetry stream."""
        try:
            return self.stream_buffer.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stream_batch(self, batch_size: int = 100, timeout: float = 5.0) -> List[TelemetryData]:
        """Get batch of data from telemetry stream."""
        batch = []
        end_time = time.time() + timeout

        while len(batch) < batch_size and time.time() < end_time:
            telemetry = self.get_stream_data(timeout=0.1)
            if telemetry:
                batch.append(telemetry)

        return batch

    def get_telemetry_stats(self) -> Dict[str, Any]:
        """Get telemetry collection statistics."""
        return {
            'stream_buffer_size': self.stream_buffer.qsize(),
            'max_buffer_size': self.stream_buffer.maxsize,
            'subscribers_count': len(self.subscribers),
            'network_agent_running': self.network_agent.is_running,
            'endpoint_agent_running': self.endpoint_agent.is_running,
            'processing_active': self.is_running,
            'network_buffer_size': len(self.network_agent.packet_buffer),
            'endpoint_buffer_size': len(self.endpoint_agent.telemetry_buffer),
        }

# Global telemetry processor instance
_telemetry_processor = None

def get_telemetry_processor() -> TelemetryStreamProcessor:
    """Get global telemetry stream processor instance."""
    global _telemetry_processor
    if _telemetry_processor is None:
        _telemetry_processor = TelemetryStreamProcessor()
    return _telemetry_processor
