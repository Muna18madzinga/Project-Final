"""
Real Data Integration Module
Central coordinator for all live data sources, replacing simulated data throughout the system
"""

import logging
import asyncio
import threading
import time
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from collections import deque, defaultdict

from .live_network_collector import get_real_network_collector, RealNetworkEvent, SystemMetrics
from .threat_intel_feeds import get_threat_intel_feeds, ThreatIndicator

logger = logging.getLogger(__name__)

@dataclass
class RealDataEvent:
    """Unified real data event structure."""
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    data: Dict[str, Any]
    threat_score: float
    threat_indicators: List[str]
    enrichment: Dict[str, Any]

class RealDataIntegrator:
    """Central coordinator for all real data sources."""
    
    def __init__(self):
        self.is_running = False
        self.network_collector = get_real_network_collector()
        self.threat_intel = get_threat_intel_feeds()
        
        # Event processing
        self.event_buffer = deque(maxlen=100000)
        self.event_subscribers = []
        self.processing_thread = None
        self.enrichment_thread = None
        
        # Real-time statistics
        self.stats = {
            'events_processed': 0,
            'events_enriched': 0,
            'threat_matches': 0,
            'high_risk_events': 0,
            'start_time': None,
            'last_event_time': None
        }
        
        # Configuration
        self.enrichment_enabled = True
        self.threat_scoring_enabled = True
        self.export_enabled = True

    def start_real_data_collection(self, config: Dict[str, Any] = None):
        """Start all real data collection processes."""
        if self.is_running:
            logger.warning("Real data collection already running")
            return
        
        self.is_running = True
        self.stats['start_time'] = datetime.now(timezone.utc)
        
        # Start network collection
        self.network_collector.start_collection()
        
        # Start threat intelligence collection
        api_keys = config.get('api_keys', {}) if config else {}
        self.threat_intel.start_collection(api_keys)
        
        # Start event processing
        self.processing_thread = threading.Thread(target=self._event_processing_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        # Start enrichment processing
        if self.enrichment_enabled:
            self.enrichment_thread = threading.Thread(target=self._enrichment_loop)
            self.enrichment_thread.daemon = True
            self.enrichment_thread.start()
        
        logger.info("Real data collection started successfully")
        
        # Log initial status
        self._log_collection_status()

    def stop_real_data_collection(self):
        """Stop all real data collection processes."""
        self.is_running = False
        
        # Stop collectors
        self.network_collector.stop_collection()
        self.threat_intel.stop_collection()
        
        # Stop processing threads
        if self.processing_thread:
            self.processing_thread.join(timeout=10)
        if self.enrichment_thread:
            self.enrichment_thread.join(timeout=10)
        
        logger.info("Real data collection stopped")
        self._log_final_statistics()

    def _event_processing_loop(self):
        """Main event processing loop."""
        while self.is_running:
            try:
                # Collect network events
                network_events = self.network_collector.get_real_data_batch(50)
                for net_event in network_events:
                    real_event = self._convert_network_event(net_event)
                    self._process_real_event(real_event)
                
                # Collect system metrics
                system_metrics = self.network_collector.system_metrics_collector.get_metrics_batch(10)
                for sys_metric in system_metrics:
                    real_event = self._convert_system_metrics(sys_metric)
                    self._process_real_event(real_event)
                
                time.sleep(0.1)  # Process every 100ms
                
            except Exception as e:
                logger.error(f"Event processing error: {e}")
                time.sleep(1)

    def _enrichment_loop(self):
        """Event enrichment processing loop."""
        while self.is_running:
            try:
                # Process events in buffer for enrichment
                events_to_enrich = []
                
                # Get up to 20 events for enrichment
                for _ in range(min(20, len(self.event_buffer))):
                    if self.event_buffer:
                        event = self.event_buffer.popleft()
                        events_to_enrich.append(event)
                
                # Enrich each event
                for event in events_to_enrich:
                    enriched_event = self._enrich_event(event)
                    self._notify_subscribers(enriched_event)
                    self.stats['events_enriched'] += 1
                
                time.sleep(0.5)  # Enrich every 500ms
                
            except Exception as e:
                logger.error(f"Enrichment processing error: {e}")
                time.sleep(1)

    def _convert_network_event(self, net_event: RealNetworkEvent) -> RealDataEvent:
        """Convert network event to unified format."""
        event_id = f"net_{hash(net_event.flow_id)}_{int(net_event.timestamp.timestamp())}"
        
        # Calculate basic threat score
        threat_score = self._calculate_network_threat_score(net_event)
        
        return RealDataEvent(
            event_id=event_id,
            timestamp=net_event.timestamp,
            source="network",
            event_type="network_traffic",
            data={
                'source_ip': net_event.source_ip,
                'dest_ip': net_event.dest_ip,
                'source_port': net_event.source_port,
                'dest_port': net_event.dest_port,
                'protocol': net_event.protocol,
                'packet_size': net_event.packet_size,
                'flags': net_event.flags,
                'payload_snippet': net_event.payload_snippet,
                'flow_id': net_event.flow_id
            },
            threat_score=threat_score,
            threat_indicators=net_event.threat_indicators,
            enrichment={}
        )

    def _convert_system_metrics(self, sys_metrics: SystemMetrics) -> RealDataEvent:
        """Convert system metrics to unified format."""
        event_id = f"sys_{int(sys_metrics.timestamp.timestamp())}"
        
        # Calculate system threat score
        threat_score = self._calculate_system_threat_score(sys_metrics)
        threat_indicators = self._analyze_system_threats(sys_metrics)
        
        return RealDataEvent(
            event_id=event_id,
            timestamp=sys_metrics.timestamp,
            source="system",
            event_type="system_metrics",
            data={
                'cpu_percent': sys_metrics.cpu_percent,
                'memory_percent': sys_metrics.memory_percent,
                'disk_io_read': sys_metrics.disk_io_read,
                'disk_io_write': sys_metrics.disk_io_write,
                'network_bytes_sent': sys_metrics.network_bytes_sent,
                'network_bytes_recv': sys_metrics.network_bytes_recv,
                'active_connections': sys_metrics.active_connections,
                'processes_count': sys_metrics.processes_count,
                'load_average': sys_metrics.load_average
            },
            threat_score=threat_score,
            threat_indicators=threat_indicators,
            enrichment={}
        )

    def _calculate_network_threat_score(self, net_event: RealNetworkEvent) -> float:
        """Calculate threat score for network events."""
        score = 0.0
        
        # Base score from existing threat indicators
        score += len(net_event.threat_indicators) * 0.2
        
        # Port-based scoring
        if net_event.dest_port:
            high_risk_ports = {22, 23, 135, 139, 445, 1433, 3389, 5900}
            if net_event.dest_port in high_risk_ports:
                score += 0.3
        
        # Size-based scoring
        if net_event.packet_size > 1500:
            score += 0.1
        if net_event.packet_size > 9000:
            score += 0.2
        
        # Payload-based scoring
        if net_event.payload_snippet:
            suspicious_patterns = ['admin', 'password', 'login', 'cmd', 'powershell']
            for pattern in suspicious_patterns:
                if pattern in net_event.payload_snippet.lower():
                    score += 0.1
        
        # Geographic scoring (if available)
        if net_event.geo_location:
            threat_level = net_event.geo_location.get('threat_level', 'low')
            if threat_level == 'high':
                score += 0.4
            elif threat_level == 'moderate':
                score += 0.2
        
        return min(score, 1.0)

    def _calculate_system_threat_score(self, sys_metrics: SystemMetrics) -> float:
        """Calculate threat score for system metrics."""
        score = 0.0
        
        # CPU usage scoring
        if sys_metrics.cpu_percent > 90:
            score += 0.3
        elif sys_metrics.cpu_percent > 70:
            score += 0.1
        
        # Memory usage scoring
        if sys_metrics.memory_percent > 95:
            score += 0.3
        elif sys_metrics.memory_percent > 80:
            score += 0.1
        
        # Connection count scoring
        if sys_metrics.active_connections > 1000:
            score += 0.2
        elif sys_metrics.active_connections > 500:
            score += 0.1
        
        # Process count scoring
        if sys_metrics.processes_count > 500:
            score += 0.1
        
        # Load average scoring (Unix/Linux systems)
        if len(sys_metrics.load_average) > 0 and sys_metrics.load_average[0] > 5.0:
            score += 0.2
        
        return min(score, 1.0)

    def _analyze_system_threats(self, sys_metrics: SystemMetrics) -> List[str]:
        """Analyze system metrics for threat indicators."""
        threats = []
        
        if sys_metrics.cpu_percent > 90:
            threats.append('high_cpu_usage')
        
        if sys_metrics.memory_percent > 95:
            threats.append('high_memory_usage')
        
        if sys_metrics.active_connections > 1000:
            threats.append('excessive_connections')
        
        if sys_metrics.processes_count > 500:
            threats.append('high_process_count')
        
        # Detect potential crypto mining (high CPU + network activity)
        if (sys_metrics.cpu_percent > 80 and 
            sys_metrics.network_bytes_sent > 1000000):
            threats.append('possible_crypto_mining')
        
        return threats

    def _process_real_event(self, event: RealDataEvent):
        """Process a real data event."""
        try:
            # Update statistics
            self.stats['events_processed'] += 1
            self.stats['last_event_time'] = event.timestamp
            
            # Check threat score
            if event.threat_score > 0.7:
                self.stats['high_risk_events'] += 1
            
            # Add to processing buffer
            self.event_buffer.append(event)
            
        except Exception as e:
            logger.error(f"Error processing event {event.event_id}: {e}")

    def _enrich_event(self, event: RealDataEvent) -> RealDataEvent:
        """Enrich event with threat intelligence and additional context."""
        try:
            enrichment = {}
            
            # Network event enrichment
            if event.event_type == "network_traffic":
                enrichment.update(self._enrich_network_event(event))
            
            # System event enrichment
            elif event.event_type == "system_metrics":
                enrichment.update(self._enrich_system_event(event))
            
            # Update event enrichment
            event.enrichment = enrichment
            
            # Recalculate threat score with enrichment
            if enrichment.get('threat_intel_matches'):
                event.threat_score = min(event.threat_score + 0.3, 1.0)
                self.stats['threat_matches'] += 1
            
            return event
            
        except Exception as e:
            logger.error(f"Error enriching event {event.event_id}: {e}")
            return event

    def _enrich_network_event(self, event: RealDataEvent) -> Dict[str, Any]:
        """Enrich network events with threat intelligence."""
        enrichment = {}
        
        try:
            data = event.data
            
            # Check source IP against threat intel
            source_ip_matches = self.threat_intel.check_indicator(data['source_ip'], 'ip')
            if source_ip_matches:
                enrichment['source_ip_threat_intel'] = [
                    {
                        'threat_type': match.threat_type,
                        'confidence': match.confidence,
                        'source': match.source,
                        'tags': match.tags
                    }
                    for match in source_ip_matches
                ]
            
            # Check destination IP against threat intel
            dest_ip_matches = self.threat_intel.check_indicator(data['dest_ip'], 'ip')
            if dest_ip_matches:
                enrichment['dest_ip_threat_intel'] = [
                    {
                        'threat_type': match.threat_type,
                        'confidence': match.confidence,
                        'source': match.source,
                        'tags': match.tags
                    }
                    for match in dest_ip_matches
                ]
            
            # Port analysis
            if data.get('dest_port'):
                enrichment['port_analysis'] = self._analyze_port(data['dest_port'])
            
            # Protocol analysis
            enrichment['protocol_analysis'] = self._analyze_protocol(data['protocol'])
            
            # Mark if any threat intel matches found
            enrichment['threat_intel_matches'] = bool(source_ip_matches or dest_ip_matches)
            
        except Exception as e:
            logger.debug(f"Network enrichment error: {e}")
        
        return enrichment

    def _enrich_system_event(self, event: RealDataEvent) -> Dict[str, Any]:
        """Enrich system events with behavioral analysis."""
        enrichment = {}
        
        try:
            data = event.data
            
            # CPU analysis
            enrichment['cpu_analysis'] = {
                'level': self._categorize_cpu_usage(data['cpu_percent']),
                'anomaly': data['cpu_percent'] > 90
            }
            
            # Memory analysis
            enrichment['memory_analysis'] = {
                'level': self._categorize_memory_usage(data['memory_percent']),
                'anomaly': data['memory_percent'] > 95
            }
            
            # Network activity analysis
            enrichment['network_analysis'] = {
                'bytes_sent': data['network_bytes_sent'],
                'bytes_recv': data['network_bytes_recv'],
                'high_activity': (data['network_bytes_sent'] + data['network_bytes_recv']) > 1000000
            }
            
            # Connection analysis
            enrichment['connection_analysis'] = {
                'count': data['active_connections'],
                'level': self._categorize_connection_count(data['active_connections'])
            }
            
        except Exception as e:
            logger.debug(f"System enrichment error: {e}")
        
        return enrichment

    def _analyze_port(self, port: int) -> Dict[str, Any]:
        """Analyze port for threat indicators."""
        port_info = {
            22: {'service': 'SSH', 'risk': 'medium', 'description': 'Secure Shell - common brute force target'},
            23: {'service': 'Telnet', 'risk': 'high', 'description': 'Unencrypted remote access'},
            80: {'service': 'HTTP', 'risk': 'low', 'description': 'Web traffic'},
            443: {'service': 'HTTPS', 'risk': 'low', 'description': 'Secure web traffic'},
            135: {'service': 'RPC', 'risk': 'high', 'description': 'Windows RPC - exploit target'},
            139: {'service': 'NetBIOS', 'risk': 'medium', 'description': 'NetBIOS session service'},
            445: {'service': 'SMB', 'risk': 'high', 'description': 'SMB file sharing - common attack vector'},
            1433: {'service': 'MSSQL', 'risk': 'medium', 'description': 'Microsoft SQL Server'},
            3389: {'service': 'RDP', 'risk': 'high', 'description': 'Remote Desktop - brute force target'},
            5900: {'service': 'VNC', 'risk': 'medium', 'description': 'VNC remote desktop'}
        }
        
        return port_info.get(port, {
            'service': 'Unknown',
            'risk': 'low',
            'description': f'Port {port}'
        })

    def _analyze_protocol(self, protocol: str) -> Dict[str, Any]:
        """Analyze protocol for characteristics."""
        protocol_info = {
            'tcp': {'description': 'Transmission Control Protocol', 'reliability': 'high'},
            'udp': {'description': 'User Datagram Protocol', 'reliability': 'low'},
            'icmp': {'description': 'Internet Control Message Protocol', 'reliability': 'medium'}
        }
        
        return protocol_info.get(protocol.lower(), {
            'description': f'Protocol {protocol}',
            'reliability': 'unknown'
        })

    def _categorize_cpu_usage(self, cpu_percent: float) -> str:
        """Categorize CPU usage level."""
        if cpu_percent > 90:
            return 'critical'
        elif cpu_percent > 70:
            return 'high'
        elif cpu_percent > 50:
            return 'medium'
        else:
            return 'low'

    def _categorize_memory_usage(self, memory_percent: float) -> str:
        """Categorize memory usage level."""
        if memory_percent > 95:
            return 'critical'
        elif memory_percent > 80:
            return 'high'
        elif memory_percent > 60:
            return 'medium'
        else:
            return 'low'

    def _categorize_connection_count(self, connections: int) -> str:
        """Categorize connection count level."""
        if connections > 1000:
            return 'critical'
        elif connections > 500:
            return 'high'
        elif connections > 200:
            return 'medium'
        else:
            return 'low'

    def _notify_subscribers(self, event: RealDataEvent):
        """Notify all event subscribers."""
        for subscriber in self.event_subscribers:
            try:
                subscriber(event)
            except Exception as e:
                logger.error(f"Subscriber notification error: {e}")

    def subscribe_to_events(self, callback: Callable[[RealDataEvent], None]):
        """Subscribe to real data events."""
        self.event_subscribers.append(callback)
        logger.info(f"New event subscriber added: {callback.__name__}")

    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time statistics."""
        uptime = 0
        if self.stats['start_time']:
            uptime = (datetime.now(timezone.utc) - self.stats['start_time']).total_seconds()
        
        network_stats = self.network_collector.get_collection_stats()
        threat_intel_stats = self.threat_intel.get_statistics()
        
        return {
            'integrator': {
                'is_running': self.is_running,
                'uptime_seconds': uptime,
                'events_processed': self.stats['events_processed'],
                'events_enriched': self.stats['events_enriched'],
                'threat_matches': self.stats['threat_matches'],
                'high_risk_events': self.stats['high_risk_events'],
                'events_per_second': self.stats['events_processed'] / max(uptime, 1),
                'buffer_size': len(self.event_buffer),
                'subscribers': len(self.event_subscribers)
            },
            'network_collection': network_stats,
            'threat_intelligence': threat_intel_stats
        }

    def get_recent_events(self, limit: int = 100, event_type: str = None) -> List[Dict[str, Any]]:
        """Get recent events."""
        events = list(self.event_buffer)
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        # Sort by timestamp descending
        events.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Convert to dict and limit
        return [asdict(event) for event in events[:limit]]

    def export_real_data(self, filepath: str, format_type: str = 'json'):
        """Export collected real data."""
        if not self.export_enabled:
            logger.warning("Data export is disabled")
            return
        
        try:
            events = list(self.event_buffer)
            
            if format_type == 'json':
                with open(filepath, 'w') as f:
                    json.dump([asdict(event) for event in events], f, 
                             default=str, indent=2)
            
            logger.info(f"Exported {len(events)} events to {filepath}")
            
        except Exception as e:
            logger.error(f"Export error: {e}")

    def _log_collection_status(self):
        """Log current collection status."""
        stats = self.get_real_time_stats()
        logger.info("Real Data Collection Status:")
        logger.info(f"  Network Collection: {'Running' if stats['network_collection']['is_running'] else 'Stopped'}")
        logger.info(f"  Threat Intelligence: {'Running' if stats['threat_intelligence']['is_running'] else 'Stopped'}")
        logger.info(f"  Events Processed: {stats['integrator']['events_processed']}")
        logger.info(f"  Buffer Size: {stats['integrator']['buffer_size']}")

    def _log_final_statistics(self):
        """Log final statistics when stopping."""
        stats = self.get_real_time_stats()
        logger.info("Final Real Data Collection Statistics:")
        logger.info(f"  Total Events Processed: {stats['integrator']['events_processed']}")
        logger.info(f"  Events Enriched: {stats['integrator']['events_enriched']}")
        logger.info(f"  Threat Matches Found: {stats['integrator']['threat_matches']}")
        logger.info(f"  High Risk Events: {stats['integrator']['high_risk_events']}")
        logger.info(f"  Network Packets Captured: {stats['network_collection']['packets_captured']}")
        logger.info(f"  Threat Indicators Collected: {stats['threat_intelligence']['total_indicators']}")


# Global real data integrator instance
_real_data_integrator = None

def get_real_data_integrator() -> RealDataIntegrator:
    """Get global real data integrator instance."""
    global _real_data_integrator
    if _real_data_integrator is None:
        _real_data_integrator = RealDataIntegrator()
    return _real_data_integrator