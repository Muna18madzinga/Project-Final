"""
Real Telemetry Collection Layer - UPDATED VERSION
Uses real data sources instead of simulated data for accurate threat detection
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

# Import real data sources
try:
    from ..real_data_sources.real_data_integration import get_real_data_integrator, RealDataEvent
    from ..real_data_sources.live_network_collector import get_real_network_collector
    from ..real_data_sources.threat_intel_feeds import get_threat_intel_feeds
    REAL_DATA_AVAILABLE = True
except ImportError as e:
    REAL_DATA_AVAILABLE = False
    logging.warning(f"Real data sources not available, falling back to simulated data: {e}")

logger = logging.getLogger(__name__)

@dataclass
class EnhancedTelemetryData:
    """Enhanced telemetry data structure with real data integration."""
    source: str
    timestamp: datetime
    data_type: str
    payload: Dict[str, Any]
    metadata: Dict[str, Any]
    risk_indicators: List[str]
    threat_score: float
    enrichment_data: Dict[str, Any]
    correlation_id: str

class RealTelemetryCollector:
    """Enhanced telemetry collector using real data sources."""
    
    def __init__(self, use_real_data: bool = True):
        self.use_real_data = use_real_data and REAL_DATA_AVAILABLE
        self.is_running = False
        self.telemetry_buffer = deque(maxlen=50000)
        self.subscribers = []
        self.collection_thread = None
        
        # Real data integrator
        if self.use_real_data:
            self.real_data_integrator = get_real_data_integrator()
            logger.info("Real telemetry collector initialized with live data sources")
        else:
            self.real_data_integrator = None
            logger.warning("Using simulated data - real data sources not available")
        
        # Statistics
        self.stats = {
            'telemetry_events_collected': 0,
            'real_events_processed': 0,
            'threat_events_detected': 0,
            'start_time': None
        }

    def start_collection(self, config: Dict[str, Any] = None):
        """Start enhanced telemetry collection."""
        if self.is_running:
            logger.warning("Telemetry collection already running")
            return
        
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        if self.use_real_data:
            # Start real data collection
            self.real_data_integrator.start_real_data_collection(config)
            
            # Subscribe to real data events
            self.real_data_integrator.subscribe_to_events(self._process_real_data_event)
            
            logger.info("Real telemetry collection started")
        else:
            # Fall back to simulated data collection
            self.collection_thread = threading.Thread(target=self._simulated_collection_loop)
            self.collection_thread.daemon = True
            self.collection_thread.start()
            
            logger.info("Simulated telemetry collection started")

    def stop_collection(self):
        """Stop telemetry collection."""
        self.is_running = False
        
        if self.use_real_data and self.real_data_integrator:
            self.real_data_integrator.stop_real_data_collection()
        
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        
        logger.info(f"Telemetry collection stopped. Processed {self.stats['telemetry_events_collected']} events")

    def _process_real_data_event(self, real_event: RealDataEvent):
        """Process incoming real data event."""
        try:
            # Convert real data event to telemetry format
            telemetry_event = self._convert_to_telemetry(real_event)
            
            # Add to buffer
            self.telemetry_buffer.append(telemetry_event)
            
            # Update statistics
            self.stats['telemetry_events_collected'] += 1
            self.stats['real_events_processed'] += 1
            
            if telemetry_event.threat_score > 0.7:
                self.stats['threat_events_detected'] += 1
            
            # Notify subscribers
            self._notify_subscribers(telemetry_event)
            
        except Exception as e:
            logger.error(f"Error processing real data event: {e}")

    def _convert_to_telemetry(self, real_event: RealDataEvent) -> EnhancedTelemetryData:
        """Convert real data event to telemetry format."""
        return EnhancedTelemetryData(
            source=f"real_{real_event.source}",
            timestamp=real_event.timestamp,
            data_type=real_event.event_type,
            payload=real_event.data,
            metadata={
                'event_id': real_event.event_id,
                'original_source': real_event.source,
                'data_quality': 'real',
                'collection_method': 'live'
            },
            risk_indicators=real_event.threat_indicators,
            threat_score=real_event.threat_score,
            enrichment_data=real_event.enrichment,
            correlation_id=real_event.event_id
        )

    def _simulated_collection_loop(self):
        """Fallback simulated data collection loop."""
        logger.warning("Using simulated telemetry data - real data sources unavailable")
        
        while self.is_running:
            try:
                # Generate simulated telemetry events
                simulated_events = self._generate_simulated_events()
                
                for event in simulated_events:
                    self.telemetry_buffer.append(event)
                    self.stats['telemetry_events_collected'] += 1
                    self._notify_subscribers(event)
                
                time.sleep(1)  # Generate events every second
                
            except Exception as e:
                logger.error(f"Simulated collection error: {e}")
                time.sleep(1)

    def _generate_simulated_events(self) -> List[EnhancedTelemetryData]:
        """Generate simulated telemetry events as fallback."""
        import random
        import uuid
        
        events = []
        
        # Network event simulation
        network_event = EnhancedTelemetryData(
            source="simulated_network",
            timestamp=datetime.now(),
            data_type="network_traffic",
            payload={
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'dest_ip': f"10.0.0.{random.randint(1, 254)}",
                'source_port': random.randint(1024, 65535),
                'dest_port': random.choice([80, 443, 22, 3389, 445]),
                'protocol': random.choice(['tcp', 'udp']),
                'packet_size': random.randint(64, 1500),
                'flags': ['syn'] if random.random() > 0.5 else []
            },
            metadata={
                'event_id': str(uuid.uuid4()),
                'data_quality': 'simulated',
                'collection_method': 'fallback'
            },
            risk_indicators=['simulated_traffic'],
            threat_score=random.uniform(0.1, 0.9),
            enrichment_data={},
            correlation_id=str(uuid.uuid4())
        )
        events.append(network_event)
        
        # System event simulation
        system_event = EnhancedTelemetryData(
            source="simulated_system",
            timestamp=datetime.now(),
            data_type="system_metrics",
            payload={
                'cpu_percent': random.uniform(10, 90),
                'memory_percent': random.uniform(20, 80),
                'disk_io_read': random.randint(1000, 50000),
                'disk_io_write': random.randint(500, 25000),
                'active_connections': random.randint(10, 300),
                'processes_count': random.randint(50, 200)
            },
            metadata={
                'event_id': str(uuid.uuid4()),
                'data_quality': 'simulated',
                'collection_method': 'fallback'
            },
            risk_indicators=[],
            threat_score=random.uniform(0.0, 0.6),
            enrichment_data={},
            correlation_id=str(uuid.uuid4())
        )
        events.append(system_event)
        
        return events

    def _notify_subscribers(self, telemetry: EnhancedTelemetryData):
        """Notify all subscribers of new telemetry data."""
        for subscriber in self.subscribers:
            try:
                subscriber(telemetry)
            except Exception as e:
                logger.error(f"Subscriber notification error: {e}")

    def subscribe(self, callback_func):
        """Subscribe to telemetry stream."""
        self.subscribers.append(callback_func)
        logger.info(f"New telemetry subscriber added: {callback_func.__name__}")

    def get_telemetry_batch(self, batch_size: int = 100, timeout: float = 5.0) -> List[EnhancedTelemetryData]:
        """Get batch of telemetry data."""
        batch = []
        end_time = time.time() + timeout
        
        while len(batch) < batch_size and time.time() < end_time:
            if self.telemetry_buffer:
                batch.append(self.telemetry_buffer.popleft())
            else:
                time.sleep(0.1)
        
        return batch

    def get_telemetry_stats(self) -> Dict[str, Any]:
        """Get telemetry collection statistics."""
        uptime = 0
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        base_stats = {
            'is_running': self.is_running,
            'use_real_data': self.use_real_data,
            'real_data_available': REAL_DATA_AVAILABLE,
            'uptime_seconds': uptime,
            'telemetry_events_collected': self.stats['telemetry_events_collected'],
            'real_events_processed': self.stats['real_events_processed'],
            'threat_events_detected': self.stats['threat_events_detected'],
            'events_per_second': self.stats['telemetry_events_collected'] / max(uptime, 1),
            'buffer_size': len(self.telemetry_buffer),
            'subscribers_count': len(self.subscribers)
        }
        
        # Add real data integrator stats if available
        if self.use_real_data and self.real_data_integrator:
            real_stats = self.real_data_integrator.get_real_time_stats()
            base_stats['real_data_stats'] = real_stats
        
        return base_stats

    def get_threat_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent threat events from telemetry."""
        threat_events = []
        
        for event in list(self.telemetry_buffer):
            if event.threat_score > 0.5:  # Threshold for threat events
                threat_events.append({
                    'timestamp': event.timestamp.isoformat(),
                    'source': event.source,
                    'data_type': event.data_type,
                    'threat_score': event.threat_score,
                    'risk_indicators': event.risk_indicators,
                    'correlation_id': event.correlation_id,
                    'payload_summary': self._summarize_payload(event.payload)
                })
        
        # Sort by threat score descending
        threat_events.sort(key=lambda x: x['threat_score'], reverse=True)
        return threat_events[:limit]

    def _summarize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of payload data."""
        summary = {}
        
        # Network traffic summary
        if 'source_ip' in payload:
            summary.update({
                'connection': f"{payload.get('source_ip')}:{payload.get('source_port', 'N/A')} -> {payload.get('dest_ip')}:{payload.get('dest_port', 'N/A')}",
                'protocol': payload.get('protocol', 'unknown')
            })
        
        # System metrics summary
        if 'cpu_percent' in payload:
            summary.update({
                'cpu_usage': f"{payload.get('cpu_percent', 0):.1f}%",
                'memory_usage': f"{payload.get('memory_percent', 0):.1f}%",
                'connections': payload.get('active_connections', 0)
            })
        
        return summary

    def export_telemetry(self, filepath: str, format_type: str = 'json', limit: int = 1000):
        """Export telemetry data."""
        try:
            events = list(self.telemetry_buffer)[:limit]
            
            if format_type == 'json':
                with open(filepath, 'w') as f:
                    json.dump([asdict(event) for event in events], f, 
                             default=str, indent=2)
            
            logger.info(f"Exported {len(events)} telemetry events to {filepath}")
            
        except Exception as e:
            logger.error(f"Telemetry export error: {e}")


class EnhancedTelemetryStreamProcessor:
    """Enhanced stream processor for real telemetry data."""
    
    def __init__(self):
        self.stream_buffer = queue.Queue(maxsize=200000)
        self.subscribers = []
        self.is_running = False
        self.processing_thread = None
        
        # Use enhanced telemetry collector
        self.telemetry_collector = RealTelemetryCollector()
        
        # Analytics
        self.event_analytics = {
            'total_processed': 0,
            'threat_events': 0,
            'network_events': 0,
            'system_events': 0,
            'high_risk_events': 0
        }

    def start_stream_processing(self, config: Dict[str, Any] = None):
        """Start enhanced telemetry stream processing."""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start telemetry collection
        self.telemetry_collector.start_collection(config)
        
        # Subscribe to telemetry events
        self.telemetry_collector.subscribe(self._process_telemetry_event)
        
        # Start stream processing
        self.processing_thread = threading.Thread(target=self._process_telemetry_stream)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        logger.info("Enhanced telemetry stream processing started")

    def stop_stream_processing(self):
        """Stop telemetry stream processing."""
        self.is_running = False
        
        # Stop telemetry collection
        self.telemetry_collector.stop_collection()
        
        # Stop processing thread
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        
        logger.info("Enhanced telemetry stream processing stopped")

    def _process_telemetry_event(self, telemetry: EnhancedTelemetryData):
        """Process individual telemetry event."""
        try:
            # Add to stream buffer
            if not self.stream_buffer.full():
                self.stream_buffer.put(telemetry)
            
            # Update analytics
            self.event_analytics['total_processed'] += 1
            
            if telemetry.threat_score > 0.7:
                self.event_analytics['high_risk_events'] += 1
            
            if telemetry.threat_score > 0.5:
                self.event_analytics['threat_events'] += 1
            
            if telemetry.data_type == 'network_traffic':
                self.event_analytics['network_events'] += 1
            elif telemetry.data_type == 'system_metrics':
                self.event_analytics['system_events'] += 1
            
            # Notify subscribers
            for subscriber in self.subscribers:
                try:
                    subscriber(telemetry)
                except Exception as e:
                    logger.error(f"Stream subscriber error: {e}")
                    
        except Exception as e:
            logger.error(f"Telemetry event processing error: {e}")

    def _process_telemetry_stream(self):
        """Process telemetry data stream."""
        while self.is_running:
            try:
                # Basic stream processing - can be extended with complex analytics
                time.sleep(0.1)
                
                # Log statistics periodically
                if self.event_analytics['total_processed'] % 1000 == 0:
                    logger.info(f"Processed {self.event_analytics['total_processed']} telemetry events")
                    
            except Exception as e:
                logger.error(f"Stream processing error: {e}")
                time.sleep(1)

    def subscribe(self, callback_func):
        """Subscribe to telemetry stream."""
        self.subscribers.append(callback_func)
        logger.info(f"New stream subscriber added: {callback_func.__name__}")

    def get_stream_data(self, timeout: float = 1.0) -> Optional[EnhancedTelemetryData]:
        """Get data from telemetry stream."""
        try:
            return self.stream_buffer.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stream_stats(self) -> Dict[str, Any]:
        """Get stream processing statistics."""
        telemetry_stats = self.telemetry_collector.get_telemetry_stats()
        
        return {
            'stream_processing': {
                'is_running': self.is_running,
                'stream_buffer_size': self.stream_buffer.qsize(),
                'stream_buffer_max': self.stream_buffer.maxsize,
                'subscribers_count': len(self.subscribers)
            },
            'event_analytics': self.event_analytics,
            'telemetry_collection': telemetry_stats
        }


# Global enhanced telemetry processor instance
_enhanced_telemetry_processor = None

def get_enhanced_telemetry_processor() -> EnhancedTelemetryStreamProcessor:
    """Get global enhanced telemetry stream processor instance."""
    global _enhanced_telemetry_processor
    if _enhanced_telemetry_processor is None:
        _enhanced_telemetry_processor = EnhancedTelemetryStreamProcessor()
    return _enhanced_telemetry_processor

# Backward compatibility - use enhanced processor by default
def get_telemetry_processor() -> EnhancedTelemetryStreamProcessor:
    """Get telemetry processor (now returns enhanced version)."""
    return get_enhanced_telemetry_processor()