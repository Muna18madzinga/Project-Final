"""
Live Threat Intelligence Feeds Integration
Replaces static threat data with real-time threat intelligence from multiple sources
"""

import logging
import json
import csv
import io
import hashlib
import time
import threading
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import concurrent.futures

logger = logging.getLogger(__name__)

@dataclass
class ThreatIndicator:
    """Threat indicator data structure."""
    value: str
    type: str  # ip, domain, url, hash, email
    threat_type: str
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    description: str
    severity: str  # low, medium, high, critical

@dataclass
class ThreatIntelligence:
    """Threat intelligence report."""
    report_id: str
    title: str
    description: str
    threat_actors: List[str]
    attack_patterns: List[str]
    indicators: List[ThreatIndicator]
    published: datetime
    source: str
    tlp: str  # Traffic Light Protocol
    confidence: float

class LiveThreatIntelFeeds:
    """Live threat intelligence feeds collector."""
    
    def __init__(self):
        self.is_running = False
        self.threat_indicators = {}  # type -> [indicators]
        self.threat_reports = []
        self.collection_thread = None
        self.last_update = {}
        self.update_lock = threading.Lock()
        
        # Configure threat intelligence sources
        self.sources = {
            # Free public sources
            'alienvault_otx': {
                'enabled': True,
                'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
                'api_key_required': True,
                'update_interval': 3600,  # 1 hour
                'parser': self._parse_otx_data
            },
            'abuse_ch_malware': {
                'enabled': True,
                'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
                'api_key_required': False,
                'update_interval': 1800,  # 30 minutes
                'parser': self._parse_abuse_ch_malware
            },
            'abuse_ch_ssl': {
                'enabled': True,
                'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
                'api_key_required': False,
                'update_interval': 3600,  # 1 hour
                'parser': self._parse_abuse_ch_ssl
            },
            'phishtank': {
                'enabled': True,
                'url': 'http://data.phishtank.com/data/online-valid.csv',
                'api_key_required': False,
                'update_interval': 1800,  # 30 minutes
                'parser': self._parse_phishtank
            },
            'emerging_threats': {
                'enabled': True,
                'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'api_key_required': False,
                'update_interval': 3600,  # 1 hour
                'parser': self._parse_emerging_threats
            },
            'spamhaus_sbl': {
                'enabled': True,
                'url': 'https://www.spamhaus.org/sbl/csv',
                'api_key_required': False,
                'update_interval': 7200,  # 2 hours
                'parser': self._parse_spamhaus_data
            },
            'malware_domain_list': {
                'enabled': True,
                'url': 'https://www.malwaredomainlist.com/hostslist/hosts.txt',
                'api_key_required': False,
                'update_interval': 3600,  # 1 hour
                'parser': self._parse_malware_domains
            },
            'misp_events': {
                'enabled': False,  # Requires MISP instance
                'url': 'https://your-misp-instance/events/restSearch',
                'api_key_required': True,
                'update_interval': 1800,  # 30 minutes
                'parser': self._parse_misp_events
            }
        }
        
        # Statistics
        self.collection_stats = {
            'total_indicators': 0,
            'indicators_by_type': defaultdict(int),
            'indicators_by_source': defaultdict(int),
            'last_update_times': {},
            'collection_errors': defaultdict(int)
        }

    def start_collection(self, api_keys: Dict[str, str] = None):
        """Start threat intelligence collection."""
        if self.is_running:
            logger.warning("Threat intel collection already running")
            return
        
        # Configure API keys if provided
        if api_keys:
            self._configure_api_keys(api_keys)
        
        self.is_running = True
        self.collection_thread = threading.Thread(target=self._collection_loop)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        
        logger.info("Live threat intelligence feeds collection started")

    def stop_collection(self):
        """Stop threat intelligence collection."""
        self.is_running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=10)
        logger.info("Threat intelligence collection stopped")

    def _configure_api_keys(self, api_keys: Dict[str, str]):
        """Configure API keys for threat intel sources."""
        for source_name, source_config in self.sources.items():
            if source_config['api_key_required'] and source_name in api_keys:
                source_config['api_key'] = api_keys[source_name]
                logger.info(f"API key configured for {source_name}")

    def _collection_loop(self):
        """Main collection loop."""
        while self.is_running:
            try:
                # Check each source for updates
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = []
                    
                    for source_name, source_config in self.sources.items():
                        if not source_config['enabled']:
                            continue
                        
                        # Check if it's time to update this source
                        if self._should_update_source(source_name):
                            future = executor.submit(self._collect_from_source, source_name, source_config)
                            futures.append((source_name, future))
                    
                    # Wait for all collections to complete
                    for source_name, future in futures:
                        try:
                            future.result(timeout=60)  # 60 second timeout per source
                        except Exception as e:
                            logger.error(f"Error collecting from {source_name}: {e}")
                            self.collection_stats['collection_errors'][source_name] += 1
                
                # Sleep for 60 seconds before next check
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Threat intel collection loop error: {e}")
                time.sleep(60)

    def _should_update_source(self, source_name: str) -> bool:
        """Check if source should be updated."""
        source_config = self.sources[source_name]
        last_update = self.last_update.get(source_name, datetime.min.replace(tzinfo=timezone.utc))
        now = datetime.now(timezone.utc)
        
        update_interval = timedelta(seconds=source_config['update_interval'])
        return now - last_update >= update_interval

    def _collect_from_source(self, source_name: str, source_config: Dict):
        """Collect threat intelligence from a specific source."""
        try:
            logger.info(f"Collecting threat intel from {source_name}")
            
            # Prepare headers
            headers = {'User-Agent': 'AdaptiveSecuritySuite/1.0'}
            
            # Add API key if required
            if source_config.get('api_key'):
                headers['X-OTX-API-KEY'] = source_config['api_key']
            
            # Make request
            response = requests.get(
                source_config['url'], 
                headers=headers, 
                timeout=30,
                verify=True
            )
            response.raise_for_status()
            
            # Parse data using source-specific parser
            indicators = source_config['parser'](response.text, source_name)
            
            # Update indicators
            with self.update_lock:
                self._update_indicators(source_name, indicators)
                self.last_update[source_name] = datetime.now(timezone.utc)
                self.collection_stats['last_update_times'][source_name] = datetime.now(timezone.utc)
            
            logger.info(f"Successfully collected {len(indicators)} indicators from {source_name}")
            
        except Exception as e:
            logger.error(f"Failed to collect from {source_name}: {e}")
            raise

    def _update_indicators(self, source: str, new_indicators: List[ThreatIndicator]):
        """Update threat indicators from a source."""
        # Remove old indicators from this source
        for indicator_type in self.threat_indicators:
            self.threat_indicators[indicator_type] = [
                ind for ind in self.threat_indicators[indicator_type] 
                if ind.source != source
            ]
        
        # Add new indicators
        for indicator in new_indicators:
            indicator_type = indicator.type
            if indicator_type not in self.threat_indicators:
                self.threat_indicators[indicator_type] = []
            
            self.threat_indicators[indicator_type].append(indicator)
            
            # Update statistics
            self.collection_stats['indicators_by_type'][indicator_type] += 1
            self.collection_stats['indicators_by_source'][source] += 1
        
        self.collection_stats['total_indicators'] = sum(
            len(indicators) for indicators in self.threat_indicators.values()
        )

    def _parse_abuse_ch_malware(self, data: str, source: str) -> List[ThreatIndicator]:
        """Parse abuse.ch malware URL data."""
        indicators = []
        lines = data.strip().split('\n')
        
        # Skip header lines
        data_lines = [line for line in lines if not line.startswith('#') and line.strip()]
        
        for line in data_lines[8:]:  # Skip CSV header
            try:
                # Parse CSV-like format
                reader = csv.reader(io.StringIO(line))
                row = next(reader)
                
                if len(row) >= 7:
                    url = row[2]
                    threat_type = row[4] if len(row) > 4 else 'malware'
                    tags = [tag.strip() for tag in row[6].split(',')] if len(row) > 6 else []
                    
                    indicator = ThreatIndicator(
                        value=url,
                        type='url',
                        threat_type=threat_type,
                        confidence=0.8,
                        source=source,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        tags=tags,
                        description=f"Malware URL detected by abuse.ch",
                        severity='high'
                    )
                    indicators.append(indicator)
                    
            except Exception as e:
                logger.debug(f"Error parsing abuse.ch line: {e}")
                continue
        
        return indicators

    def _parse_abuse_ch_ssl(self, data: str, source: str) -> List[ThreatIndicator]:
        """Parse abuse.ch SSL blacklist data."""
        indicators = []
        lines = data.strip().split('\n')
        
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            
            try:
                # SSL blacklist format: SHA1,port
                parts = line.split(',')
                if len(parts) >= 1:
                    ssl_hash = parts[0].strip()
                    
                    indicator = ThreatIndicator(
                        value=ssl_hash,
                        type='hash',
                        threat_type='malicious_ssl',
                        confidence=0.9,
                        source=source,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        tags=['ssl', 'certificate'],
                        description="Malicious SSL certificate",
                        severity='medium'
                    )
                    indicators.append(indicator)
                    
            except Exception as e:
                logger.debug(f"Error parsing SSL line: {e}")
                continue
        
        return indicators

    def _parse_phishtank(self, data: str, source: str) -> List[ThreatIndicator]:
        """Parse PhishTank phishing URL data."""
        indicators = []
        lines = data.strip().split('\n')
        
        # Skip header
        if lines and 'phish_id' in lines[0]:
            lines = lines[1:]
        
        for line in lines:
            try:
                reader = csv.reader(io.StringIO(line))
                row = next(reader)
                
                if len(row) >= 2:
                    url = row[1]
                    
                    indicator = ThreatIndicator(
                        value=url,
                        type='url',
                        threat_type='phishing',
                        confidence=0.85,
                        source=source,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        tags=['phishing', 'social_engineering'],
                        description="Phishing URL from PhishTank",
                        severity='high'
                    )
                    indicators.append(indicator)
                    
            except Exception as e:
                logger.debug(f"Error parsing PhishTank line: {e}")
                continue
        
        return indicators

    def _parse_emerging_threats(self, data: str, source: str) -> List[ThreatIndicator]:
        """Parse Emerging Threats IP blacklist."""
        indicators = []
        lines = data.strip().split('\n')
        
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            
            try:
                ip = line.strip()
                if self._is_valid_ip(ip):
                    indicator = ThreatIndicator(
                        value=ip,
                        type='ip',
                        threat_type='compromised_host',
                        confidence=0.8,
                        source=source,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        tags=['compromised', 'botnet'],
                        description="Compromised host from Emerging Threats",
                        severity='medium'
                    )
                    indicators.append(indicator)
                    
            except Exception as e:
                logger.debug(f"Error parsing ET IP line: {e}")
                continue
        
        return indicators

    def _parse_spamhaus_data(self, data: str, source: str) -> List[ThreatIndicator]:
        """Parse Spamhaus SBL data."""
        indicators = []
        
        # Spamhaus data is often in different formats, handle accordingly
        lines = data.strip().split('\n')
        
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            
            try:
                # Basic IP/domain extraction
                parts = line.split()
                if parts:
                    value = parts[0]
                    
                    # Determine type
                    indicator_type = 'ip' if self._is_valid_ip(value) else 'domain'
                    
                    indicator = ThreatIndicator(
                        value=value,
                        type=indicator_type,
                        threat_type='spam_source',
                        confidence=0.9,
                        source=source,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        tags=['spam', 'blacklist'],
                        description="Spam source from Spamhaus",
                        severity='medium'
                    )
                    indicators.append(indicator)
                    
            except Exception as e:
                logger.debug(f"Error parsing Spamhaus line: {e}")
                continue
        
        return indicators

    def _parse_malware_domains(self, data: str, source: str) -> List[ThreatIndicator]:
        """Parse malware domain list."""
        indicators = []
        lines = data.strip().split('\n')
        
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            
            try:
                # hosts file format: 127.0.0.1 malicious.domain.com
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ['127.0.0.1', '0.0.0.0']:
                    domain = parts[1]
                    
                    indicator = ThreatIndicator(
                        value=domain,
                        type='domain',
                        threat_type='malware_host',
                        confidence=0.8,
                        source=source,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        tags=['malware', 'hosting'],
                        description="Malware hosting domain",
                        severity='high'
                    )
                    indicators.append(indicator)
                    
            except Exception as e:
                logger.debug(f"Error parsing malware domain line: {e}")
                continue
        
        return indicators

    def _parse_otx_data(self, data: str, source: str) -> List[ThreatIndicator]:
        """Parse AlienVault OTX data."""
        indicators = []
        
        try:
            otx_data = json.loads(data)
            
            for pulse in otx_data.get('results', []):
                for indicator_data in pulse.get('indicators', []):
                    indicator = ThreatIndicator(
                        value=indicator_data['indicator'],
                        type=indicator_data['type'].lower(),
                        threat_type=pulse.get('adversary', 'unknown'),
                        confidence=0.8,
                        source=source,
                        first_seen=datetime.fromisoformat(pulse['created'].replace('Z', '+00:00')),
                        last_seen=datetime.fromisoformat(pulse['modified'].replace('Z', '+00:00')),
                        tags=pulse.get('tags', []),
                        description=pulse.get('description', ''),
                        severity='medium'
                    )
                    indicators.append(indicator)
                    
        except Exception as e:
            logger.error(f"Error parsing OTX data: {e}")
        
        return indicators

    def _parse_misp_events(self, data: str, source: str) -> List[ThreatIndicator]:
        """Parse MISP events data."""
        indicators = []
        
        try:
            misp_data = json.loads(data)
            
            for event in misp_data.get('response', []):
                event_info = event.get('Event', {})
                
                for attribute in event_info.get('Attribute', []):
                    if attribute.get('to_ids'):  # Only include indicators
                        indicator = ThreatIndicator(
                            value=attribute['value'],
                            type=attribute['type'],
                            threat_type=event_info.get('info', 'unknown'),
                            confidence=float(attribute.get('comment', '0.5')),
                            source=source,
                            first_seen=datetime.fromisoformat(event_info['date']),
                            last_seen=datetime.fromisoformat(attribute['timestamp']),
                            tags=event_info.get('Tag', []),
                            description=event_info.get('info', ''),
                            severity=self._misp_threat_level_to_severity(event_info.get('threat_level_id', '3'))
                        )
                        indicators.append(indicator)
                        
        except Exception as e:
            logger.error(f"Error parsing MISP data: {e}")
        
        return indicators

    def _misp_threat_level_to_severity(self, threat_level: str) -> str:
        """Convert MISP threat level to severity."""
        level_map = {
            '1': 'critical',
            '2': 'high', 
            '3': 'medium',
            '4': 'low'
        }
        return level_map.get(str(threat_level), 'medium')

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address."""
        import socket
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def check_indicator(self, value: str, indicator_type: str = None) -> List[ThreatIndicator]:
        """Check if a value matches any threat indicators."""
        matches = []
        
        with self.update_lock:
            if indicator_type:
                # Check specific type
                if indicator_type in self.threat_indicators:
                    for indicator in self.threat_indicators[indicator_type]:
                        if indicator.value == value:
                            matches.append(indicator)
            else:
                # Check all types
                for indicators in self.threat_indicators.values():
                    for indicator in indicators:
                        if indicator.value == value:
                            matches.append(indicator)
        
        return matches

    def get_indicators_by_type(self, indicator_type: str, limit: int = 100) -> List[ThreatIndicator]:
        """Get indicators by type."""
        with self.update_lock:
            indicators = self.threat_indicators.get(indicator_type, [])
            return indicators[:limit]

    def get_recent_indicators(self, hours: int = 24, limit: int = 100) -> List[ThreatIndicator]:
        """Get recent indicators from the last N hours."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        recent_indicators = []
        
        with self.update_lock:
            for indicators in self.threat_indicators.values():
                for indicator in indicators:
                    if indicator.first_seen >= cutoff_time:
                        recent_indicators.append(indicator)
        
        # Sort by first_seen descending and limit
        recent_indicators.sort(key=lambda x: x.first_seen, reverse=True)
        return recent_indicators[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence collection statistics."""
        with self.update_lock:
            stats = self.collection_stats.copy()
            stats.update({
                'is_running': self.is_running,
                'sources_enabled': sum(1 for s in self.sources.values() if s['enabled']),
                'sources_total': len(self.sources),
                'indicators_by_type': dict(self.collection_stats['indicators_by_type']),
                'indicators_by_source': dict(self.collection_stats['indicators_by_source']),
                'collection_errors': dict(self.collection_stats['collection_errors'])
            })
        
        return stats

    def export_indicators(self, format_type: str = 'json', indicator_types: List[str] = None) -> str:
        """Export indicators in various formats."""
        with self.update_lock:
            if indicator_types:
                export_indicators = []
                for itype in indicator_types:
                    export_indicators.extend(self.threat_indicators.get(itype, []))
            else:
                export_indicators = []
                for indicators in self.threat_indicators.values():
                    export_indicators.extend(indicators)
        
        if format_type == 'json':
            return json.dumps([asdict(ind) for ind in export_indicators], 
                            default=str, indent=2)
        elif format_type == 'csv':
            # Convert to CSV format
            csv_lines = ['value,type,threat_type,confidence,source,first_seen,last_seen,tags,description,severity']
            for ind in export_indicators:
                csv_lines.append(f'"{ind.value}","{ind.type}","{ind.threat_type}","{ind.confidence}","{ind.source}","{ind.first_seen}","{ind.last_seen}","{",".join(ind.tags)}","{ind.description}","{ind.severity}"')
            return '\n'.join(csv_lines)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")


# Global threat intel feeds instance
_threat_intel_feeds = None

def get_threat_intel_feeds() -> LiveThreatIntelFeeds:
    """Get global threat intelligence feeds instance."""
    global _threat_intel_feeds
    if _threat_intel_feeds is None:
        _threat_intel_feeds = LiveThreatIntelFeeds()
    return _threat_intel_feeds