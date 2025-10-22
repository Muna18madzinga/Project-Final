"""
Enforcement Layer - Chapter 3.3 System Architecture
Software-based SDN controllers utilizing API-based policies for virtual micro-segmentation
and automated quarantines. Enforced using TLS 1.3 libraries.
Implements software-defined security model-based programmable threat mitigation.
"""

import logging
import asyncio
import json
import ssl
import time
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum
import threading
import queue
import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

from .policy_engine import PolicyDecision, PolicyAction, RiskLevel

logger = logging.getLogger(__name__)

class EnforcementAction(Enum):
    """Enforcement action types."""
    BLOCK_IP = "block_ip"
    QUARANTINE_ENDPOINT = "quarantine_endpoint"
    RESTRICT_NETWORK = "restrict_network"
    ISOLATE_SESSION = "isolate_session"
    TERMINATE_CONNECTION = "terminate_connection"
    APPLY_MICRO_SEGMENTATION = "apply_micro_segmentation"
    ENABLE_ENHANCED_MONITORING = "enable_enhanced_monitoring"
    REQUIRE_AUTHENTICATION = "require_authentication"

@dataclass
class NetworkRule:
    """Network enforcement rule."""
    rule_id: str
    rule_type: str
    source: str
    destination: str
    protocol: str
    port: Optional[int]
    action: str  # allow, deny, restrict
    priority: int
    expires_at: Optional[datetime]
    created_at: datetime
    metadata: Dict[str, Any]

@dataclass
class EnforcementResult:
    """Result of enforcement action."""
    action_id: str
    policy_decision_id: str
    enforcement_actions: List[EnforcementAction]
    success: bool
    timestamp: datetime
    affected_entities: List[str]
    network_rules_applied: List[str]
    errors: List[str]
    duration_applied: Optional[int]  # minutes

class VirtualSDNController:
    """Virtual Software-Defined Networking controller for policy enforcement."""

    def __init__(self):
        self.active_rules = {}
        self.rule_history = deque(maxlen=10000)
        self.network_topology = {}
        self.quarantine_networks = {
            'quarantine_vlan': '192.168.100.0/24',
            'restricted_vlan': '192.168.101.0/24',
            'monitoring_vlan': '192.168.102.0/24'
        }

        # Virtual switch configuration
        self.virtual_switches = {
            'main_switch': {
                'dpid': '0000000000000001',
                'ports': list(range(1, 49)),
                'vlans': [1, 100, 101, 102],
                'flow_table': {}
            }
        }

        # TLS configuration for secure communication
        self.tls_context = self._setup_tls_context()

    def _setup_tls_context(self) -> ssl.SSLContext:
        """Setup TLS 1.3 context for secure SDN communication."""
        # Create self-signed certificate for demonstration
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Virtual"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "SDN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Adaptive Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SDN Controller"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Create TLS context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # In a real implementation, these would be proper certificates
        # For demo, we'll use the default context with secure settings
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        return context

    def apply_network_policy(self, policy_decision: PolicyDecision) -> List[NetworkRule]:
        """Apply network policy based on policy decision."""
        rules = []
        current_time = datetime.now()

        entity_id = policy_decision.entity_id
        action = policy_decision.action
        risk_level = policy_decision.risk_level

        # Determine enforcement actions based on policy
        if action == PolicyAction.DENY:
            rule = self._create_deny_rule(entity_id, policy_decision)
            rules.append(rule)

        elif action == PolicyAction.QUARANTINE:
            quarantine_rules = self._create_quarantine_rules(entity_id, policy_decision)
            rules.extend(quarantine_rules)

        elif action == PolicyAction.RESTRICT:
            restriction_rules = self._create_restriction_rules(entity_id, policy_decision)
            rules.extend(restriction_rules)

        elif action == PolicyAction.MONITOR:
            monitoring_rules = self._create_monitoring_rules(entity_id, policy_decision)
            rules.extend(monitoring_rules)

        # Apply micro-segmentation for high-risk entities
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            microseg_rules = self._create_microsegmentation_rules(entity_id, policy_decision)
            rules.extend(microseg_rules)

        # Install rules in virtual switches
        for rule in rules:
            self._install_flow_rule(rule)
            self.active_rules[rule.rule_id] = rule
            self.rule_history.append(rule)

        logger.info(f"Applied {len(rules)} network rules for policy {policy_decision.decision_id}")
        return rules

    def _create_deny_rule(self, entity_id: str, policy_decision: PolicyDecision) -> NetworkRule:
        """Create deny rule for entity."""
        rule_id = f"deny_{entity_id}_{int(time.time())}"

        return NetworkRule(
            rule_id=rule_id,
            rule_type="deny_all",
            source=f"entity:{entity_id}",
            destination="*",
            protocol="*",
            port=None,
            action="deny",
            priority=1000,  # High priority
            expires_at=datetime.now() + timedelta(minutes=policy_decision.recommended_duration or 60),
            created_at=datetime.now(),
            metadata={
                'policy_decision_id': policy_decision.decision_id,
                'risk_level': policy_decision.risk_level.value,
                'reasoning': policy_decision.reasoning
            }
        )

    def _create_quarantine_rules(self, entity_id: str, policy_decision: PolicyDecision) -> List[NetworkRule]:
        """Create quarantine rules for entity."""
        rules = []
        current_time = datetime.now()
        quarantine_vlan = self.quarantine_networks['quarantine_vlan']

        # Rule 1: Redirect all traffic to quarantine network
        redirect_rule = NetworkRule(
            rule_id=f"quarantine_redirect_{entity_id}_{int(time.time())}",
            rule_type="redirect",
            source=f"entity:{entity_id}",
            destination=quarantine_vlan,
            protocol="*",
            port=None,
            action="redirect",
            priority=900,
            expires_at=current_time + timedelta(minutes=policy_decision.recommended_duration or 120),
            created_at=current_time,
            metadata={
                'policy_decision_id': policy_decision.decision_id,
                'quarantine_network': quarantine_vlan
            }
        )
        rules.append(redirect_rule)

        # Rule 2: Block external communication
        block_external_rule = NetworkRule(
            rule_id=f"quarantine_block_external_{entity_id}_{int(time.time())}",
            rule_type="block_external",
            source=f"entity:{entity_id}",
            destination="external:*",
            protocol="*",
            port=None,
            action="deny",
            priority=950,
            expires_at=current_time + timedelta(minutes=policy_decision.recommended_duration or 120),
            created_at=current_time,
            metadata={
                'policy_decision_id': policy_decision.decision_id,
                'block_reason': 'quarantine_isolation'
            }
        )
        rules.append(block_external_rule)

        return rules

    def _create_restriction_rules(self, entity_id: str, policy_decision: PolicyDecision) -> List[NetworkRule]:
        """Create network restriction rules."""
        rules = []
        current_time = datetime.now()

        # Restrict to specific protocols and ports
        allowed_protocols = ['tcp:443', 'tcp:80', 'udp:53']  # HTTPS, HTTP, DNS only

        for protocol_port in allowed_protocols:
            protocol, port = protocol_port.split(':')

            allow_rule = NetworkRule(
                rule_id=f"restrict_allow_{protocol}_{port}_{entity_id}_{int(time.time())}",
                rule_type="selective_allow",
                source=f"entity:{entity_id}",
                destination="*",
                protocol=protocol,
                port=int(port),
                action="allow",
                priority=800,
                expires_at=current_time + timedelta(minutes=policy_decision.recommended_duration or 30),
                created_at=current_time,
                metadata={
                    'policy_decision_id': policy_decision.decision_id,
                    'restriction_type': 'protocol_port_limited'
                }
            )
            rules.append(allow_rule)

        # Default deny for other traffic
        default_deny_rule = NetworkRule(
            rule_id=f"restrict_default_deny_{entity_id}_{int(time.time())}",
            rule_type="default_deny",
            source=f"entity:{entity_id}",
            destination="*",
            protocol="*",
            port=None,
            action="deny",
            priority=700,
            expires_at=current_time + timedelta(minutes=policy_decision.recommended_duration or 30),
            created_at=current_time,
            metadata={
                'policy_decision_id': policy_decision.decision_id,
                'restriction_type': 'default_deny'
            }
        )
        rules.append(default_deny_rule)

        return rules

    def _create_monitoring_rules(self, entity_id: str, policy_decision: PolicyDecision) -> List[NetworkRule]:
        """Create enhanced monitoring rules."""
        rules = []
        current_time = datetime.now()

        # Mirror traffic to monitoring VLAN
        mirror_rule = NetworkRule(
            rule_id=f"monitor_mirror_{entity_id}_{int(time.time())}",
            rule_type="traffic_mirror",
            source=f"entity:{entity_id}",
            destination=self.quarantine_networks['monitoring_vlan'],
            protocol="*",
            port=None,
            action="mirror",
            priority=600,
            expires_at=current_time + timedelta(hours=24),  # Extended monitoring
            created_at=current_time,
            metadata={
                'policy_decision_id': policy_decision.decision_id,
                'monitoring_level': 'enhanced',
                'mirror_destination': self.quarantine_networks['monitoring_vlan']
            }
        )
        rules.append(mirror_rule)

        return rules

    def _create_microsegmentation_rules(self, entity_id: str, policy_decision: PolicyDecision) -> List[NetworkRule]:
        """Create micro-segmentation rules for high-risk entities."""
        rules = []
        current_time = datetime.now()

        # Create isolated network segment
        microseg_network = f"microseg_{entity_id[:8]}"

        # Isolate entity in micro-segment
        isolation_rule = NetworkRule(
            rule_id=f"microseg_isolate_{entity_id}_{int(time.time())}",
            rule_type="micro_segmentation",
            source=f"entity:{entity_id}",
            destination=f"segment:{microseg_network}",
            protocol="*",
            port=None,
            action="isolate",
            priority=1100,  # Highest priority
            expires_at=current_time + timedelta(minutes=policy_decision.recommended_duration or 240),
            created_at=current_time,
            metadata={
                'policy_decision_id': policy_decision.decision_id,
                'microsegment': microseg_network,
                'isolation_level': 'strict'
            }
        )
        rules.append(isolation_rule)

        # Allow only essential services
        essential_services = [
            ('tcp', 22, 'ssh_management'),
            ('udp', 53, 'dns_resolution'),
            ('tcp', 123, 'time_sync')
        ]

        for protocol, port, service in essential_services:
            service_rule = NetworkRule(
                rule_id=f"microseg_essential_{service}_{entity_id}_{int(time.time())}",
                rule_type="essential_service",
                source=f"entity:{entity_id}",
                destination="essential_services",
                protocol=protocol,
                port=port,
                action="allow",
                priority=1050,
                expires_at=current_time + timedelta(minutes=policy_decision.recommended_duration or 240),
                created_at=current_time,
                metadata={
                    'policy_decision_id': policy_decision.decision_id,
                    'service_type': service,
                    'essential': True
                }
            )
            rules.append(service_rule)

        return rules

    def _install_flow_rule(self, rule: NetworkRule):
        """Install flow rule in virtual switch."""
        # Simulate OpenFlow rule installation
        switch_id = 'main_switch'
        flow_entry = {
            'rule_id': rule.rule_id,
            'match': {
                'source': rule.source,
                'destination': rule.destination,
                'protocol': rule.protocol,
                'port': rule.port
            },
            'action': rule.action,
            'priority': rule.priority,
            'timeout': int((rule.expires_at - datetime.now()).total_seconds()) if rule.expires_at else 0
        }

        # Add to switch flow table
        if switch_id not in self.virtual_switches:
            logger.error(f"Virtual switch {switch_id} not found")
            return

        flow_table = self.virtual_switches[switch_id]['flow_table']
        flow_table[rule.rule_id] = flow_entry

        logger.debug(f"Installed flow rule {rule.rule_id} in switch {switch_id}")

    def remove_expired_rules(self):
        """Remove expired network rules."""
        current_time = datetime.now()
        expired_rules = []

        for rule_id, rule in self.active_rules.items():
            if rule.expires_at and current_time > rule.expires_at:
                expired_rules.append(rule_id)

        for rule_id in expired_rules:
            rule = self.active_rules[rule_id]
            del self.active_rules[rule_id]

            # Remove from virtual switch
            for switch_id, switch in self.virtual_switches.items():
                if rule_id in switch['flow_table']:
                    del switch['flow_table'][rule_id]

            logger.info(f"Removed expired rule {rule_id}")

        return len(expired_rules)

    def get_network_status(self) -> Dict[str, Any]:
        """Get current network status and statistics."""
        current_time = datetime.now()

        # Count rules by type
        rule_types = defaultdict(int)
        active_rules_count = len(self.active_rules)

        for rule in self.active_rules.values():
            rule_types[rule.rule_type] += 1

        # Count rules by action
        action_counts = defaultdict(int)
        for rule in self.active_rules.values():
            action_counts[rule.action] += 1

        return {
            'active_rules': active_rules_count,
            'rule_types': dict(rule_types),
            'action_distribution': dict(action_counts),
            'virtual_switches': len(self.virtual_switches),
            'quarantine_networks': list(self.quarantine_networks.keys()),
            'rules_applied_24h': len([
                r for r in self.rule_history
                if current_time - r.created_at <= timedelta(hours=24)
            ]),
            'tls_version': 'TLS 1.3',
            'flow_table_entries': sum(
                len(switch['flow_table'])
                for switch in self.virtual_switches.values()
            )
        }

class EndpointEnforcementAgent:
    """Endpoint enforcement agent for local policy enforcement."""

    def __init__(self):
        self.active_enforcements = {}
        self.enforcement_history = deque(maxlen=5000)
        self.quarantine_status = {}

    def enforce_endpoint_policy(self, entity_id: str, policy_decision: PolicyDecision) -> EnforcementResult:
        """Enforce policy at endpoint level."""
        action_id = f"ep_enforce_{entity_id}_{int(time.time())}"
        enforcement_actions = []
        errors = []
        affected_entities = [entity_id]

        try:
            # Determine enforcement actions based on policy
            if policy_decision.action == PolicyAction.QUARANTINE:
                self._quarantine_endpoint(entity_id, policy_decision)
                enforcement_actions.append(EnforcementAction.QUARANTINE_ENDPOINT)

            elif policy_decision.action == PolicyAction.DENY:
                self._block_endpoint_network(entity_id, policy_decision)
                enforcement_actions.append(EnforcementAction.BLOCK_IP)

            elif policy_decision.action == PolicyAction.RESTRICT:
                self._restrict_endpoint_access(entity_id, policy_decision)
                enforcement_actions.append(EnforcementAction.RESTRICT_NETWORK)

            elif policy_decision.action == PolicyAction.MONITOR:
                self._enable_enhanced_monitoring(entity_id, policy_decision)
                enforcement_actions.append(EnforcementAction.ENABLE_ENHANCED_MONITORING)

            elif policy_decision.action == PolicyAction.AUTHENTICATE:
                self._require_additional_authentication(entity_id, policy_decision)
                enforcement_actions.append(EnforcementAction.REQUIRE_AUTHENTICATION)

            # Apply additional controls
            for control in policy_decision.additional_controls:
                if control == 'session_recording':
                    self._enable_session_recording(entity_id)
                elif control == 'network_isolation':
                    self._isolate_network_session(entity_id)
                    enforcement_actions.append(EnforcementAction.ISOLATE_SESSION)

            success = len(errors) == 0

        except Exception as e:
            errors.append(str(e))
            success = False
            logger.error(f"Endpoint enforcement failed for {entity_id}: {e}")

        result = EnforcementResult(
            action_id=action_id,
            policy_decision_id=policy_decision.decision_id,
            enforcement_actions=enforcement_actions,
            success=success,
            timestamp=datetime.now(),
            affected_entities=affected_entities,
            network_rules_applied=[],  # Endpoint-specific, no network rules
            errors=errors,
            duration_applied=policy_decision.recommended_duration
        )

        self.active_enforcements[action_id] = result
        self.enforcement_history.append(result)

        return result

    def _quarantine_endpoint(self, entity_id: str, policy_decision: PolicyDecision):
        """Quarantine endpoint by isolating it."""
        self.quarantine_status[entity_id] = {
            'quarantined': True,
            'reason': policy_decision.reasoning,
            'timestamp': datetime.now(),
            'policy_decision_id': policy_decision.decision_id,
            'scheduled_release': datetime.now() + timedelta(minutes=policy_decision.recommended_duration or 120)
        }

        # Simulate endpoint quarantine actions
        logger.info(f"Endpoint {entity_id} quarantined due to: {', '.join(policy_decision.reasoning)}")

    def _block_endpoint_network(self, entity_id: str, policy_decision: PolicyDecision):
        """Block network access for endpoint."""
        # Simulate network blocking
        logger.info(f"Network access blocked for endpoint {entity_id}")

    def _restrict_endpoint_access(self, entity_id: str, policy_decision: PolicyDecision):
        """Restrict endpoint access to essential services only."""
        # Simulate access restriction
        logger.info(f"Access restricted for endpoint {entity_id}")

    def _enable_enhanced_monitoring(self, entity_id: str, policy_decision: PolicyDecision):
        """Enable enhanced monitoring for endpoint."""
        # Simulate enhanced monitoring
        logger.info(f"Enhanced monitoring enabled for endpoint {entity_id}")

    def _require_additional_authentication(self, entity_id: str, policy_decision: PolicyDecision):
        """Require additional authentication for endpoint."""
        # Simulate additional authentication requirement
        logger.info(f"Additional authentication required for endpoint {entity_id}")

    def _enable_session_recording(self, entity_id: str):
        """Enable session recording for endpoint."""
        # Simulate session recording
        logger.info(f"Session recording enabled for endpoint {entity_id}")

    def _isolate_network_session(self, entity_id: str):
        """Isolate network session for endpoint."""
        # Simulate network session isolation
        logger.info(f"Network session isolated for endpoint {entity_id}")

    def release_quarantined_endpoints(self):
        """Release endpoints that have completed quarantine duration."""
        current_time = datetime.now()
        released_endpoints = []

        for entity_id, status in list(self.quarantine_status.items()):
            if status['scheduled_release'] and current_time >= status['scheduled_release']:
                del self.quarantine_status[entity_id]
                released_endpoints.append(entity_id)
                logger.info(f"Released endpoint {entity_id} from quarantine")

        return released_endpoints

    def get_enforcement_status(self) -> Dict[str, Any]:
        """Get endpoint enforcement status."""
        return {
            'active_enforcements': len(self.active_enforcements),
            'quarantined_endpoints': len(self.quarantine_status),
            'enforcement_history_size': len(self.enforcement_history),
            'quarantine_details': {
                entity_id: {
                    'reason': status['reason'],
                    'quarantined_at': status['timestamp'],
                    'scheduled_release': status['scheduled_release']
                }
                for entity_id, status in self.quarantine_status.items()
            }
        }

class EnforcementEngine:
    """Main enforcement engine coordinating network and endpoint enforcement."""

    def __init__(self):
        self.sdn_controller = VirtualSDNController()
        self.endpoint_agent = EndpointEnforcementAgent()
        self.enforcement_results = deque(maxlen=10000)

        # Automated cleanup
        self.cleanup_thread = None
        self.cleanup_running = False

    def start_enforcement_services(self):
        """Start enforcement services and cleanup tasks."""
        if self.cleanup_running:
            return

        self.cleanup_running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

        logger.info("Enforcement services started")

    def stop_enforcement_services(self):
        """Stop enforcement services."""
        self.cleanup_running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)

        logger.info("Enforcement services stopped")

    def _cleanup_loop(self):
        """Automated cleanup loop for expired rules and quarantines."""
        while self.cleanup_running:
            try:
                # Remove expired network rules
                expired_rules = self.sdn_controller.remove_expired_rules()
                if expired_rules > 0:
                    logger.info(f"Cleaned up {expired_rules} expired network rules")

                # Release quarantined endpoints
                released_endpoints = self.endpoint_agent.release_quarantined_endpoints()
                if released_endpoints:
                    logger.info(f"Released {len(released_endpoints)} endpoints from quarantine")

                time.sleep(60)  # Cleanup every minute

            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                time.sleep(60)

    def enforce_policy_decision(self, policy_decision: PolicyDecision) -> EnforcementResult:
        """
        Enforce a policy decision across network and endpoint layers.

        Args:
            policy_decision: Policy decision to enforce

        Returns:
            Enforcement result
        """
        entity_id = policy_decision.entity_id
        action_id = f"enforce_{entity_id}_{int(time.time())}"

        logger.info(f"Enforcing policy decision {policy_decision.decision_id} for {entity_id}")

        # Apply network-level enforcement
        network_rules = self.sdn_controller.apply_network_policy(policy_decision)
        network_rule_ids = [rule.rule_id for rule in network_rules]

        # Apply endpoint-level enforcement
        endpoint_result = self.endpoint_agent.enforce_endpoint_policy(entity_id, policy_decision)

        # Combine enforcement actions
        all_enforcement_actions = [EnforcementAction.APPLY_MICRO_SEGMENTATION]  # Network rules applied
        all_enforcement_actions.extend(endpoint_result.enforcement_actions)

        # Determine overall success
        success = endpoint_result.success and len(network_rules) > 0

        # Combine errors
        all_errors = endpoint_result.errors.copy()

        result = EnforcementResult(
            action_id=action_id,
            policy_decision_id=policy_decision.decision_id,
            enforcement_actions=all_enforcement_actions,
            success=success,
            timestamp=datetime.now(),
            affected_entities=[entity_id],
            network_rules_applied=network_rule_ids,
            errors=all_errors,
            duration_applied=policy_decision.recommended_duration
        )

        self.enforcement_results.append(result)

        if success:
            logger.info(f"Successfully enforced policy for {entity_id}: {policy_decision.action.value}")
        else:
            logger.error(f"Enforcement failed for {entity_id}: {all_errors}")

        return result

    def get_enforcement_status(self) -> Dict[str, Any]:
        """Get comprehensive enforcement status."""
        network_status = self.sdn_controller.get_network_status()
        endpoint_status = self.endpoint_agent.get_enforcement_status()

        # Recent enforcement statistics
        recent_results = [
            r for r in self.enforcement_results
            if datetime.now() - r.timestamp <= timedelta(hours=24)
        ]

        success_rate = (
            sum(1 for r in recent_results if r.success) / len(recent_results)
            if recent_results else 0.0
        )

        return {
            'network_enforcement': network_status,
            'endpoint_enforcement': endpoint_status,
            'total_enforcement_actions_24h': len(recent_results),
            'enforcement_success_rate': success_rate,
            'cleanup_services_running': self.cleanup_running,
            'enforcement_results_stored': len(self.enforcement_results)
        }

# Global enforcement engine instance
_enforcement_engine = None

def get_enforcement_engine() -> EnforcementEngine:
    """Get global enforcement engine instance."""
    global _enforcement_engine
    if _enforcement_engine is None:
        _enforcement_engine = EnforcementEngine()
    return _enforcement_engine