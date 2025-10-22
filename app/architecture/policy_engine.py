"""
Policy Engine Layer - Chapter 3.3 System Architecture
Executes continuous risk analysis in compliance with Zero Trust Architecture (ZTA) rules.
Incorporates User/Entity Behavior Analytics (UEBA) and virtual device posture simulations.
Supports AI-powered policy automation as per 2025 zero trust trends.
"""

import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import threading
import queue

from .analytics_layer import AnalysisResult
from .telemetry_collection import TelemetryData

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PolicyAction(Enum):
    """Policy action enumeration."""
    ALLOW = "allow"
    DENY = "deny"
    QUARANTINE = "quarantine"
    MONITOR = "monitor"
    AUTHENTICATE = "authenticate"
    RESTRICT = "restrict"

@dataclass
class PolicyDecision:
    """Policy decision data structure."""
    decision_id: str
    timestamp: datetime
    entity_id: str
    entity_type: str
    action: PolicyAction
    risk_level: RiskLevel
    confidence: float
    reasoning: List[str]
    mitre_tactics: List[str]
    recommended_duration: Optional[int]  # minutes
    additional_controls: List[str]

@dataclass
class EntityProfile:
    """Entity behavior profile for UEBA."""
    entity_id: str
    entity_type: str  # user, device, application
    baseline_behavior: Dict[str, float]
    recent_activities: List[Dict[str, Any]]
    risk_score: float
    trust_level: float
    last_updated: datetime
    anomaly_history: List[str]
    compliance_status: str

class UserEntityBehaviorAnalytics:
    """User and Entity Behavior Analytics (UEBA) component."""

    def __init__(self):
        self.entity_profiles = {}
        self.behavior_baselines = {}
        self.anomaly_detector = DBSCAN(eps=0.5, min_samples=3)
        self.scaler = StandardScaler()
        self.learning_window = timedelta(days=7)

    def update_entity_behavior(self, entity_id: str, entity_type: str,
                              telemetry: TelemetryData, analysis: AnalysisResult):
        """Update entity behavior profile with new telemetry data."""

        if entity_id not in self.entity_profiles:
            self.entity_profiles[entity_id] = EntityProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                baseline_behavior={},
                recent_activities=[],
                risk_score=0.0,
                trust_level=1.0,
                last_updated=datetime.now(),
                anomaly_history=[],
                compliance_status="compliant"
            )

        profile = self.entity_profiles[entity_id]

        # Extract behavioral features
        behavior_features = self._extract_behavioral_features(telemetry, analysis)

        # Update recent activities (keep last 1000)
        activity = {
            'timestamp': telemetry.timestamp,
            'data_type': telemetry.data_type,
            'risk_indicators': telemetry.risk_indicators,
            'anomaly_score': analysis.anomaly_score,
            'features': behavior_features
        }
        profile.recent_activities.append(activity)
        if len(profile.recent_activities) > 1000:
            profile.recent_activities.pop(0)

        # Update baseline behavior
        self._update_baseline(profile, behavior_features)

        # Calculate risk score
        profile.risk_score = self._calculate_entity_risk_score(profile)

        # Update trust level
        profile.trust_level = self._calculate_trust_level(profile)

        # Update anomaly history
        if analysis.is_anomalous:
            profile.anomaly_history.append(f"{telemetry.timestamp}: {analysis.threat_classification}")
            if len(profile.anomaly_history) > 100:
                profile.anomaly_history.pop(0)

        # Update compliance status
        profile.compliance_status = self._assess_compliance_status(profile)

        profile.last_updated = datetime.now()

        logger.debug(f"Updated UEBA profile for {entity_id}: risk={profile.risk_score:.3f}, trust={profile.trust_level:.3f}")

    def _extract_behavioral_features(self, telemetry: TelemetryData,
                                   analysis: AnalysisResult) -> Dict[str, float]:
        """Extract behavioral features from telemetry and analysis."""
        features = {}

        # Temporal features
        features['hour_of_day'] = telemetry.timestamp.hour
        features['day_of_week'] = telemetry.timestamp.weekday()
        features['is_weekend'] = float(telemetry.timestamp.weekday() >= 5)

        # Activity features
        features['risk_indicator_count'] = len(telemetry.risk_indicators)
        features['anomaly_score'] = analysis.anomaly_score
        features['confidence'] = analysis.confidence

        # Payload-specific features
        payload = telemetry.payload
        if 'cpu_usage' in payload:
            features['cpu_usage'] = float(payload['cpu_usage'])
        if 'memory_usage' in payload:
            features['memory_usage'] = float(payload['memory_usage'])
        if 'network_connections' in payload:
            features['network_connections'] = float(payload['network_connections'])
        if 'failed_logins' in payload:
            features['failed_logins'] = float(payload['failed_logins'])

        # MITRE ATT&CK features
        features['mitre_tactic_count'] = len(analysis.mitre_tactics)
        features['mitre_technique_count'] = len(analysis.mitre_techniques)

        return features

    def _update_baseline(self, profile: EntityProfile, features: Dict[str, float]):
        """Update baseline behavior using exponential moving average."""
        alpha = 0.1  # Learning rate

        for feature, value in features.items():
            if feature in profile.baseline_behavior:
                # Exponential moving average
                profile.baseline_behavior[feature] = (
                    alpha * value + (1 - alpha) * profile.baseline_behavior[feature]
                )
            else:
                profile.baseline_behavior[feature] = value

    def _calculate_entity_risk_score(self, profile: EntityProfile) -> float:
        """Calculate entity risk score based on behavior analysis."""
        if not profile.recent_activities:
            return 0.0

        # Recent activity risk
        recent_activities = [
            a for a in profile.recent_activities
            if datetime.now() - a['timestamp'] <= timedelta(hours=24)
        ]

        if not recent_activities:
            return profile.risk_score * 0.9  # Decay existing risk

        # Average anomaly score in last 24 hours
        avg_anomaly_score = np.mean([a['anomaly_score'] for a in recent_activities])

        # Risk indicator frequency
        total_risk_indicators = sum(len(a['risk_indicators']) for a in recent_activities)
        risk_indicator_rate = total_risk_indicators / len(recent_activities)

        # Anomaly history impact
        recent_anomalies = sum(1 for a in profile.anomaly_history
                              if datetime.now() - datetime.fromisoformat(a.split(':')[0]) <= timedelta(days=7))

        # Combine risk factors
        base_risk = avg_anomaly_score * 0.5
        indicator_risk = min(risk_indicator_rate * 0.1, 0.3)
        history_risk = min(recent_anomalies * 0.05, 0.2)

        total_risk = base_risk + indicator_risk + history_risk

        return min(total_risk, 1.0)

    def _calculate_trust_level(self, profile: EntityProfile) -> float:
        """Calculate entity trust level based on historical behavior."""
        # Trust starts at 1.0 and decreases with risky behavior
        base_trust = 1.0

        # Recent risk impact
        trust_decay = profile.risk_score * 0.5

        # Compliance impact
        compliance_bonus = 0.1 if profile.compliance_status == "compliant" else -0.2

        # Historical consistency (reward consistent behavior)
        if len(profile.recent_activities) > 50:
            feature_consistency = self._calculate_behavior_consistency(profile)
            consistency_bonus = feature_consistency * 0.2
        else:
            consistency_bonus = 0.0

        trust_level = base_trust - trust_decay + compliance_bonus + consistency_bonus

        return max(0.0, min(trust_level, 1.0))

    def _calculate_behavior_consistency(self, profile: EntityProfile) -> float:
        """Calculate how consistent the entity's behavior is."""
        if len(profile.recent_activities) < 10:
            return 0.5

        # Extract feature vectors from recent activities
        feature_vectors = []
        for activity in profile.recent_activities[-50:]:  # Last 50 activities
            if 'features' in activity:
                vector = list(activity['features'].values())
                feature_vectors.append(vector)

        if not feature_vectors or not all(len(v) == len(feature_vectors[0]) for v in feature_vectors):
            return 0.5

        # Calculate coefficient of variation for each feature
        feature_matrix = np.array(feature_vectors)
        cvs = []

        for i in range(feature_matrix.shape[1]):
            mean_val = np.mean(feature_matrix[:, i])
            std_val = np.std(feature_matrix[:, i])
            if mean_val > 0:
                cv = std_val / mean_val
                cvs.append(cv)

        if not cvs:
            return 0.5

        # Lower CV means more consistent behavior
        avg_cv = np.mean(cvs)
        consistency_score = max(0.0, 1.0 - avg_cv)

        return consistency_score

    def _assess_compliance_status(self, profile: EntityProfile) -> str:
        """Assess entity compliance status."""
        if profile.risk_score > 0.8:
            return "non_compliant"
        elif profile.risk_score > 0.5:
            return "at_risk"
        elif profile.trust_level > 0.8:
            return "compliant"
        else:
            return "under_review"

    def get_entity_risk_assessment(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive risk assessment for an entity."""
        if entity_id not in self.entity_profiles:
            return None

        profile = self.entity_profiles[entity_id]

        return {
            'entity_id': entity_id,
            'entity_type': profile.entity_type,
            'risk_score': profile.risk_score,
            'trust_level': profile.trust_level,
            'compliance_status': profile.compliance_status,
            'recent_anomaly_count': len([
                a for a in profile.anomaly_history
                if datetime.now() - datetime.fromisoformat(a.split(':')[0]) <= timedelta(days=1)
            ]),
            'baseline_established': len(profile.recent_activities) > 50,
            'last_activity': profile.recent_activities[-1]['timestamp'] if profile.recent_activities else None,
            'recommendation': self._get_entity_recommendation(profile)
        }

    def _get_entity_recommendation(self, profile: EntityProfile) -> str:
        """Get recommendation for entity based on risk assessment."""
        if profile.risk_score > 0.9:
            return "immediate_action_required"
        elif profile.risk_score > 0.7:
            return "enhanced_monitoring"
        elif profile.trust_level < 0.3:
            return "trust_verification"
        elif profile.compliance_status == "non_compliant":
            return "compliance_review"
        else:
            return "continue_monitoring"

class ZeroTrustPolicyEngine:
    """Zero Trust Architecture policy engine with continuous verification."""

    def __init__(self):
        self.ueba = UserEntityBehaviorAnalytics()
        self.policy_rules = self._initialize_policy_rules()
        self.decision_cache = {}
        self.decision_history = deque(maxlen=50000)
        self.adaptive_thresholds = {
            'risk_threshold_low': 0.3,
            'risk_threshold_medium': 0.6,
            'risk_threshold_high': 0.8,
            'trust_threshold_minimum': 0.4,
            'anomaly_threshold': 0.5
        }

        # Continuous verification components
        self.verification_queue = queue.Queue(maxsize=10000)
        self.verification_thread = None
        self.is_running = False

    def _initialize_policy_rules(self) -> Dict[str, Any]:
        """Initialize zero trust policy rules."""
        return {
            'default_policy': PolicyAction.DENY,
            'risk_based_rules': {
                RiskLevel.LOW: {
                    'default_action': PolicyAction.ALLOW,
                    'additional_controls': ['logging', 'monitoring']
                },
                RiskLevel.MEDIUM: {
                    'default_action': PolicyAction.MONITOR,
                    'additional_controls': ['enhanced_logging', 'behavior_analysis']
                },
                RiskLevel.HIGH: {
                    'default_action': PolicyAction.RESTRICT,
                    'additional_controls': ['multi_factor_auth', 'session_recording']
                },
                RiskLevel.CRITICAL: {
                    'default_action': PolicyAction.QUARANTINE,
                    'additional_controls': ['immediate_alert', 'incident_response']
                }
            },
            'mitre_tactic_rules': {
                'initial_access': {
                    'min_action': PolicyAction.AUTHENTICATE,
                    'controls': ['access_review', 'credential_verification']
                },
                'privilege_escalation': {
                    'min_action': PolicyAction.DENY,
                    'controls': ['privilege_verification', 'admin_approval']
                },
                'defense_evasion': {
                    'min_action': PolicyAction.QUARANTINE,
                    'controls': ['behavioral_analysis', 'forensic_collection']
                },
                'exfiltration': {
                    'min_action': PolicyAction.DENY,
                    'controls': ['network_isolation', 'data_loss_prevention']
                }
            },
            'trust_based_rules': {
                'high_trust': {  # Trust > 0.8
                    'allow_actions': ['standard_access', 'resource_access'],
                    'reduced_friction': True
                },
                'medium_trust': {  # Trust 0.4-0.8
                    'require_verification': True,
                    'additional_monitoring': True
                },
                'low_trust': {  # Trust < 0.4
                    'default_action': PolicyAction.DENY,
                    'require_admin_approval': True
                }
            }
        }

    def start_continuous_verification(self):
        """Start continuous verification process."""
        if self.is_running:
            return

        self.is_running = True
        self.verification_thread = threading.Thread(target=self._continuous_verification_loop)
        self.verification_thread.daemon = True
        self.verification_thread.start()

        logger.info("Zero Trust continuous verification started")

    def stop_continuous_verification(self):
        """Stop continuous verification process."""
        self.is_running = False
        if self.verification_thread:
            self.verification_thread.join(timeout=5)

        logger.info("Zero Trust continuous verification stopped")

    def _continuous_verification_loop(self):
        """Continuous verification loop for active sessions."""
        while self.is_running:
            try:
                # Re-evaluate all active entities
                for entity_id, profile in self.ueba.entity_profiles.items():
                    # Skip entities with no recent activity
                    if not profile.recent_activities:
                        continue

                    last_activity = profile.recent_activities[-1]['timestamp']
                    if datetime.now() - last_activity > timedelta(hours=1):
                        continue

                    # Re-evaluate entity risk
                    current_assessment = self.ueba.get_entity_risk_assessment(entity_id)
                    if current_assessment:
                        # Check if risk has changed significantly
                        risk_change = abs(current_assessment['risk_score'] -
                                        profile.risk_score) > 0.2

                        if risk_change:
                            # Generate new policy decision
                            decision = self._make_policy_decision(
                                entity_id=entity_id,
                                entity_type=profile.entity_type,
                                current_risk=current_assessment['risk_score'],
                                trust_level=current_assessment['trust_level'],
                                compliance_status=current_assessment['compliance_status']
                            )

                            # Add to verification queue
                            if not self.verification_queue.full():
                                self.verification_queue.put(decision)

                time.sleep(30)  # Re-evaluate every 30 seconds

            except Exception as e:
                logger.error(f"Continuous verification error: {e}")
                time.sleep(60)

    def evaluate_policy(self, entity_id: str, entity_type: str,
                       telemetry: TelemetryData, analysis: AnalysisResult) -> PolicyDecision:
        """
        Evaluate policy for a given entity and context.

        Args:
            entity_id: Unique identifier for the entity
            entity_type: Type of entity (user, device, application)
            telemetry: Telemetry data
            analysis: Analysis result from analytics layer

        Returns:
            Policy decision
        """
        # Update entity behavior in UEBA
        self.ueba.update_entity_behavior(entity_id, entity_type, telemetry, analysis)

        # Get entity risk assessment
        risk_assessment = self.ueba.get_entity_risk_assessment(entity_id)

        # Make policy decision
        decision = self._make_policy_decision(
            entity_id=entity_id,
            entity_type=entity_type,
            current_risk=risk_assessment['risk_score'] if risk_assessment else 0.5,
            trust_level=risk_assessment['trust_level'] if risk_assessment else 0.5,
            compliance_status=risk_assessment['compliance_status'] if risk_assessment else 'unknown',
            analysis_result=analysis,
            telemetry_data=telemetry
        )

        # Cache and store decision
        cache_key = f"{entity_id}_{telemetry.timestamp.isoformat()}"
        self.decision_cache[cache_key] = decision
        self.decision_history.append(decision)

        logger.info(f"Policy decision for {entity_id}: {decision.action.value} (risk: {decision.risk_level.value})")

        return decision

    def _make_policy_decision(self, entity_id: str, entity_type: str,
                            current_risk: float, trust_level: float,
                            compliance_status: str,
                            analysis_result: Optional[AnalysisResult] = None,
                            telemetry_data: Optional[TelemetryData] = None) -> PolicyDecision:
        """Make policy decision based on risk assessment and rules."""

        decision_id = f"pd_{entity_id}_{int(time.time())}"
        reasoning = []

        # Determine risk level
        if current_risk >= self.adaptive_thresholds['risk_threshold_high']:
            risk_level = RiskLevel.CRITICAL if current_risk > 0.9 else RiskLevel.HIGH
        elif current_risk >= self.adaptive_thresholds['risk_threshold_medium']:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Start with risk-based action
        risk_rules = self.policy_rules['risk_based_rules'][risk_level]
        action = risk_rules['default_action']
        additional_controls = risk_rules['additional_controls'].copy()

        reasoning.append(f"Risk level: {risk_level.value} (score: {current_risk:.3f})")

        # Adjust based on trust level
        if trust_level < self.adaptive_thresholds['trust_threshold_minimum']:
            if action == PolicyAction.ALLOW:
                action = PolicyAction.AUTHENTICATE
            additional_controls.append('trust_verification')
            reasoning.append(f"Low trust level: {trust_level:.3f}")
        elif trust_level > 0.8:
            # High trust can reduce restrictions for low/medium risk
            if risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM] and action in [PolicyAction.RESTRICT, PolicyAction.MONITOR]:
                action = PolicyAction.ALLOW
                reasoning.append(f"High trust override: {trust_level:.3f}")

        # Apply MITRE ATT&CK tactic-based rules
        mitre_tactics = []
        if analysis_result and analysis_result.mitre_tactics:
            mitre_tactics = analysis_result.mitre_tactics
            for tactic in analysis_result.mitre_tactics:
                if tactic in self.policy_rules['mitre_tactic_rules']:
                    tactic_rule = self.policy_rules['mitre_tactic_rules'][tactic]
                    min_action = tactic_rule['min_action']

                    # Escalate action if necessary
                    if self._action_severity(min_action) > self._action_severity(action):
                        action = min_action
                        reasoning.append(f"Escalated due to MITRE tactic: {tactic}")

                    additional_controls.extend(tactic_rule['controls'])

        # Compliance status impact
        if compliance_status == 'non_compliant':
            if action == PolicyAction.ALLOW:
                action = PolicyAction.RESTRICT
            additional_controls.append('compliance_review')
            reasoning.append("Non-compliant status")

        # Calculate confidence based on available data
        confidence = self._calculate_decision_confidence(
            current_risk, trust_level, analysis_result, telemetry_data
        )

        # Determine recommended duration for temporary actions
        recommended_duration = self._calculate_action_duration(action, risk_level, current_risk)

        return PolicyDecision(
            decision_id=decision_id,
            timestamp=datetime.now(),
            entity_id=entity_id,
            entity_type=entity_type,
            action=action,
            risk_level=risk_level,
            confidence=confidence,
            reasoning=reasoning,
            mitre_tactics=mitre_tactics,
            recommended_duration=recommended_duration,
            additional_controls=list(set(additional_controls))  # Remove duplicates
        )

    def _action_severity(self, action: PolicyAction) -> int:
        """Return severity level of policy action for comparison."""
        severity_map = {
            PolicyAction.ALLOW: 1,
            PolicyAction.MONITOR: 2,
            PolicyAction.AUTHENTICATE: 3,
            PolicyAction.RESTRICT: 4,
            PolicyAction.DENY: 5,
            PolicyAction.QUARANTINE: 6
        }
        return severity_map.get(action, 3)

    def _calculate_decision_confidence(self, current_risk: float, trust_level: float,
                                     analysis_result: Optional[AnalysisResult],
                                     telemetry_data: Optional[TelemetryData]) -> float:
        """Calculate confidence in policy decision."""
        confidence_factors = []

        # Risk assessment confidence
        if current_risk > 0.8 or current_risk < 0.2:
            confidence_factors.append(0.9)  # High confidence in extreme values
        else:
            confidence_factors.append(0.6)  # Medium confidence in middle range

        # Trust level confidence
        if trust_level > 0.8 or trust_level < 0.3:
            confidence_factors.append(0.8)
        else:
            confidence_factors.append(0.6)

        # Analysis result confidence
        if analysis_result:
            confidence_factors.append(analysis_result.confidence)
        else:
            confidence_factors.append(0.5)

        # Data availability
        if telemetry_data and len(telemetry_data.risk_indicators) > 0:
            confidence_factors.append(0.8)
        else:
            confidence_factors.append(0.5)

        return np.mean(confidence_factors)

    def _calculate_action_duration(self, action: PolicyAction,
                                 risk_level: RiskLevel, risk_score: float) -> Optional[int]:
        """Calculate recommended duration for temporary actions."""
        if action in [PolicyAction.ALLOW, PolicyAction.MONITOR]:
            return None  # No time limit

        # Duration in minutes based on risk level
        base_durations = {
            RiskLevel.LOW: 60,      # 1 hour
            RiskLevel.MEDIUM: 30,   # 30 minutes
            RiskLevel.HIGH: 15,     # 15 minutes
            RiskLevel.CRITICAL: 5   # 5 minutes
        }

        base_duration = base_durations.get(risk_level, 30)

        # Adjust based on specific risk score
        if risk_score > 0.9:
            return base_duration // 2
        elif risk_score < 0.3:
            return base_duration * 2

        return base_duration

    def adapt_thresholds(self, feedback_data: List[Dict[str, Any]]):
        """Adapt policy thresholds based on feedback and performance."""
        if not feedback_data:
            return

        # Analyze false positives and false negatives
        fp_rate = sum(1 for f in feedback_data if f.get('false_positive', False)) / len(feedback_data)
        fn_rate = sum(1 for f in feedback_data if f.get('false_negative', False)) / len(feedback_data)

        # Adjust risk thresholds
        if fp_rate > 0.1:  # Too many false positives
            self.adaptive_thresholds['risk_threshold_high'] = min(0.9, self.adaptive_thresholds['risk_threshold_high'] + 0.05)
            self.adaptive_thresholds['risk_threshold_medium'] = min(0.8, self.adaptive_thresholds['risk_threshold_medium'] + 0.05)
        elif fn_rate > 0.05:  # Too many false negatives
            self.adaptive_thresholds['risk_threshold_high'] = max(0.6, self.adaptive_thresholds['risk_threshold_high'] - 0.05)
            self.adaptive_thresholds['risk_threshold_medium'] = max(0.4, self.adaptive_thresholds['risk_threshold_medium'] - 0.05)

        logger.info(f"Adapted policy thresholds: {self.adaptive_thresholds}")

    def get_policy_stats(self) -> Dict[str, Any]:
        """Get policy engine statistics."""
        if not self.decision_history:
            return {'total_decisions': 0}

        recent_decisions = [
            d for d in self.decision_history
            if datetime.now() - d.timestamp <= timedelta(hours=24)
        ]

        action_distribution = defaultdict(int)
        risk_distribution = defaultdict(int)

        for decision in recent_decisions:
            action_distribution[decision.action.value] += 1
            risk_distribution[decision.risk_level.value] += 1

        return {
            'total_decisions': len(self.decision_history),
            'decisions_24h': len(recent_decisions),
            'action_distribution': dict(action_distribution),
            'risk_distribution': dict(risk_distribution),
            'entities_tracked': len(self.ueba.entity_profiles),
            'adaptive_thresholds': self.adaptive_thresholds,
            'verification_queue_size': self.verification_queue.qsize(),
            'continuous_verification_active': self.is_running
        }

# Global policy engine instance
_policy_engine = None

def get_policy_engine() -> ZeroTrustPolicyEngine:
    """Get global policy engine instance."""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = ZeroTrustPolicyEngine()
    return _policy_engine