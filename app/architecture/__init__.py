"""
Chapter 3 - Four-Layer Adaptive Security Architecture
Software-based cybersecurity solution with AI/ML capabilities

Architecture Layers:
1. Telemetry Collection Layer - Software agents for data collection from virtual endpoints
2. Analytics Layer - Deep Learning-based model adaptation using LSTM-Transformer hybrids
3. Policy Engine Layer - Zero Trust Architecture with continuous risk analysis and UEBA
4. Enforcement Layer - Software-based SDN controllers with API-based policy enforcement
"""

from .telemetry_collection import (
    TelemetryStreamProcessor,
    TelemetryData,
    NetworkTelemetryAgent,
    EndpointTelemetryAgent,
    get_telemetry_processor
)

from .analytics_layer import (
    AnalyticsEngine,
    HybridAnomalyDetector,
    AnalysisResult,
    MitreAttackMapper,
    FeatureExtractor,
    get_analytics_engine
)

from .policy_engine import (
    ZeroTrustPolicyEngine,
    UserEntityBehaviorAnalytics,
    PolicyDecision,
    PolicyAction,
    RiskLevel,
    EntityProfile,
    get_policy_engine
)

from .enforcement_layer import (
    EnforcementEngine,
    VirtualSDNController,
    EndpointEnforcementAgent,
    NetworkRule,
    EnforcementResult,
    EnforcementAction,
    get_enforcement_engine
)

__version__ = "1.0.0"
__architecture__ = "Four-Layer Adaptive Security Suite - Chapter 3"

__all__ = [
    # Telemetry Collection Layer
    'TelemetryStreamProcessor',
    'TelemetryData',
    'NetworkTelemetryAgent',
    'EndpointTelemetryAgent',
    'get_telemetry_processor',

    # Analytics Layer
    'AnalyticsEngine',
    'HybridAnomalyDetector',
    'AnalysisResult',
    'MitreAttackMapper',
    'FeatureExtractor',
    'get_analytics_engine',

    # Policy Engine Layer
    'ZeroTrustPolicyEngine',
    'UserEntityBehaviorAnalytics',
    'PolicyDecision',
    'PolicyAction',
    'RiskLevel',
    'EntityProfile',
    'get_policy_engine',

    # Enforcement Layer
    'EnforcementEngine',
    'VirtualSDNController',
    'EndpointEnforcementAgent',
    'NetworkRule',
    'EnforcementResult',
    'EnforcementAction',
    'get_enforcement_engine'
]