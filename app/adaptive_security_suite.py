"""
Adaptive Security Suite - Chapter 3 Complete Integration
Main integration module that brings together all four layers of the architecture:
- Telemetry Collection Layer
- Analytics Layer
- Policy Engine Layer
- Enforcement Layer

Implements the complete software-based cybersecurity solution with AI and ML capabilities.
"""

import logging
import asyncio
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
import numpy as np
import torch
import json
from pathlib import Path

# Import all architectural layers
from .architecture.telemetry_collection import (
    TelemetryStreamProcessor, TelemetryData, get_telemetry_processor
)
from .architecture.analytics_layer import (
    AnalyticsEngine, AnalysisResult, get_analytics_engine
)
from .architecture.policy_engine import (
    ZeroTrustPolicyEngine, PolicyDecision, get_policy_engine
)
from .architecture.enforcement_layer import (
    EnforcementEngine, EnforcementResult, get_enforcement_engine
)
from .data_preprocessing import get_dataset_processor
from .evolutionary_adaptation import get_evolutionary_engine
from .advanced_adaptive_engine import get_advanced_adaptive_engine

logger = logging.getLogger(__name__)

@dataclass
class AdaptiveSecurityConfig:
    """Configuration for the Adaptive Security Suite."""
    # Telemetry Collection
    telemetry_enabled: bool = True
    telemetry_batch_size: int = 100
    telemetry_processing_interval: float = 1.0  # seconds

    # Analytics
    analytics_enabled: bool = True
    model_training_enabled: bool = True
    ml_model_path: Optional[str] = None

    # Policy Engine
    zero_trust_enabled: bool = True
    continuous_verification_enabled: bool = True
    risk_thresholds: Dict[str, float] = None

    # Enforcement
    enforcement_enabled: bool = True
    sdn_simulation_enabled: bool = True
    endpoint_enforcement_enabled: bool = True

    # Evolutionary Adaptation
    evolutionary_adaptation_enabled: bool = True
    adaptation_interval: int = 24  # hours

    # Advanced Features
    advanced_threat_detection_enabled: bool = True
    privacy_preserving_enabled: bool = False

    def __post_init__(self):
        if self.risk_thresholds is None:
            self.risk_thresholds = {
                'low': 0.3,
                'medium': 0.6,
                'high': 0.8,
                'critical': 0.9
            }

class AdaptiveSecuritySuite:
    """
    Main Adaptive Security Suite implementing Chapter 3.3 System Architecture.

    Integrates all four software layers:
    1. Telemetry Collection Layer: Software agents for data collection
    2. Analytics Layer: DL-based model adaptation (LSTM-Transformer hybrids)
    3. Policy Engine Layer: ZTA continuous risk analysis with UEBA
    4. Enforcement Layer: Software-based SDN controllers with API-based policies
    """

    def __init__(self, config: AdaptiveSecurityConfig = None):
        self.config = config or AdaptiveSecurityConfig()

        # Initialize all components
        self._initialize_components()

        # Runtime state
        self.is_running = False
        self.processing_thread = None
        self.adaptation_thread = None

        # Performance metrics
        self.metrics = {
            'total_telemetry_processed': 0,
            'total_threats_detected': 0,
            'total_policies_enforced': 0,
            'total_adaptations_performed': 0,
            'start_time': None,
            'last_adaptation': None
        }

        # Event handlers
        self.event_handlers = {
            'threat_detected': [],
            'policy_enforced': [],
            'adaptation_completed': [],
            'system_alert': []
        }

    def _initialize_components(self):
        """Initialize all architectural components."""
        logger.info("Initializing Adaptive Security Suite components...")

        # Initialize architectural layers
        if self.config.telemetry_enabled:
            self.telemetry_processor = get_telemetry_processor()
            logger.info("✓ Telemetry Collection Layer initialized")

        if self.config.analytics_enabled:
            self.analytics_engine = get_analytics_engine()
            if self.config.ml_model_path:
                self.analytics_engine.initialize_model()
            logger.info("✓ Analytics Layer initialized")

        if self.config.zero_trust_enabled:
            self.policy_engine = get_policy_engine()
            # Update adaptive thresholds from config
            self.policy_engine.adaptive_thresholds.update(self.config.risk_thresholds)
            logger.info("✓ Policy Engine Layer initialized")

        if self.config.enforcement_enabled:
            self.enforcement_engine = get_enforcement_engine()
            logger.info("✓ Enforcement Layer initialized")

        # Initialize supporting components
        self.dataset_processor = get_dataset_processor()

        if self.config.evolutionary_adaptation_enabled:
            self.evolutionary_engine = get_evolutionary_engine()
            logger.info("✓ Evolutionary Adaptation Engine initialized")

        if self.config.advanced_threat_detection_enabled:
            self.advanced_engine = get_advanced_adaptive_engine()
            logger.info("✓ Advanced Adaptive Engine initialized")

        logger.info("All components initialized successfully")

    def start_suite(self):
        """Start the complete Adaptive Security Suite."""
        if self.is_running:
            logger.warning("Adaptive Security Suite is already running")
            return

        logger.info("Starting Adaptive Security Suite...")
        self.metrics['start_time'] = datetime.now()
        self.is_running = True

        try:
            # Start all layers
            if self.config.telemetry_enabled:
                self.telemetry_processor.start_stream_processing()
                # Subscribe to telemetry stream
                self.telemetry_processor.subscribe(self._process_telemetry_callback)

            if self.config.zero_trust_enabled and self.config.continuous_verification_enabled:
                self.policy_engine.start_continuous_verification()

            if self.config.enforcement_enabled:
                self.enforcement_engine.start_enforcement_services()

            # Start main processing loop
            self.processing_thread = threading.Thread(target=self._main_processing_loop)
            self.processing_thread.daemon = True
            self.processing_thread.start()

            # Start evolutionary adaptation loop
            if self.config.evolutionary_adaptation_enabled:
                self.adaptation_thread = threading.Thread(target=self._adaptation_loop)
                self.adaptation_thread.daemon = True
                self.adaptation_thread.start()

            logger.info("🚀 Adaptive Security Suite started successfully")
            self._emit_event('system_alert', {
                'type': 'suite_started',
                'timestamp': datetime.now(),
                'message': 'Adaptive Security Suite operational'
            })

        except Exception as e:
            logger.error(f"Failed to start Adaptive Security Suite: {e}")
            self.stop_suite()
            raise

    def stop_suite(self):
        """Stop the Adaptive Security Suite."""
        if not self.is_running:
            return

        logger.info("Stopping Adaptive Security Suite...")
        self.is_running = False

        # Stop all components
        if hasattr(self, 'telemetry_processor'):
            self.telemetry_processor.stop_stream_processing()

        if hasattr(self, 'policy_engine'):
            self.policy_engine.stop_continuous_verification()

        if hasattr(self, 'enforcement_engine'):
            self.enforcement_engine.stop_enforcement_services()

        # Wait for threads to complete
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5)

        if self.adaptation_thread and self.adaptation_thread.is_alive():
            self.adaptation_thread.join(timeout=5)

        logger.info("✓ Adaptive Security Suite stopped")

    def _main_processing_loop(self):
        """
        Main processing loop implementing the Chapter 3.4 process flow:
        1. Telemetry Ingestion: Simulate ingest of data from virtual sources
        2. Preprocessing: Clean and normalize data using Pandas pipelines
        3. Analysis: Execute ML detection models within PyTorch runtime
        4. Policy Decision: Compute risks and generate virtual actions
        5. Enforcement: Establish software controls; loop back for monitoring
        """
        logger.info("Starting main processing loop")

        while self.is_running:
            try:
                # Step 1: Telemetry Ingestion
                telemetry_batch = self._collect_telemetry_batch()

                if telemetry_batch:
                    # Step 2: Preprocessing (handled within analytics)
                    # Step 3: Analysis - Execute ML detection models
                    analysis_results = self._analyze_telemetry_batch(telemetry_batch)

                    # Step 4: Policy Decision - Compute risks and generate actions
                    policy_decisions = self._evaluate_policies(telemetry_batch, analysis_results)

                    # Step 5: Enforcement - Establish software controls
                    enforcement_results = self._enforce_policies(policy_decisions)

                    # Update metrics
                    self.metrics['total_telemetry_processed'] += len(telemetry_batch)

                    # Process results
                    self._process_detection_results(analysis_results, policy_decisions, enforcement_results)

                # Loop back for continued monitoring
                time.sleep(self.config.telemetry_processing_interval)

            except Exception as e:
                logger.error(f"Error in main processing loop: {e}")
                time.sleep(5)  # Back off on error

    def _collect_telemetry_batch(self) -> List[TelemetryData]:
        """Collect batch of telemetry data from all sources."""
        if not self.config.telemetry_enabled:
            return []

        return self.telemetry_processor.get_stream_batch(
            batch_size=self.config.telemetry_batch_size,
            timeout=self.config.telemetry_processing_interval
        )

    def _analyze_telemetry_batch(self, telemetry_batch: List[TelemetryData]) -> List[AnalysisResult]:
        """Analyze telemetry batch using ML models."""
        if not self.config.analytics_enabled:
            return []

        # Use analytics engine for ML-based analysis
        ml_results = self.analytics_engine.analyze_telemetry_batch(telemetry_batch)

        # Use advanced engine for modern threat detection
        advanced_results = []
        if self.config.advanced_threat_detection_enabled:
            for telemetry in telemetry_batch:
                # Convert telemetry to format expected by advanced engine
                advanced_data = {
                    'payload': telemetry.payload,
                    'metadata': telemetry.metadata,
                    'timestamp': telemetry.timestamp.isoformat()
                }

                advanced_result = self.advanced_engine.detect_modern_threats(advanced_data)
                if advanced_result['threats_detected']:
                    # Convert to AnalysisResult format
                    analysis_result = AnalysisResult(
                        anomaly_score=advanced_result['risk_score'],
                        is_anomalous=True,
                        threat_classification='modern_threat',
                        confidence=advanced_result['confidence'],
                        mitre_tactics=[],
                        mitre_techniques=[],
                        risk_level='high',
                        timestamp=datetime.now(),
                        features_analyzed=[]
                    )
                    advanced_results.append(analysis_result)

        # Combine results
        all_results = ml_results + advanced_results

        # Count threats detected
        threats_detected = sum(1 for result in all_results if result.is_anomalous)
        self.metrics['total_threats_detected'] += threats_detected

        return all_results

    def _evaluate_policies(self, telemetry_batch: List[TelemetryData],
                         analysis_results: List[AnalysisResult]) -> List[PolicyDecision]:
        """Evaluate policies using Zero Trust engine."""
        if not self.config.zero_trust_enabled:
            return []

        policy_decisions = []

        for telemetry, analysis in zip(telemetry_batch, analysis_results):
            # Extract entity information
            entity_id = telemetry.source
            entity_type = telemetry.data_type

            # Evaluate policy
            decision = self.policy_engine.evaluate_policy(
                entity_id=entity_id,
                entity_type=entity_type,
                telemetry=telemetry,
                analysis=analysis
            )

            policy_decisions.append(decision)

        return policy_decisions

    def _enforce_policies(self, policy_decisions: List[PolicyDecision]) -> List[EnforcementResult]:
        """Enforce policy decisions."""
        if not self.config.enforcement_enabled:
            return []

        enforcement_results = []

        for decision in policy_decisions:
            # Only enforce decisions that require action
            if decision.action.value != 'allow':
                result = self.enforcement_engine.enforce_policy_decision(decision)
                enforcement_results.append(result)

                self.metrics['total_policies_enforced'] += 1

        return enforcement_results

    def _process_detection_results(self, analysis_results: List[AnalysisResult],
                                 policy_decisions: List[PolicyDecision],
                                 enforcement_results: List[EnforcementResult]):
        """Process and emit events for detection results."""
        # Emit threat detection events
        for analysis in analysis_results:
            if analysis.is_anomalous:
                self._emit_event('threat_detected', {
                    'threat_classification': analysis.threat_classification,
                    'confidence': analysis.confidence,
                    'risk_level': analysis.risk_level,
                    'timestamp': analysis.timestamp
                })

        # Emit policy enforcement events
        for decision in policy_decisions:
            if decision.action.value != 'allow':
                self._emit_event('policy_enforced', {
                    'entity_id': decision.entity_id,
                    'action': decision.action.value,
                    'risk_level': decision.risk_level.value,
                    'confidence': decision.confidence,
                    'timestamp': decision.timestamp
                })

    def _adaptation_loop(self):
        """Evolutionary adaptation loop for continuous model improvement."""
        logger.info("Starting evolutionary adaptation loop")

        while self.is_running:
            try:
                # Wait for adaptation interval
                time.sleep(self.config.adaptation_interval * 3600)  # Convert hours to seconds

                if not self.is_running:
                    break

                logger.info("Performing evolutionary model adaptation")

                # Check if we have enough new data for adaptation
                if self._should_perform_adaptation():
                    self._perform_evolutionary_adaptation()

                    self.metrics['total_adaptations_performed'] += 1
                    self.metrics['last_adaptation'] = datetime.now()

                    self._emit_event('adaptation_completed', {
                        'timestamp': datetime.now(),
                        'adaptation_number': self.metrics['total_adaptations_performed']
                    })

            except Exception as e:
                logger.error(f"Error in adaptation loop: {e}")
                time.sleep(3600)  # Wait 1 hour on error

    def _should_perform_adaptation(self) -> bool:
        """Determine if evolutionary adaptation should be performed."""
        # Check if we have processed enough data
        min_telemetry_threshold = 10000

        # Check if model performance has degraded
        # (In a real implementation, this would check actual performance metrics)

        return (self.metrics['total_telemetry_processed'] >= min_telemetry_threshold and
                self.config.evolutionary_adaptation_enabled)

    def _perform_evolutionary_adaptation(self):
        """Perform evolutionary adaptation of the ML model."""
        try:
            # Get current model
            if hasattr(self.analytics_engine, 'model') and self.analytics_engine.model:
                base_model = self.analytics_engine.model

                # Generate synthetic new data batch and validation data
                # In a real implementation, this would be actual new data
                new_data_batch = self._generate_adaptation_data()
                validation_data = self._generate_validation_data()

                # Perform evolutionary adaptation
                evolution_result = self.evolutionary_engine.adapt_model(
                    base_model=base_model,
                    new_data_batch=new_data_batch,
                    validation_data=validation_data
                )

                logger.info(f"Evolutionary adaptation completed with fitness: {evolution_result.best_fitness:.4f}")

                # Update analytics engine with evolved model
                model_ops = self.evolutionary_engine.ModelEvolutionOperators(None)
                evolved_model = model_ops.create_model_from_individual(evolution_result.best_individual)
                self.analytics_engine.model = evolved_model

        except Exception as e:
            logger.error(f"Evolutionary adaptation failed: {e}")

    def _generate_adaptation_data(self) -> tuple:
        """Generate data for evolutionary adaptation."""
        # Synthetic data generation for demonstration
        X = torch.randn(1000, 10, 49)  # Batch, sequence, features
        y = torch.randint(0, 2, (1000,))  # Binary labels
        return X, y

    def _generate_validation_data(self) -> tuple:
        """Generate validation data for fitness evaluation."""
        # Synthetic validation data
        X = torch.randn(200, 10, 49)
        y = torch.randint(0, 2, (200,))
        return X, y

    def _process_telemetry_callback(self, telemetry: TelemetryData):
        """Callback for real-time telemetry processing."""
        # This is called for each telemetry data point in real-time
        # Can be used for immediate threat detection or alerting

        if telemetry.risk_indicators:
            logger.debug(f"Risk indicators detected from {telemetry.source}: {telemetry.risk_indicators}")

    def _emit_event(self, event_type: str, event_data: Dict[str, Any]):
        """Emit event to registered handlers."""
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    handler(event_data)
                except Exception as e:
                    logger.error(f"Event handler error for {event_type}: {e}")

    def register_event_handler(self, event_type: str, handler: Callable):
        """Register an event handler."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []

        self.event_handlers[event_type].append(handler)
        logger.info(f"Registered handler for {event_type} events")

    def train_initial_models(self, training_data_path: Optional[str] = None):
        """Train initial ML models using specified datasets."""
        if not self.config.model_training_enabled:
            logger.info("Model training disabled in configuration")
            return

        logger.info("Training initial models...")

        try:
            # Load or generate training data
            if training_data_path:
                # Load from file
                import pandas as pd
                df = pd.read_csv(training_data_path)
            else:
                # Use UNSW-NB15 synthetic data
                df = self.dataset_processor.load_unsw_nb15('')

            # Process dataset
            processed_data = self.dataset_processor.process_dataset(
                df=df,
                dataset_name='unsw_nb15',
                target_column='attack_cat',
                apply_privacy=self.config.privacy_preserving_enabled
            )

            # Train analytics model
            training_data = [
                # Convert processed data to TelemetryData format for training
                # This is a simplified conversion
            ]

            if hasattr(self.analytics_engine, 'train_model'):
                training_metrics = self.analytics_engine.train_model(
                    training_data=training_data,
                    epochs=50
                )

                logger.info("Initial model training completed")
                logger.info(f"Training metrics: {training_metrics}")

        except Exception as e:
            logger.error(f"Initial model training failed: {e}")

    def get_suite_status(self) -> Dict[str, Any]:
        """Get comprehensive status of the Adaptive Security Suite."""
        status = {
            'is_running': self.is_running,
            'uptime': None,
            'metrics': self.metrics.copy(),
            'components': {},
            'performance': {}
        }

        if self.metrics['start_time']:
            uptime = datetime.now() - self.metrics['start_time']
            status['uptime'] = str(uptime)

        # Component statuses
        if hasattr(self, 'telemetry_processor'):
            status['components']['telemetry'] = self.telemetry_processor.get_telemetry_stats()

        if hasattr(self, 'analytics_engine'):
            status['components']['analytics'] = self.analytics_engine.get_analytics_stats()

        if hasattr(self, 'policy_engine'):
            status['components']['policy'] = self.policy_engine.get_policy_stats()

        if hasattr(self, 'enforcement_engine'):
            status['components']['enforcement'] = self.enforcement_engine.get_enforcement_status()

        if hasattr(self, 'evolutionary_engine'):
            status['components']['evolution'] = self.evolutionary_engine.get_adaptation_stats()

        if hasattr(self, 'advanced_engine'):
            status['components']['advanced'] = self.advanced_engine.get_advanced_model_info()

        # Performance metrics
        if self.metrics['start_time']:
            runtime_hours = (datetime.now() - self.metrics['start_time']).total_seconds() / 3600
            if runtime_hours > 0:
                status['performance'] = {
                    'telemetry_per_hour': self.metrics['total_telemetry_processed'] / runtime_hours,
                    'threats_per_hour': self.metrics['total_threats_detected'] / runtime_hours,
                    'policies_per_hour': self.metrics['total_policies_enforced'] / runtime_hours,
                }

        return status

    def save_suite_state(self, output_dir: str):
        """Save complete suite state for persistence."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save configuration
        config_dict = {
            'telemetry_enabled': self.config.telemetry_enabled,
            'analytics_enabled': self.config.analytics_enabled,
            'zero_trust_enabled': self.config.zero_trust_enabled,
            'enforcement_enabled': self.config.enforcement_enabled,
            'evolutionary_adaptation_enabled': self.config.evolutionary_adaptation_enabled,
            'risk_thresholds': self.config.risk_thresholds
        }

        with open(output_path / 'suite_config.json', 'w') as f:
            json.dump(config_dict, f, indent=2)

        # Save metrics
        with open(output_path / 'suite_metrics.json', 'w') as f:
            json.dump(self.metrics, f, indent=2, default=str)

        # Save component states
        if hasattr(self, 'advanced_engine'):
            self.advanced_engine.save_advanced_model()

        if hasattr(self, 'evolutionary_engine'):
            self.evolutionary_engine.save_evolution_results(str(output_path / 'evolution'))

        logger.info(f"Suite state saved to {output_dir}")

# Global suite instance
_adaptive_suite = None

def get_adaptive_security_suite(config: AdaptiveSecurityConfig = None) -> AdaptiveSecuritySuite:
    """Get global Adaptive Security Suite instance."""
    global _adaptive_suite
    if _adaptive_suite is None:
        _adaptive_suite = AdaptiveSecuritySuite(config)
    return _adaptive_suite

def create_default_suite() -> AdaptiveSecuritySuite:
    """Create Adaptive Security Suite with default configuration."""
    config = AdaptiveSecurityConfig(
        telemetry_enabled=True,
        analytics_enabled=True,
        zero_trust_enabled=True,
        enforcement_enabled=True,
        evolutionary_adaptation_enabled=True,
        advanced_threat_detection_enabled=True,
        model_training_enabled=True
    )

    return AdaptiveSecuritySuite(config)