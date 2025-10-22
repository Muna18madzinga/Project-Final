"""
Advanced Adaptive Security Engine for Modern Threats (2024-2025)
Self-adapting system for adversarial ML attacks, zero-day vulnerabilities, and AI-powered threats
"""

import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from collections import defaultdict, deque
import hashlib
import json
import re
import math
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib
import os

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligence:
    """Modern threat intelligence data structure."""
    threat_id: str
    threat_type: str
    indicators: List[str]
    confidence: float
    first_seen: datetime
    last_seen: datetime
    attack_vector: str
    severity: int
    source: str
    metadata: Dict[str, Any]

@dataclass
class AdversarialAttack:
    """Adversarial ML attack detection result."""
    is_adversarial: bool
    attack_type: str
    confidence: float
    perturbation_score: float
    original_input: Any
    modified_input: Any
    timestamp: datetime

class AdvancedThreatPatterns:
    """Modern threat pattern detection for 2024-2025."""
    
    def __init__(self):
        self.ai_social_engineering_patterns = {
            'deepfake_indicators': [
                r'urgent.{0,20}verify.{0,20}account',
                r'click.{0,10}here.{0,10}immediately',
                r'suspended.{0,20}restore.{0,20}access',
                r'congratulations.{0,20}won.{0,20}\$[\d,]+',
            ],
            'voice_cloning_indicators': [
                r'audio.{0,10}quality.{0,10}poor',
                r'background.{0,10}noise.{0,10}consistent',
                r'emotional.{0,10}tone.{0,10}flat',
                r'speech.{0,10}pattern.{0,10}robotic',
            ],
            'llm_generated_content': [
                r'as.{0,5}an.{0,5}ai.{0,5}language.{0,5}model',
                r'i.{0,5}apologize.{0,5}but.{0,5}cannot',
                r'please.{0,5}note.{0,5}that.{0,5}i.{0,5}am',
                r'however.{0,5}i.{0,5}must.{0,5}clarify',
            ]
        }
        
        self.zero_day_indicators = {
            'exploit_signatures': [
                r'ROP.{0,10}chain.{0,10}gadget',
                r'heap.{0,10}spray.{0,10}technique',
                r'return.{0,10}oriented.{0,10}programming',
                r'use.{0,10}after.{0,10}free',
                r'buffer.{0,10}overflow.{0,10}exploit',
            ],
            'unknown_binary_patterns': [
                r'[\x00-\x08\x0e-\x1f\x7f-\xff]{20,}',  # Suspicious binary sequences
                r'\x90{10,}',  # NOP sleds
                r'\xcc{5,}',   # INT3 instructions
            ],
            'memory_corruption': [
                r'AAAA.{0,50}BBBB.{0,50}CCCC',
                r'%p%p%p%p',  # Format string attacks
                r'\x41{100,}',  # Large 'A' patterns
            ]
        }
        
        self.adversarial_ml_patterns = {
            'evasion_attempts': [
                r'gradient.{0,10}descent.{0,10}attack',
                r'FGSM.{0,10}perturbation',
                r'adversarial.{0,10}example',
                r'model.{0,10}inversion',
            ],
            'data_poisoning': [
                r'training.{0,10}data.{0,10}manipulation',
                r'backdoor.{0,10}trigger',
                r'label.{0,10}flipping',
                r'clean.{0,10}label.{0,10}attack',
            ],
            'model_extraction': [
                r'query.{0,10}complexity.{0,10}analysis',
                r'model.{0,10}stealing',
                r'API.{0,10}abuse.{0,10}extraction',
                r'decision.{0,10}boundary.{0,10}probe',
            ]
        }

class AdversarialMLDetector:
    """Detect adversarial attacks against ML models."""
    
    def __init__(self):
        self.baseline_model = IsolationForest(contamination=0.1, random_state=42)
        self.perturbation_detector = DBSCAN(eps=0.3, min_samples=5)
        self.input_validator = StandardScaler()
        self.is_trained = False
        self.normal_input_distribution = None
        self.statistical_thresholds = {}
        
    def train_baseline(self, normal_inputs: List[np.ndarray]):
        """Train baseline model on normal inputs."""
        if not normal_inputs:
            return
            
        # Flatten and normalize inputs
        X = np.array([inp.flatten() if hasattr(inp, 'flatten') else np.array(inp) for inp in normal_inputs])
        
        # Handle variable input sizes by padding/truncating
        max_len = max(len(x) for x in X)
        X_normalized = []
        for x in X:
            if len(x) < max_len:
                x = np.pad(x, (0, max_len - len(x)), mode='constant')
            elif len(x) > max_len:
                x = x[:max_len]
            X_normalized.append(x)
        
        X_normalized = np.array(X_normalized)
        X_scaled = self.input_validator.fit_transform(X_normalized)
        
        # Train anomaly detector
        self.baseline_model.fit(X_scaled)
        
        # Store statistical properties
        self.normal_input_distribution = {
            'mean': np.mean(X_scaled, axis=0),
            'std': np.std(X_scaled, axis=0),
            'min': np.min(X_scaled, axis=0),
            'max': np.max(X_scaled, axis=0)
        }
        
        # Set statistical thresholds
        self.statistical_thresholds = {
            'l2_norm_threshold': np.mean([np.linalg.norm(x) for x in X_scaled]) + 2 * np.std([np.linalg.norm(x) for x in X_scaled]),
            'perturbation_threshold': 0.05,  # 5% deviation threshold
            'frequency_threshold': np.mean([np.sum(np.abs(np.fft.fft(x.real))) for x in X_scaled if len(x) > 0])
        }
        
        self.is_trained = True
        logger.info("Adversarial ML detector trained on {} normal samples".format(len(normal_inputs)))
    
    def detect_adversarial_input(self, input_data: np.ndarray) -> AdversarialAttack:
        """Detect if input is adversarially crafted."""
        if not self.is_trained:
            logger.warning("Adversarial detector not trained, returning no attack detected")
            return AdversarialAttack(
                is_adversarial=False,
                attack_type='unknown',
                confidence=0.0,
                perturbation_score=0.0,
                original_input=input_data,
                modified_input=input_data,
                timestamp=datetime.now()
            )
        
        # Normalize input
        if hasattr(input_data, 'flatten'):
            input_flat = input_data.flatten()
        else:
            input_flat = np.array(input_data)
        
        # Pad/truncate to match training size
        expected_size = len(self.normal_input_distribution['mean'])
        if len(input_flat) < expected_size:
            input_flat = np.pad(input_flat, (0, expected_size - len(input_flat)), mode='constant')
        elif len(input_flat) > expected_size:
            input_flat = input_flat[:expected_size]
        
        input_scaled = self.input_validator.transform([input_flat])[0]
        
        # Statistical anomaly detection
        anomaly_score = self.baseline_model.predict([input_scaled])[0]  # -1 = anomaly, 1 = normal
        decision_score = abs(self.baseline_model.decision_function([input_scaled])[0])
        
        # Perturbation analysis
        perturbation_score = self._calculate_perturbation_score(input_scaled)
        
        # Frequency analysis
        frequency_anomaly = self._detect_frequency_anomaly(input_scaled)
        
        # Statistical distribution analysis
        distribution_anomaly = self._detect_distribution_anomaly(input_scaled)
        
        # Combine all indicators
        is_adversarial = (
            anomaly_score == -1 or
            perturbation_score > self.statistical_thresholds['perturbation_threshold'] or
            frequency_anomaly or
            distribution_anomaly
        )
        
        # Determine attack type
        attack_type = self._classify_attack_type(input_scaled, perturbation_score, frequency_anomaly)
        
        # Calculate overall confidence
        confidence = min(1.0, (decision_score + perturbation_score + (0.5 if frequency_anomaly else 0)) / 3)
        
        return AdversarialAttack(
            is_adversarial=is_adversarial,
            attack_type=attack_type,
            confidence=confidence,
            perturbation_score=perturbation_score,
            original_input=input_data,
            modified_input=input_data,  # Would need original for comparison
            timestamp=datetime.now()
        )
    
    def _calculate_perturbation_score(self, input_scaled: np.ndarray) -> float:
        """Calculate how much input deviates from normal distribution."""
        if self.normal_input_distribution is None:
            return 0.0
        
        # L2 norm deviation
        l2_deviation = abs(np.linalg.norm(input_scaled) - np.mean([np.linalg.norm(self.normal_input_distribution['mean'])]))
        l2_normalized = l2_deviation / self.statistical_thresholds['l2_norm_threshold']
        
        # Statistical deviation
        mean_deviation = np.mean(np.abs(input_scaled - self.normal_input_distribution['mean']))
        std_normalized = mean_deviation / (np.mean(self.normal_input_distribution['std']) + 1e-8)
        
        return min(1.0, (l2_normalized + std_normalized) / 2)
    
    def _detect_frequency_anomaly(self, input_scaled: np.ndarray) -> bool:
        """Detect frequency domain anomalies."""
        if len(input_scaled) == 0:
            return False
        
        try:
            fft_coeffs = np.fft.fft(input_scaled.real)
            frequency_energy = np.sum(np.abs(fft_coeffs))
            return frequency_energy > self.statistical_thresholds['frequency_threshold'] * 1.5
        except Exception:
            return False
    
    def _detect_distribution_anomaly(self, input_scaled: np.ndarray) -> bool:
        """Detect statistical distribution anomalies."""
        if self.normal_input_distribution is None:
            return False
        
        # Check if values are outside expected range
        outside_range = np.sum(
            (input_scaled < self.normal_input_distribution['min'] - 2 * self.normal_input_distribution['std']) |
            (input_scaled > self.normal_input_distribution['max'] + 2 * self.normal_input_distribution['std'])
        )
        
        return outside_range > len(input_scaled) * 0.1  # More than 10% of values outside range
    
    def _classify_attack_type(self, input_scaled: np.ndarray, perturbation_score: float, frequency_anomaly: bool) -> str:
        """Classify the type of adversarial attack."""
        if perturbation_score > 0.8:
            return 'high_perturbation_attack'
        elif perturbation_score > 0.5:
            return 'medium_perturbation_attack'
        elif frequency_anomaly:
            return 'frequency_domain_attack'
        elif self._detect_gradient_based_attack(input_scaled):
            return 'gradient_based_attack'
        else:
            return 'unknown_adversarial_attack'
    
    def _detect_gradient_based_attack(self, input_scaled: np.ndarray) -> bool:
        """Detect gradient-based attacks (FGSM, PGD, etc.)."""
        if len(input_scaled) < 2:
            return False
        
        # Look for systematic patterns in gradients
        gradients = np.diff(input_scaled)
        gradient_consistency = np.std(gradients) < 0.01  # Very consistent gradients
        
        return gradient_consistency and np.mean(np.abs(gradients)) > 0.05

class AdvancedAdaptiveEngine:
    """Advanced adaptive security engine for modern threats."""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.threat_patterns = AdvancedThreatPatterns()
        self.adversarial_detector = AdversarialMLDetector()
        
        # Enhanced threat intelligence
        self.threat_intel_db = defaultdict(list)
        self.zero_day_signatures = set()
        self.ai_attack_patterns = defaultdict(float)  # Pattern -> confidence score
        
        # Adaptive learning components
        self.pattern_evolution_tracker = defaultdict(deque)  # Track how patterns evolve
        self.threat_correlation_matrix = defaultdict(lambda: defaultdict(float))
        self.adaptive_thresholds = {
            'ai_social_engineering': 0.7,
            'zero_day_exploit': 0.8,
            'adversarial_ml': 0.6,
            'quantum_threat': 0.9,  # High threshold for emerging threats
            'supply_chain_attack': 0.75,
        }
        
        # Self-adaptation mechanisms
        self.adaptation_history = deque(maxlen=1000)
        self.false_positive_tracker = defaultdict(int)
        self.true_positive_tracker = defaultdict(int)
        self.threat_emergence_detector = DBSCAN(eps=0.5, min_samples=3)
        
        # Quantum-resistant preparation
        self.quantum_threat_indicators = {
            'post_quantum_crypto_bypass',
            'quantum_key_distribution_attack',
            'shor_algorithm_preparation',
            'grover_search_acceleration'
        }
        
        self.initialize_advanced_detectors()
    
    def initialize_advanced_detectors(self):
        """Initialize advanced detection systems."""
        logger.info("Initializing advanced threat detection systems...")
        
        # Train adversarial ML detector with synthetic normal data
        normal_samples = self._generate_normal_ml_inputs(100)
        self.adversarial_detector.train_baseline(normal_samples)
        
        # Load existing threat intelligence if available
        self._load_threat_intelligence()
        
        # Initialize pattern evolution tracking
        self._initialize_pattern_tracking()
        
        logger.info("Advanced adaptive engine initialized")
    
    def _generate_normal_ml_inputs(self, count: int) -> List[np.ndarray]:
        """Generate synthetic normal ML inputs for baseline training."""
        normal_inputs = []
        for _ in range(count):
            # Generate realistic feature vectors
            features = np.random.normal(0.5, 0.2, 50)  # 50-dimensional normal features
            features = np.clip(features, 0, 1)  # Clip to valid range
            normal_inputs.append(features)
        return normal_inputs
    
    def _load_threat_intelligence(self):
        """Load existing threat intelligence database."""
        intel_path = os.path.join(self.model_dir, 'threat_intelligence.json')
        if os.path.exists(intel_path):
            try:
                with open(intel_path, 'r') as f:
                    data = json.load(f)
                    for threat_type, intel_list in data.items():
                        for intel_data in intel_list:
                            intel = ThreatIntelligence(
                                threat_id=intel_data['threat_id'],
                                threat_type=intel_data['threat_type'],
                                indicators=intel_data['indicators'],
                                confidence=intel_data['confidence'],
                                first_seen=datetime.fromisoformat(intel_data['first_seen']),
                                last_seen=datetime.fromisoformat(intel_data['last_seen']),
                                attack_vector=intel_data['attack_vector'],
                                severity=intel_data['severity'],
                                source=intel_data['source'],
                                metadata=intel_data['metadata']
                            )
                            self.threat_intel_db[threat_type].append(intel)
                logger.info(f"Loaded threat intelligence: {len(data)} threat types")
            except Exception as e:
                logger.error(f"Failed to load threat intelligence: {e}")
    
    def _initialize_pattern_tracking(self):
        """Initialize pattern evolution tracking."""
        # Initialize tracking for modern threat types
        modern_threats = [
            'ai_generated_phishing',
            'deepfake_audio_attack',
            'llm_prompt_injection',
            'adversarial_ml_evasion',
            'zero_day_memory_corruption',
            'quantum_cryptography_attack',
            'supply_chain_compromise',
            'ai_powered_reconnaissance'
        ]
        
        for threat in modern_threats:
            self.pattern_evolution_tracker[threat] = deque(maxlen=100)
    
    def detect_modern_threats(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive detection of modern threat patterns."""
        detection_results = {
            'threats_detected': [],
            'risk_score': 0.0,
            'confidence': 0.0,
            'threat_types': [],
            'adaptive_response': None,
            'timestamp': datetime.now().isoformat()
        }
        
        # AI-powered social engineering detection
        ai_social_result = self._detect_ai_social_engineering(data)
        if ai_social_result['is_threat']:
            detection_results['threats_detected'].append(ai_social_result)
            detection_results['risk_score'] += ai_social_result['risk_contribution']
        
        # Zero-day vulnerability detection
        zero_day_result = self._detect_zero_day_indicators(data)
        if zero_day_result['is_threat']:
            detection_results['threats_detected'].append(zero_day_result)
            detection_results['risk_score'] += zero_day_result['risk_contribution']
        
        # Adversarial ML attack detection
        if 'ml_input' in data or 'features' in data:
            adversarial_result = self._detect_adversarial_ml_attack(data)
            if adversarial_result['is_threat']:
                detection_results['threats_detected'].append(adversarial_result)
                detection_results['risk_score'] += adversarial_result['risk_contribution']
        
        # Quantum threat preparation detection
        quantum_result = self._detect_quantum_threats(data)
        if quantum_result['is_threat']:
            detection_results['threats_detected'].append(quantum_result)
            detection_results['risk_score'] += quantum_result['risk_contribution']
        
        # Supply chain attack detection
        supply_chain_result = self._detect_supply_chain_attacks(data)
        if supply_chain_result['is_threat']:
            detection_results['threats_detected'].append(supply_chain_result)
            detection_results['risk_score'] += supply_chain_result['risk_contribution']
        
        # Calculate overall confidence and risk
        if detection_results['threats_detected']:
            detection_results['confidence'] = sum(t['confidence'] for t in detection_results['threats_detected']) / len(detection_results['threats_detected'])
            detection_results['threat_types'] = list(set(t['threat_type'] for t in detection_results['threats_detected']))
            detection_results['risk_score'] = min(1.0, detection_results['risk_score'])
            
            # Generate adaptive response
            detection_results['adaptive_response'] = self._generate_adaptive_response(detection_results)
        
        # Update pattern evolution tracking
        self._update_pattern_evolution(detection_results)
        
        # Adapt thresholds based on recent performance
        self._adapt_detection_thresholds()
        
        return detection_results
    
    def _detect_ai_social_engineering(self, data: Dict) -> Dict:
        """Detect AI-powered social engineering attacks."""
        threat_score = 0.0
        indicators = []
        
        content = str(data.get('payload', '')) + str(data.get('message', '')) + str(data.get('content', ''))
        
        # Check for deepfake indicators
        for pattern in self.threat_patterns.ai_social_engineering_patterns['deepfake_indicators']:
            if re.search(pattern, content, re.IGNORECASE):
                threat_score += 0.3
                indicators.append(f"deepfake_pattern: {pattern}")
        
        # Check for voice cloning indicators
        audio_metadata = data.get('audio_metadata', {})
        if audio_metadata:
            for pattern in self.threat_patterns.ai_social_engineering_patterns['voice_cloning_indicators']:
                if re.search(pattern, str(audio_metadata), re.IGNORECASE):
                    threat_score += 0.4
                    indicators.append(f"voice_cloning: {pattern}")
        
        # Check for LLM-generated content
        for pattern in self.threat_patterns.ai_social_engineering_patterns['llm_generated_content']:
            if re.search(pattern, content, re.IGNORECASE):
                threat_score += 0.25
                indicators.append(f"llm_generated: {pattern}")
        
        # Advanced linguistic analysis for AI detection
        ai_linguistic_score = self._analyze_ai_linguistic_patterns(content)
        threat_score += ai_linguistic_score
        
        is_threat = threat_score >= self.adaptive_thresholds['ai_social_engineering']
        
        return {
            'is_threat': is_threat,
            'threat_type': 'ai_social_engineering',
            'confidence': min(1.0, threat_score),
            'risk_contribution': 0.4 if is_threat else 0.0,
            'indicators': indicators,
            'linguistic_ai_score': ai_linguistic_score
        }
    
    def _detect_zero_day_indicators(self, data: Dict) -> Dict:
        """Detect zero-day vulnerability exploitation attempts."""
        threat_score = 0.0
        indicators = []
        
        payload = str(data.get('payload', ''))
        binary_data = data.get('binary_data', b'')
        
        # Check exploit signatures
        for pattern in self.threat_patterns.zero_day_indicators['exploit_signatures']:
            if re.search(pattern, payload, re.IGNORECASE):
                threat_score += 0.5
                indicators.append(f"exploit_signature: {pattern}")
        
        # Check binary patterns
        if binary_data:
            binary_str = binary_data.hex() if isinstance(binary_data, bytes) else str(binary_data)
            for pattern in self.threat_patterns.zero_day_indicators['unknown_binary_patterns']:
                if re.search(pattern, binary_str):
                    threat_score += 0.6
                    indicators.append(f"binary_pattern: {pattern}")
        
        # Memory corruption indicators
        for pattern in self.threat_patterns.zero_day_indicators['memory_corruption']:
            if re.search(pattern, payload):
                threat_score += 0.7
                indicators.append(f"memory_corruption: {pattern}")
        
        # Behavioral analysis for unknown exploitation patterns
        behavioral_score = self._analyze_exploitation_behavior(data)
        threat_score += behavioral_score
        
        is_threat = threat_score >= self.adaptive_thresholds['zero_day_exploit']
        
        return {
            'is_threat': is_threat,
            'threat_type': 'zero_day_exploit',
            'confidence': min(1.0, threat_score),
            'risk_contribution': 0.6 if is_threat else 0.0,
            'indicators': indicators,
            'behavioral_score': behavioral_score
        }
    
    def _detect_adversarial_ml_attack(self, data: Dict) -> Dict:
        """Detect adversarial ML attacks."""
        threat_score = 0.0
        indicators = []
        
        # Get ML input data
        ml_input = data.get('ml_input', data.get('features'))
        if ml_input is None:
            return {'is_threat': False, 'threat_type': 'adversarial_ml', 'confidence': 0.0, 'risk_contribution': 0.0}
        
        # Convert to numpy array
        if not isinstance(ml_input, np.ndarray):
            ml_input = np.array(ml_input)
        
        # Use adversarial detector
        adversarial_result = self.adversarial_detector.detect_adversarial_input(ml_input)
        
        if adversarial_result.is_adversarial:
            threat_score = adversarial_result.confidence
            indicators.append(f"adversarial_attack_type: {adversarial_result.attack_type}")
            indicators.append(f"perturbation_score: {adversarial_result.perturbation_score}")
        
        # Check for known adversarial patterns in metadata
        content = str(data.get('metadata', '')) + str(data.get('description', ''))
        for pattern in self.threat_patterns.adversarial_ml_patterns['evasion_attempts']:
            if re.search(pattern, content, re.IGNORECASE):
                threat_score += 0.3
                indicators.append(f"evasion_pattern: {pattern}")
        
        is_threat = threat_score >= self.adaptive_thresholds['adversarial_ml']
        
        return {
            'is_threat': is_threat,
            'threat_type': 'adversarial_ml_attack',
            'confidence': min(1.0, threat_score),
            'risk_contribution': 0.5 if is_threat else 0.0,
            'indicators': indicators,
            'adversarial_details': adversarial_result.__dict__ if adversarial_result.is_adversarial else None
        }
    
    def _detect_quantum_threats(self, data: Dict) -> Dict:
        """Detect quantum computing-related threats."""
        threat_score = 0.0
        indicators = []
        
        content = str(data.get('payload', '')) + str(data.get('description', ''))
        
        # Check for quantum threat indicators
        for indicator in self.quantum_threat_indicators:
            if indicator.replace('_', ' ') in content.lower():
                threat_score += 0.4
                indicators.append(f"quantum_indicator: {indicator}")
        
        # Check for post-quantum cryptography bypass attempts
        crypto_patterns = [
            r'lattice.{0,10}based.{0,10}attack',
            r'shor.{0,10}algorithm',
            r'grover.{0,10}search',
            r'quantum.{0,10}key.{0,10}distribution',
            r'post.{0,10}quantum.{0,10}crypto'
        ]
        
        for pattern in crypto_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threat_score += 0.3
                indicators.append(f"quantum_crypto_pattern: {pattern}")
        
        is_threat = threat_score >= self.adaptive_thresholds['quantum_threat']
        
        return {
            'is_threat': is_threat,
            'threat_type': 'quantum_cryptography_threat',
            'confidence': min(1.0, threat_score),
            'risk_contribution': 0.8 if is_threat else 0.0,  # High risk for quantum threats
            'indicators': indicators
        }
    
    def _detect_supply_chain_attacks(self, data: Dict) -> Dict:
        """Detect supply chain compromise attempts."""
        threat_score = 0.0
        indicators = []
        
        # Check package/dependency information
        package_info = data.get('package_info', {})
        dependencies = data.get('dependencies', [])
        
        # Suspicious package patterns
        supply_chain_patterns = [
            r'malicious.{0,10}dependency',
            r'typosquatting',
            r'backdoor.{0,10}package',
            r'compromised.{0,10}library',
            r'software.{0,10}supply.{0,10}chain'
        ]
        
        content = str(package_info) + str(dependencies) + str(data.get('description', ''))
        
        for pattern in supply_chain_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                threat_score += 0.4
                indicators.append(f"supply_chain_pattern: {pattern}")
        
        # Check for suspicious package characteristics
        if package_info:
            # Recently created packages with few downloads
            if (package_info.get('age_days', 1000) < 30 and 
                package_info.get('download_count', 0) < 100):
                threat_score += 0.3
                indicators.append("suspicious_new_package")
            
            # Packages with obfuscated code
            if package_info.get('obfuscated_code', False):
                threat_score += 0.5
                indicators.append("obfuscated_code_detected")
        
        is_threat = threat_score >= self.adaptive_thresholds['supply_chain_attack']
        
        return {
            'is_threat': is_threat,
            'threat_type': 'supply_chain_attack',
            'confidence': min(1.0, threat_score),
            'risk_contribution': 0.6 if is_threat else 0.0,
            'indicators': indicators
        }
    
    def _analyze_ai_linguistic_patterns(self, content: str) -> float:
        """Analyze linguistic patterns that suggest AI generation."""
        if not content:
            return 0.0
        
        ai_score = 0.0
        
        # Check for overly formal language
        formal_phrases = [
            'i apologize for any confusion',
            'please note that',
            'it is important to mention',
            'i must clarify that',
            'however, i should point out'
        ]
        
        for phrase in formal_phrases:
            if phrase in content.lower():
                ai_score += 0.1
        
        # Check for repetitive patterns
        words = content.lower().split()
        if len(words) > 10:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.6:  # High repetition
                ai_score += 0.2
        
        # Check for unnatural punctuation patterns
        if content.count('.') > len(content.split()) * 0.3:  # Too many periods
            ai_score += 0.15
        
        return min(0.5, ai_score)  # Cap at 0.5
    
    def _analyze_exploitation_behavior(self, data: Dict) -> float:
        """Analyze behavioral patterns for exploitation attempts."""
        behavior_score = 0.0
        
        # Rapid successive attempts
        if data.get('request_frequency', 0) > 100:  # More than 100 requests per minute
            behavior_score += 0.3
        
        # Unusual timing patterns
        timestamp = data.get('timestamp')
        if timestamp:
            hour = datetime.fromisoformat(timestamp).hour
            if 2 <= hour <= 5:  # Late night activity
                behavior_score += 0.1
        
        # Suspicious user agent patterns
        user_agent = data.get('user_agent', '')
        if 'bot' in user_agent.lower() or len(user_agent) < 10:
            behavior_score += 0.2
        
        # Geographic anomalies
        if data.get('geographic_anomaly', False):
            behavior_score += 0.2
        
        return min(0.4, behavior_score)  # Cap at 0.4
    
    def _generate_adaptive_response(self, detection_results: Dict) -> Dict:
        """Generate adaptive response based on detected threats."""
        response = {
            'recommended_actions': [],
            'threshold_adjustments': {},
            'new_patterns_learned': [],
            'intelligence_updates': []
        }
        
        threat_types = detection_results['threat_types']
        risk_score = detection_results['risk_score']
        
        # Recommend actions based on threat types
        if 'ai_social_engineering' in threat_types:
            response['recommended_actions'].extend([
                'Enable enhanced email filtering',
                'Activate voice authentication verification',
                'Deploy deepfake detection at email gateway'
            ])
        
        if 'zero_day_exploit' in threat_types:
            response['recommended_actions'].extend([
                'Implement behavioral analysis blocking',
                'Enable memory protection mechanisms',
                'Deploy honeypot systems for unknown exploit detection'
            ])
        
        if 'adversarial_ml_attack' in threat_types:
            response['recommended_actions'].extend([
                'Activate adversarial input filtering',
                'Enable model ensemble defense',
                'Deploy input validation strengthening'
            ])
        
        # Adjust thresholds based on performance
        if risk_score > 0.8:
            # Lower thresholds for high-risk scenarios
            for threat_type in threat_types:
                current_threshold = self.adaptive_thresholds.get(threat_type, 0.7)
                response['threshold_adjustments'][threat_type] = max(0.5, current_threshold - 0.1)
        
        return response
    
    def _update_pattern_evolution(self, detection_results: Dict):
        """Update pattern evolution tracking."""
        timestamp = datetime.now()
        
        for threat in detection_results['threats_detected']:
            threat_type = threat['threat_type']
            
            pattern_data = {
                'timestamp': timestamp,
                'confidence': threat['confidence'],
                'indicators': threat.get('indicators', []),
                'risk_contribution': threat['risk_contribution']
            }
            
            self.pattern_evolution_tracker[threat_type].append(pattern_data)
        
        # Store in adaptation history
        self.adaptation_history.append({
            'timestamp': timestamp,
            'threats_detected': len(detection_results['threats_detected']),
            'risk_score': detection_results['risk_score'],
            'threat_types': detection_results['threat_types']
        })
    
    def _adapt_detection_thresholds(self):
        """Adapt detection thresholds based on recent performance."""
        if len(self.adaptation_history) < 50:
            return  # Need more data
        
        recent_history = list(self.adaptation_history)[-50:]
        
        # Calculate false positive rate estimate
        high_risk_detections = sum(1 for h in recent_history if h['risk_score'] > 0.8)
        total_detections = sum(1 for h in recent_history if h['threats_detected'] > 0)
        
        if total_detections > 0:
            estimated_fp_rate = (total_detections - high_risk_detections) / total_detections
            
            # Adjust thresholds based on estimated false positive rate
            for threat_type in self.adaptive_thresholds:
                current_threshold = self.adaptive_thresholds[threat_type]
                
                if estimated_fp_rate > 0.2:  # Too many false positives
                    self.adaptive_thresholds[threat_type] = min(0.9, current_threshold + 0.05)
                elif estimated_fp_rate < 0.05:  # Very low false positives, can be more sensitive
                    self.adaptive_thresholds[threat_type] = max(0.4, current_threshold - 0.02)
        
        logger.info(f"Adapted detection thresholds: {self.adaptive_thresholds}")
    
    def add_threat_intelligence(self, threat_intel: ThreatIntelligence):
        """Add new threat intelligence to the system."""
        self.threat_intel_db[threat_intel.threat_type].append(threat_intel)
        
        # Update pattern tracking
        for indicator in threat_intel.indicators:
            self.ai_attack_patterns[indicator] = threat_intel.confidence
        
        logger.info(f"Added threat intelligence: {threat_intel.threat_type} - {threat_intel.threat_id}")
    
    def save_advanced_model(self):
        """Save the advanced adaptive model."""
        os.makedirs(self.model_dir, exist_ok=True)
        
        try:
            # Save threat intelligence
            intel_path = os.path.join(self.model_dir, 'threat_intelligence.json')
            intel_data = {}
            for threat_type, intel_list in self.threat_intel_db.items():
                intel_data[threat_type] = []
                for intel in intel_list:
                    intel_data[threat_type].append({
                        'threat_id': intel.threat_id,
                        'threat_type': intel.threat_type,
                        'indicators': intel.indicators,
                        'confidence': intel.confidence,
                        'first_seen': intel.first_seen.isoformat(),
                        'last_seen': intel.last_seen.isoformat(),
                        'attack_vector': intel.attack_vector,
                        'severity': intel.severity,
                        'source': intel.source,
                        'metadata': intel.metadata
                    })
            
            with open(intel_path, 'w') as f:
                json.dump(intel_data, f, indent=2)
            
            # Save adaptive model components
            model_data = {
                'adaptive_thresholds': self.adaptive_thresholds,
                'ai_attack_patterns': dict(self.ai_attack_patterns),
                'zero_day_signatures': list(self.zero_day_signatures),
                'adaptation_history': list(self.adaptation_history),
                'pattern_evolution_tracker': {k: list(v) for k, v in self.pattern_evolution_tracker.items()}
            }
            
            model_path = os.path.join(self.model_dir, 'advanced_adaptive_model.pkl')
            joblib.dump(model_data, model_path)
            
            # Save adversarial detector
            if self.adversarial_detector.is_trained:
                adversarial_path = os.path.join(self.model_dir, 'adversarial_detector.pkl')
                joblib.dump(self.adversarial_detector, adversarial_path)
            
            logger.info("Advanced adaptive model saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save advanced model: {e}")
    
    def get_advanced_model_info(self) -> Dict:
        """Get information about the advanced adaptive model."""
        return {
            'adaptive_thresholds': self.adaptive_thresholds,
            'threat_intelligence_entries': sum(len(intel_list) for intel_list in self.threat_intel_db.values()),
            'ai_attack_patterns': len(self.ai_attack_patterns),
            'zero_day_signatures': len(self.zero_day_signatures),
            'pattern_evolution_tracked': len(self.pattern_evolution_tracker),
            'adaptation_history_entries': len(self.adaptation_history),
            'adversarial_detector_trained': self.adversarial_detector.is_trained,
            'last_threshold_adaptation': datetime.now().isoformat(),
            'supported_threat_types': [
                'ai_social_engineering',
                'zero_day_exploit', 
                'adversarial_ml_attack',
                'quantum_cryptography_threat',
                'supply_chain_attack'
            ]
        }

# Global advanced engine instance
_advanced_engine_instance = None

def get_advanced_adaptive_engine() -> AdvancedAdaptiveEngine:
    """Get the global advanced adaptive engine instance."""
    global _advanced_engine_instance
    if _advanced_engine_instance is None:
        _advanced_engine_instance = AdvancedAdaptiveEngine()
    return _advanced_engine_instance