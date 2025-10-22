"""
Custom Machine Learning Threat Detection System
Adaptive threat detection without external API dependencies
"""
import os
import json
import pickle
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import defaultdict, deque

# ML Libraries
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN
import joblib

logger = logging.getLogger(__name__)

@dataclass
class ThreatSample:
    """Data structure for threat samples."""
    features: List[float]
    raw_data: Dict[str, Any]
    is_threat: bool
    timestamp: datetime
    threat_type: Optional[str] = None
    confidence: float = 0.0
    source: str = "unknown"

@dataclass
class ModelMetrics:
    """Model performance metrics."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    last_updated: datetime

class FeatureExtractor:
    """Extract features from raw security data."""
    
    def __init__(self):
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 3),
            lowercase=True
        )
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_fitted = False
        
    def extract_network_features(self, data: Dict) -> List[float]:
        """Extract features from network traffic data."""
        features = []
        
        # Basic network features
        features.extend([
            data.get('packet_size', 0) / 1500.0,  # Normalized packet size
            data.get('port', 0) / 65535.0,  # Normalized port number
            data.get('connection_duration', 0) / 3600.0,  # Normalized duration (hours)
            float(data.get('is_encrypted', False)),
            data.get('packet_count', 0) / 1000.0,  # Normalized packet count
            data.get('bytes_transferred', 0) / (1024 * 1024),  # MB transferred
        ])
        
        # Protocol features
        protocol = data.get('protocol', 'unknown').lower()
        protocol_features = [
            float(protocol == 'tcp'),
            float(protocol == 'udp'),
            float(protocol == 'icmp'),
            float(protocol == 'http'),
            float(protocol == 'https'),
            float(protocol in ['ftp', 'sftp']),
            float(protocol in ['smtp', 'pop3', 'imap']),
            float(protocol == 'dns'),
        ]
        features.extend(protocol_features)
        
        # Traffic pattern features
        features.extend([
            data.get('request_frequency', 0) / 100.0,  # Requests per minute
            data.get('unique_destinations', 0) / 100.0,  # Unique IPs contacted
            float(data.get('is_weekend', False)),
            (data.get('hour_of_day', 12) - 12) / 12.0,  # Normalized hour
        ])
        
        return features
    
    def extract_auth_features(self, data: Dict) -> List[float]:
        """Extract features from authentication attempts."""
        features = []
        
        # Authentication attempt features
        features.extend([
            data.get('failed_attempts', 0) / 10.0,  # Normalized failed attempts
            data.get('time_since_last_attempt', 0) / 3600.0,  # Hours since last
            float(data.get('new_device', False)),
            float(data.get('new_location', False)),
            float(data.get('tor_exit_node', False)),
            float(data.get('vpn_detected', False)),
        ])
        
        # Geographic features
        features.extend([
            data.get('distance_from_usual', 0) / 10000.0,  # km from usual location
            float(data.get('country_mismatch', False)),
            float(data.get('high_risk_country', False)),
        ])
        
        # Behavioral features
        features.extend([
            data.get('typing_pattern_similarity', 1.0),  # 0-1 similarity score
            data.get('session_duration_anomaly', 0.0),  # Standard deviations from norm
            data.get('unusual_access_pattern', 0.0),  # Anomaly score
        ])
        
        return features
    
    def extract_payload_features(self, data: Dict) -> List[float]:
        """Extract features from request payloads."""
        payload = data.get('payload', '')
        if not isinstance(payload, str):
            payload = str(payload)
        
        features = []
        
        # String-based features
        features.extend([
            len(payload) / 1000.0,  # Normalized length
            payload.count('<') / max(len(payload), 1),  # HTML tag density
            payload.count('script') / max(len(payload), 1),  # Script tag density
            payload.count('union') / max(len(payload), 1),  # SQL union density
            payload.count('select') / max(len(payload), 1),  # SQL select density
            payload.count('drop') / max(len(payload), 1),  # SQL drop density
            payload.count('..') / max(len(payload), 1),  # Path traversal
            payload.count('%') / max(len(payload), 1),  # URL encoding density
        ])
        
        # Pattern-based features
        suspicious_patterns = [
            'eval(', 'exec(', 'system(', 'shell_exec',
            'javascript:', 'vbscript:', 'onload=', 'onerror=',
            'alert(', 'prompt(', 'confirm(',
            'union select', 'or 1=1', 'and 1=1', '/*',
            '../', '..\\', '/etc/passwd', '/etc/shadow',
            'cmd.exe', 'powershell', '/bin/sh', '/bin/bash'
        ]
        
        for pattern in suspicious_patterns:
            features.append(float(pattern.lower() in payload.lower()))
        
        return features
    
    def extract_all_features(self, data: Dict) -> List[float]:
        """Extract all features from input data."""
        features = []
        
        # Extract different types of features based on data type
        data_type = data.get('type', 'unknown')
        
        if data_type == 'network' or 'src_ip' in data:
            features.extend(self.extract_network_features(data))
        elif data_type == 'auth' or 'username' in data:
            features.extend(self.extract_auth_features(data))
        elif data_type == 'payload' or 'payload' in data:
            features.extend(self.extract_payload_features(data))
        else:
            # Generic feature extraction
            features.extend([
                data.get('severity', 0) / 10.0,
                data.get('confidence', 0.5),
                float(data.get('anomalous', False)),
                data.get('risk_score', 0.5),
            ])
        
        # Ensure consistent feature vector size
        target_size = 50  # Fixed feature vector size
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        elif len(features) > target_size:
            features = features[:target_size]
        
        return features
    
    def fit_transform(self, samples: List[Dict]) -> np.ndarray:
        """Fit feature extractors and transform samples."""
        feature_vectors = []
        
        for sample in samples:
            features = self.extract_all_features(sample)
            feature_vectors.append(features)
        
        X = np.array(feature_vectors)
        X_scaled = self.scaler.fit_transform(X)
        self.is_fitted = True
        
        return X_scaled
    
    def transform(self, samples: List[Dict]) -> np.ndarray:
        """Transform samples using fitted extractors."""
        if not self.is_fitted:
            raise ValueError("FeatureExtractor must be fitted before transform")
        
        feature_vectors = []
        
        for sample in samples:
            features = self.extract_all_features(sample)
            feature_vectors.append(features)
        
        X = np.array(feature_vectors)
        X_scaled = self.scaler.transform(X)
        
        return X_scaled

class AdaptiveThreatDetector:
    """Self-adapting threat detection model."""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.feature_extractor = FeatureExtractor()
        
        # Ensemble of models for robust detection
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10,
            min_samples_split=5
        )
        
        self.clusterer = DBSCAN(eps=0.5, min_samples=5)
        
        # Adaptive learning components
        self.threat_buffer = deque(maxlen=1000)  # Recent threat samples
        self.feedback_buffer = deque(maxlen=500)  # User feedback
        self.pattern_tracker = defaultdict(list)  # Track emerging patterns
        
        # Model metadata
        self.metrics = ModelMetrics(0.0, 0.0, 0.0, 0.0, 0.0, datetime.now())
        self.last_retrain = datetime.now()
        self.retrain_threshold = 100  # Retrain after N new samples
        self.confidence_threshold = 0.7
        
        # Initialize with synthetic threat data
        self._initialize_with_synthetic_data()
        
        # Load existing model if available
        self.load_model()
    
    def _initialize_with_synthetic_data(self):
        """Initialize model with synthetic threat patterns."""
        logger.info("Initializing threat detector with synthetic data...")
        
        synthetic_threats = self._generate_synthetic_threats()
        synthetic_normal = self._generate_synthetic_normal()
        
        # Combine and train initial model
        all_samples = synthetic_threats + synthetic_normal
        self._train_initial_model(all_samples)
        
        logger.info(f"Initialized with {len(all_samples)} synthetic samples")
    
    def _generate_synthetic_threats(self) -> List[ThreatSample]:
        """Generate synthetic threat samples for initial training."""
        threats = []
        
        # SQL Injection patterns
        sql_payloads = [
            "' OR '1'='1",
            "admin'--",
            "1; DROP TABLE users",
            "UNION SELECT * FROM passwords",
            "' AND 1=1--"
        ]
        
        for payload in sql_payloads:
            sample = ThreatSample(
                features=[],
                raw_data={
                    'type': 'payload',
                    'payload': payload,
                    'severity': 8,
                    'source_ip': '192.168.1.100'
                },
                is_threat=True,
                timestamp=datetime.now(),
                threat_type='sql_injection',
                confidence=0.9,
                source='synthetic'
            )
            threats.append(sample)
        
        # XSS patterns
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        for payload in xss_payloads:
            sample = ThreatSample(
                features=[],
                raw_data={
                    'type': 'payload',
                    'payload': payload,
                    'severity': 7,
                    'source_ip': '10.0.0.50'
                },
                is_threat=True,
                timestamp=datetime.now(),
                threat_type='xss',
                confidence=0.85,
                source='synthetic'
            )
            threats.append(sample)
        
        # Brute force patterns
        for i in range(10):
            sample = ThreatSample(
                features=[],
                raw_data={
                    'type': 'auth',
                    'failed_attempts': 10 + i,
                    'time_since_last_attempt': 1,
                    'new_device': True,
                    'new_location': True,
                    'username': f'admin_{i}'
                },
                is_threat=True,
                timestamp=datetime.now(),
                threat_type='brute_force',
                confidence=0.8,
                source='synthetic'
            )
            threats.append(sample)
        
        # DDoS patterns
        for i in range(5):
            sample = ThreatSample(
                features=[],
                raw_data={
                    'type': 'network',
                    'packet_size': 1500,
                    'packet_count': 1000 + i * 100,
                    'request_frequency': 100 + i * 20,
                    'protocol': 'tcp',
                    'port': 80
                },
                is_threat=True,
                timestamp=datetime.now(),
                threat_type='ddos',
                confidence=0.75,
                source='synthetic'
            )
            threats.append(sample)
        
        return threats
    
    def _generate_synthetic_normal(self) -> List[ThreatSample]:
        """Generate synthetic normal samples for initial training."""
        normal = []
        
        # Normal web requests
        normal_payloads = [
            "search?q=python tutorial",
            "login.php",
            "profile/update",
            "api/users/123",
            "home.html"
        ]
        
        for payload in normal_payloads:
            sample = ThreatSample(
                features=[],
                raw_data={
                    'type': 'payload',
                    'payload': payload,
                    'severity': 1,
                    'source_ip': '192.168.1.10'
                },
                is_threat=False,
                timestamp=datetime.now(),
                threat_type=None,
                confidence=0.9,
                source='synthetic'
            )
            normal.append(sample)
        
        # Normal authentication
        for i in range(15):
            sample = ThreatSample(
                features=[],
                raw_data={
                    'type': 'auth',
                    'failed_attempts': 0,
                    'time_since_last_attempt': 3600,
                    'new_device': False,
                    'new_location': False,
                    'username': f'user_{i}'
                },
                is_threat=False,
                timestamp=datetime.now(),
                threat_type=None,
                confidence=0.95,
                source='synthetic'
            )
            normal.append(sample)
        
        # Normal network traffic
        for i in range(10):
            sample = ThreatSample(
                features=[],
                raw_data={
                    'type': 'network',
                    'packet_size': 500 + i * 50,
                    'packet_count': 10 + i,
                    'request_frequency': 5 + i,
                    'protocol': 'https',
                    'port': 443
                },
                is_threat=False,
                timestamp=datetime.now(),
                threat_type=None,
                confidence=0.9,
                source='synthetic'
            )
            normal.append(sample)
        
        return normal
    
    def _train_initial_model(self, samples: List[ThreatSample]):
        """Train initial model with synthetic data."""
        if not samples:
            return
        
        # Extract features and labels
        raw_data = [sample.raw_data for sample in samples]
        labels = [sample.is_threat for sample in samples]
        
        # Transform features
        X = self.feature_extractor.fit_transform(raw_data)
        y = np.array(labels)
        
        # Train models
        self.anomaly_detector.fit(X)
        
        if len(np.unique(y)) > 1:  # Need both classes for classification
            self.classifier.fit(X, y)
        
        # Store samples in buffer
        for sample in samples:
            sample.features = self.feature_extractor.extract_all_features(sample.raw_data)
            self.threat_buffer.append(sample)
        
        logger.info("Initial model training completed")
    
    def predict(self, data: Dict) -> Dict[str, Any]:
        """Predict if input data represents a threat."""
        try:
            # Extract features
            features = self.feature_extractor.transform([data])
            
            # Get predictions from all models
            anomaly_score = self.anomaly_detector.predict(features)[0]  # -1 = anomaly, 1 = normal
            anomaly_confidence = abs(self.anomaly_detector.decision_function(features)[0])
            
            # Classification prediction (if model is trained)
            try:
                class_proba = self.classifier.predict_proba(features)[0]
                if len(class_proba) > 1:
                    threat_probability = class_proba[1]  # Probability of threat class
                else:
                    threat_probability = 0.5
            except Exception:
                threat_probability = 0.5
            
            # Combine predictions
            is_anomaly = anomaly_score == -1
            combined_confidence = (anomaly_confidence + threat_probability) / 2
            
            # Determine final threat status
            is_threat = is_anomaly or threat_probability > self.confidence_threshold
            final_confidence = max(anomaly_confidence, threat_probability) if is_threat else 1 - combined_confidence
            
            # Determine threat type based on features and patterns
            threat_type = self._classify_threat_type(data) if is_threat else None
            
            result = {
                'is_threat': bool(is_threat),
                'confidence': float(min(final_confidence, 1.0)),
                'threat_type': threat_type,
                'anomaly_score': float(anomaly_confidence),
                'classification_score': float(threat_probability),
                'model_version': self.last_retrain.isoformat(),
                'features_used': len(self.feature_extractor.extract_all_features(data))
            }
            
            # Store prediction for adaptive learning
            self._store_prediction(data, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'error': str(e),
                'model_version': self.last_retrain.isoformat()
            }
    
    def _classify_threat_type(self, data: Dict) -> str:
        """Classify the type of threat based on data patterns."""
        payload = str(data.get('payload', ''))
        data_type = data.get('type', 'unknown')
        
        if data_type == 'auth' or 'username' in data:
            if data.get('failed_attempts', 0) > 5:
                return 'brute_force'
            elif data.get('new_location') and data.get('new_device'):
                return 'suspicious_auth'
        
        if 'payload' in data or data_type == 'payload':
            payload_lower = payload.lower()
            if any(word in payload_lower for word in ['select', 'union', 'drop', 'insert']):
                return 'sql_injection'
            elif any(word in payload_lower for word in ['script', 'alert', 'javascript', 'onload']):
                return 'xss'
            elif any(word in payload_lower for word in ['../etc', 'windows/system32', '/bin/sh']):
                return 'path_traversal'
        
        if data_type == 'network':
            if data.get('request_frequency', 0) > 50:
                return 'ddos'
            elif data.get('packet_size', 0) > 1400:
                return 'packet_flood'
        
        return 'unknown_threat'
    
    def _store_prediction(self, data: Dict, result: Dict):
        """Store prediction for adaptive learning."""
        sample = ThreatSample(
            features=self.feature_extractor.extract_all_features(data),
            raw_data=data.copy(),
            is_threat=result['is_threat'],
            timestamp=datetime.now(),
            threat_type=result.get('threat_type'),
            confidence=result['confidence'],
            source='prediction'
        )
        
        self.threat_buffer.append(sample)
        
        # Track patterns for emerging threats
        if result['is_threat']:
            threat_type = result.get('threat_type', 'unknown')
            self.pattern_tracker[threat_type].append(sample)
    
    def add_feedback(self, data: Dict, is_threat: bool, threat_type: str = None):
        """Add user feedback for adaptive learning."""
        feedback_sample = ThreatSample(
            features=self.feature_extractor.extract_all_features(data),
            raw_data=data.copy(),
            is_threat=is_threat,
            timestamp=datetime.now(),
            threat_type=threat_type,
            confidence=1.0,  # High confidence for human feedback
            source='human_feedback'
        )
        
        self.feedback_buffer.append(feedback_sample)
        
        logger.info(f"Added feedback: threat={is_threat}, type={threat_type}")
        
        # Trigger retraining if enough feedback accumulated
        if len(self.feedback_buffer) >= 50:
            self.retrain_model()
    
    def retrain_model(self):
        """Retrain the model with new data."""
        logger.info("Starting model retraining...")
        
        # Combine all available samples
        all_samples = list(self.threat_buffer) + list(self.feedback_buffer)
        
        if len(all_samples) < 10:
            logger.warning("Not enough samples for retraining")
            return
        
        # Prepare training data
        raw_data = [sample.raw_data for sample in all_samples]
        labels = [sample.is_threat for sample in all_samples]
        
        # Re-fit feature extractor with all data
        X = self.feature_extractor.fit_transform(raw_data)
        y = np.array(labels)
        
        # Split data for validation
        if len(X) > 20:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
            )
        else:
            X_train, X_test, y_train, y_test = X, X, y, y
        
        # Retrain models
        self.anomaly_detector = IsolationForest(
            contamination=min(0.3, sum(y) / len(y)),  # Adaptive contamination
            random_state=42,
            n_estimators=100
        )
        self.anomaly_detector.fit(X_train)
        
        if len(np.unique(y_train)) > 1:
            self.classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10,
                min_samples_split=5
            )
            self.classifier.fit(X_train, y_train)
            
            # Calculate metrics
            if len(X_test) > 0:
                y_pred = self.classifier.predict(X_test)
                from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
                
                self.metrics = ModelMetrics(
                    accuracy=accuracy_score(y_test, y_pred),
                    precision=precision_score(y_test, y_pred, zero_division=0),
                    recall=recall_score(y_test, y_pred, zero_division=0),
                    f1_score=f1_score(y_test, y_pred, zero_division=0),
                    false_positive_rate=sum((y_pred == 1) & (y_test == 0)) / sum(y_test == 0) if sum(y_test == 0) > 0 else 0,
                    last_updated=datetime.now()
                )
        
        # Clear feedback buffer after retraining
        self.feedback_buffer.clear()
        self.last_retrain = datetime.now()
        
        # Save updated model
        self.save_model()
        
        logger.info(f"Model retrained with {len(all_samples)} samples")
        logger.info(f"Model metrics: accuracy={self.metrics.accuracy:.3f}, precision={self.metrics.precision:.3f}")
    
    def save_model(self):
        """Save the trained model to disk."""
        os.makedirs(self.model_dir, exist_ok=True)
        
        try:
            # Save all model components
            model_data = {
                'anomaly_detector': self.anomaly_detector,
                'classifier': self.classifier,
                'feature_extractor': self.feature_extractor,
                'metrics': self.metrics,
                'last_retrain': self.last_retrain,
                'threat_buffer': list(self.threat_buffer),
                'pattern_tracker': dict(self.pattern_tracker)
            }
            
            model_path = os.path.join(self.model_dir, 'threat_detector.pkl')
            joblib.dump(model_data, model_path)
            
            logger.info(f"Model saved to {model_path}")
            
        except Exception as e:
            logger.error(f"Failed to save model: {str(e)}")
    
    def load_model(self):
        """Load a previously trained model from disk."""
        model_path = os.path.join(self.model_dir, 'threat_detector.pkl')
        
        if not os.path.exists(model_path):
            logger.info("No existing model found, using initial model")
            return
        
        try:
            model_data = joblib.load(model_path)
            
            self.anomaly_detector = model_data['anomaly_detector']
            self.classifier = model_data['classifier']
            self.feature_extractor = model_data['feature_extractor']
            self.metrics = model_data['metrics']
            self.last_retrain = model_data['last_retrain']
            self.threat_buffer = deque(model_data['threat_buffer'], maxlen=1000)
            self.pattern_tracker = defaultdict(list, model_data['pattern_tracker'])
            
            logger.info(f"Model loaded from {model_path}")
            logger.info(f"Model trained on {len(self.threat_buffer)} samples")
            
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            logger.info("Using initial model instead")
    
    def get_model_info(self) -> Dict:
        """Get information about the current model."""
        return {
            'model_version': self.last_retrain.isoformat(),
            'samples_trained': len(self.threat_buffer),
            'feedback_samples': len(self.feedback_buffer),
            'metrics': {
                'accuracy': self.metrics.accuracy,
                'precision': self.metrics.precision,
                'recall': self.metrics.recall,
                'f1_score': self.metrics.f1_score,
                'false_positive_rate': self.metrics.false_positive_rate,
                'last_updated': self.metrics.last_updated.isoformat()
            },
            'threat_patterns': {k: len(v) for k, v in self.pattern_tracker.items()},
            'next_retrain': (self.last_retrain + timedelta(hours=24)).isoformat()
        }

# Global detector instance
_detector_instance = None

def get_threat_detector() -> AdaptiveThreatDetector:
    """Get the global threat detector instance."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AdaptiveThreatDetector()
    return _detector_instance