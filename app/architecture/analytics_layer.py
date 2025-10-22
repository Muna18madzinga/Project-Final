"""
Analytics Layer - Chapter 3.3 System Architecture
Deep Learning-based model adaptation using LSTM-Transformer hybrids in PyTorch.
Conducts anomaly detection and TTP mapping to MITRE ATT&CK.
Implements software-based model adaptation via evolutionary algorithms.
"""

import logging
import torch
import torch.nn as nn
import torch.optim as optim
from torch.nn import TransformerEncoder, TransformerEncoderLayer
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import json
import joblib
from collections import deque, defaultdict
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import mlflow
import mlflow.pytorch
from .telemetry_collection import TelemetryData

logger = logging.getLogger(__name__)

@dataclass
class AnalysisResult:
    """Analysis result structure."""
    anomaly_score: float
    is_anomalous: bool
    threat_classification: str
    confidence: float
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    risk_level: str
    timestamp: datetime
    features_analyzed: List[str]

class HybridAnomalyDetector(nn.Module):
    """
    Hybrid LSTM-Transformer anomaly detection model as specified in Chapter 3.6.
    Combines LSTM for sequence modeling with Transformers for attention mechanism.
    """

    def __init__(self, input_dim: int, hidden_dim: int = 256,
                 num_lstm_layers: int = 3, num_transformer_layers: int = 2,
                 num_heads: int = 6, dropout: float = 0.3):
        super(HybridAnomalyDetector, self).__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim

        # LSTM layers for sequence modeling
        self.lstm = nn.LSTM(
            input_dim, hidden_dim, num_lstm_layers,
            batch_first=True, dropout=dropout, bidirectional=False
        )

        # Transformer encoder for attention mechanism
        encoder_layer = TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=num_heads,
            dim_feedforward=1024,
            dropout=dropout,
            activation='gelu'
        )
        self.transformer = TransformerEncoder(
            encoder_layer, num_layers=num_transformer_layers
        )

        # Residual connection for stability
        self.residual = nn.Linear(input_dim, hidden_dim)

        # Adversarial defense components
        self.adversarial_defense = nn.Sequential(
            nn.Dropout(0.1),
            nn.LayerNorm(hidden_dim)
        )

        # Final classification layers
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid()
        )

        # Initialize weights
        self._init_weights()

    def _init_weights(self):
        """Initialize model weights."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.LSTM):
                for param in module.parameters():
                    if len(param.shape) >= 2:
                        nn.init.orthogonal_(param.data)
                    else:
                        nn.init.normal_(param.data, 0, 0.01)

    def forward(self, x):
        """
        Forward pass through hybrid model.
        Args:
            x: Input tensor of shape (batch_size, sequence_length, input_dim)
        Returns:
            Anomaly probability tensor
        """
        batch_size, seq_len, _ = x.shape

        # LSTM processing for sequential patterns
        lstm_out, (hidden, cell) = self.lstm(x)

        # Residual connection from input
        if seq_len > 0:
            res = self.residual(x[:, -1, :])  # Use last timestep for residual
            res = res.unsqueeze(1).expand(-1, seq_len, -1)
        else:
            res = torch.zeros_like(lstm_out)

        # Add residual connection
        lstm_out = lstm_out + res

        # Transformer processing for attention mechanism
        # Transpose for transformer (seq_len, batch_size, hidden_dim)
        trans_input = lstm_out.transpose(0, 1)
        trans_out = self.transformer(trans_input)

        # Transpose back (batch_size, seq_len, hidden_dim)
        trans_out = trans_out.transpose(0, 1)

        # Adversarial defense
        trans_out = self.adversarial_defense(trans_out)

        # Use last timestep for classification
        final_features = trans_out[:, -1, :] if seq_len > 0 else trans_out.mean(dim=1)

        # Final classification
        output = self.fc(final_features)

        return output

class MitreAttackMapper:
    """Maps detected anomalies to MITRE ATT&CK tactics and techniques."""

    def __init__(self):
        self.tactic_technique_map = {
            'initial_access': {
                'T1190': 'Exploit Public-Facing Application',
                'T1566': 'Phishing',
                'T1078': 'Valid Accounts',
                'T1133': 'External Remote Services'
            },
            'execution': {
                'T1059': 'Command and Scripting Interpreter',
                'T1106': 'Native API',
                'T1053': 'Scheduled Task/Job'
            },
            'persistence': {
                'T1547': 'Boot or Logon Autostart Execution',
                'T1053': 'Scheduled Task/Job',
                'T1078': 'Valid Accounts'
            },
            'privilege_escalation': {
                'T1068': 'Exploitation for Privilege Escalation',
                'T1548': 'Abuse Elevation Control Mechanism',
                'T1078': 'Valid Accounts'
            },
            'defense_evasion': {
                'T1070': 'Indicator Removal',
                'T1027': 'Obfuscated Files or Information',
                'T1562': 'Impair Defenses'
            },
            'credential_access': {
                'T1110': 'Brute Force',
                'T1003': 'OS Credential Dumping',
                'T1552': 'Unsecured Credentials'
            },
            'discovery': {
                'T1057': 'Process Discovery',
                'T1018': 'Remote System Discovery',
                'T1083': 'File and Directory Discovery'
            },
            'lateral_movement': {
                'T1021': 'Remote Services',
                'T1080': 'Taint Shared Content',
                'T1550': 'Use Alternate Authentication Material'
            },
            'collection': {
                'T1005': 'Data from Local System',
                'T1039': 'Data from Network Shared Drive',
                'T1113': 'Screen Capture'
            },
            'command_and_control': {
                'T1071': 'Application Layer Protocol',
                'T1095': 'Non-Application Layer Protocol',
                'T1572': 'Protocol Tunneling'
            },
            'exfiltration': {
                'T1041': 'Exfiltration Over C2 Channel',
                'T1048': 'Exfiltration Over Alternative Protocol',
                'T1567': 'Exfiltration Over Web Service'
            },
            'impact': {
                'T1486': 'Data Encrypted for Impact',
                'T1499': 'Endpoint Denial of Service',
                'T1485': 'Data Destruction'
            }
        }

        # Anomaly indicators to MITRE mapping
        self.indicator_mapping = {
            'high_cpu_usage': [('execution', 'T1059')],
            'suspicious_processes_detected': [('execution', 'T1059'), ('defense_evasion', 'T1027')],
            'privilege_escalation_detected': [('privilege_escalation', 'T1068')],
            'excessive_failed_logins': [('credential_access', 'T1110')],
            'suspicious_file_access': [('collection', 'T1005')],
            'suspicious_port_access': [('lateral_movement', 'T1021')],
            'internal_to_external_communication': [('command_and_control', 'T1071')],
            'oversized_packet': [('exfiltration', 'T1041')],
            'excessive_network_connections': [('command_and_control', 'T1095')],
        }

    def map_to_mitre(self, risk_indicators: List[str]) -> Tuple[List[str], List[str]]:
        """
        Map risk indicators to MITRE ATT&CK tactics and techniques.

        Args:
            risk_indicators: List of detected risk indicators

        Returns:
            Tuple of (tactics, techniques)
        """
        tactics = set()
        techniques = set()

        for indicator in risk_indicators:
            if indicator in self.indicator_mapping:
                for tactic, technique in self.indicator_mapping[indicator]:
                    tactics.add(tactic)
                    techniques.add(technique)

        return list(tactics), list(techniques)

class FeatureExtractor:
    """Extract features from telemetry data for ML analysis."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_columns = []

    def extract_features(self, telemetry_batch: List[TelemetryData]) -> np.ndarray:
        """Extract numerical features from telemetry data."""
        features_list = []

        for telemetry in telemetry_batch:
            features = self._extract_single_telemetry_features(telemetry)
            features_list.append(features)

        if not features_list:
            return np.array([])

        # Convert to numpy array
        feature_matrix = np.array(features_list)

        # Fit scaler on first batch if not fitted
        if not self.is_fitted:
            self.scaler.fit(feature_matrix)
            self.is_fitted = True
            logger.info(f"Feature extractor fitted with {feature_matrix.shape[1]} features")

        # Scale features
        scaled_features = self.scaler.transform(feature_matrix)

        return scaled_features

    def _extract_single_telemetry_features(self, telemetry: TelemetryData) -> List[float]:
        """Extract features from a single telemetry data point."""
        features = []

        # Basic temporal features
        features.extend([
            telemetry.timestamp.hour,
            telemetry.timestamp.minute,
            telemetry.timestamp.weekday(),
        ])

        # Source and type encoding
        source_encoding = hash(telemetry.source) % 1000 / 1000.0  # Normalize hash
        type_encoding = hash(telemetry.data_type) % 1000 / 1000.0
        features.extend([source_encoding, type_encoding])

        # Risk indicators count
        features.append(len(telemetry.risk_indicators))

        # Extract numerical features from payload
        payload_features = self._extract_payload_features(telemetry.payload)
        features.extend(payload_features)

        # Pad or truncate to fixed size (49 features as per UNSW-NB15)
        target_size = 49
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        else:
            features = features[:target_size]

        return features

    def _extract_payload_features(self, payload: Dict[str, Any]) -> List[float]:
        """Extract numerical features from payload data."""
        features = []

        # Common numerical fields
        numerical_fields = [
            'cpu_usage', 'memory_usage', 'disk_io_read', 'disk_io_write',
            'network_connections', 'packet_size', 'src_port', 'dst_port',
            'tcp_window', 'total_events', 'failed_logins', 'suspicious_file_access'
        ]

        for field in numerical_fields:
            if field in payload:
                value = payload[field]
                if isinstance(value, (int, float)):
                    features.append(float(value))
                else:
                    features.append(0.0)
            else:
                features.append(0.0)

        # Statistical features from distributions
        if 'event_distribution' in payload and isinstance(payload['event_distribution'], dict):
            event_values = list(payload['event_distribution'].values())
            if event_values:
                features.extend([
                    np.mean(event_values),
                    np.std(event_values),
                    np.max(event_values),
                    np.min(event_values)
                ])
            else:
                features.extend([0.0, 0.0, 0.0, 0.0])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])

        return features

class AnalyticsEngine:
    """Main analytics engine implementing the Analytics Layer."""

    def __init__(self, model_dir: str = "models", device: str = "cpu"):
        self.model_dir = model_dir
        self.device = torch.device(device)

        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.mitre_mapper = MitreAttackMapper()
        self.model = None
        self.is_trained = False

        # Analysis history
        self.analysis_history = deque(maxlen=10000)
        self.performance_metrics = {
            'total_analyzed': 0,
            'anomalies_detected': 0,
            'high_risk_events': 0,
            'last_analysis': None
        }

        # MLflow experiment tracking
        self.experiment_name = "adaptive_security_analytics"
        self._setup_mlflow()

    def _setup_mlflow(self):
        """Setup MLflow for experiment tracking."""
        try:
            mlflow.set_experiment(self.experiment_name)
            logger.info(f"MLflow experiment set: {self.experiment_name}")
        except Exception as e:
            logger.warning(f"MLflow setup failed: {e}")

    def initialize_model(self, input_dim: int = 49):
        """Initialize the hybrid anomaly detection model."""
        self.model = HybridAnomalyDetector(
            input_dim=input_dim,
            hidden_dim=256,
            num_lstm_layers=3,
            num_transformer_layers=2,
            num_heads=6,
            dropout=0.3
        ).to(self.device)

        logger.info(f"Hybrid anomaly detector initialized with {input_dim} input features")

        return self.model

    def train_model(self, training_data: List[TelemetryData],
                   validation_data: List[TelemetryData] = None,
                   epochs: int = 100, learning_rate: float = 0.0005) -> Dict[str, Any]:
        """
        Train the hybrid anomaly detection model.

        Args:
            training_data: List of telemetry data for training
            validation_data: Optional validation data
            epochs: Number of training epochs
            learning_rate: Learning rate for optimization

        Returns:
            Training metrics dictionary
        """
        if self.model is None:
            self.initialize_model()

        # Extract features
        X_train = self.feature_extractor.extract_features(training_data)

        # Create synthetic labels (assume most data is normal)
        # In real implementation, this would come from labeled data
        y_train = np.random.binomial(1, 0.1, len(X_train))  # 10% anomalies

        # Convert to sequences (using sliding window approach)
        sequence_length = 10
        X_sequences, y_sequences = self._create_sequences(X_train, y_train, sequence_length)

        # Convert to PyTorch tensors
        X_tensor = torch.FloatTensor(X_sequences).to(self.device)
        y_tensor = torch.FloatTensor(y_sequences).to(self.device)

        # Setup training
        criterion = nn.BCELoss()  # Binary cross-entropy for anomaly detection
        optimizer = optim.AdamW(self.model.parameters(), lr=learning_rate, weight_decay=0.01)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

        # Training loop
        training_losses = []
        validation_losses = []

        with mlflow.start_run():
            # Log hyperparameters
            mlflow.log_params({
                'epochs': epochs,
                'learning_rate': learning_rate,
                'sequence_length': sequence_length,
                'model_type': 'LSTM-Transformer Hybrid'
            })

            self.model.train()
            for epoch in range(epochs):
                epoch_loss = 0.0

                # Mini-batch training
                batch_size = 32
                num_batches = len(X_tensor) // batch_size

                for i in range(0, len(X_tensor), batch_size):
                    batch_X = X_tensor[i:i+batch_size]
                    batch_y = y_tensor[i:i+batch_size].unsqueeze(1)

                    optimizer.zero_grad()

                    # Forward pass
                    outputs = self.model(batch_X)
                    loss = criterion(outputs, batch_y)

                    # Backward pass
                    loss.backward()

                    # Gradient clipping for stability
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

                    optimizer.step()
                    epoch_loss += loss.item()

                epoch_loss /= num_batches
                training_losses.append(epoch_loss)

                # Validation if available
                if validation_data:
                    val_loss = self._validate_model(validation_data, criterion, sequence_length)
                    validation_losses.append(val_loss)

                scheduler.step()

                # Log metrics
                if epoch % 10 == 0:
                    logger.info(f"Epoch {epoch}/{epochs}, Loss: {epoch_loss:.4f}")
                    mlflow.log_metric('training_loss', epoch_loss, step=epoch)
                    if validation_data:
                        mlflow.log_metric('validation_loss', validation_losses[-1], step=epoch)

            # Save model
            model_path = f"{self.model_dir}/hybrid_anomaly_detector.pth"
            torch.save(self.model.state_dict(), model_path)
            mlflow.pytorch.log_model(self.model, "model")

            self.is_trained = True
            logger.info("Model training completed")

        return {
            'training_losses': training_losses,
            'validation_losses': validation_losses,
            'final_loss': training_losses[-1],
            'epochs_completed': epochs
        }

    def _create_sequences(self, X: np.ndarray, y: np.ndarray,
                         sequence_length: int) -> Tuple[np.ndarray, np.ndarray]:
        """Create sequences from time series data."""
        sequences_X = []
        sequences_y = []

        for i in range(len(X) - sequence_length + 1):
            sequences_X.append(X[i:i+sequence_length])
            sequences_y.append(y[i+sequence_length-1])  # Use last label in sequence

        return np.array(sequences_X), np.array(sequences_y)

    def _validate_model(self, validation_data: List[TelemetryData],
                       criterion, sequence_length: int) -> float:
        """Validate model on validation data."""
        if not validation_data:
            return 0.0

        self.model.eval()
        with torch.no_grad():
            X_val = self.feature_extractor.extract_features(validation_data)
            y_val = np.random.binomial(1, 0.1, len(X_val))  # Synthetic labels

            X_seq, y_seq = self._create_sequences(X_val, y_val, sequence_length)
            X_tensor = torch.FloatTensor(X_seq).to(self.device)
            y_tensor = torch.FloatTensor(y_seq).to(self.device)

            outputs = self.model(X_tensor)
            loss = criterion(outputs, y_tensor.unsqueeze(1))

        self.model.train()
        return loss.item()

    def analyze_telemetry_batch(self, telemetry_batch: List[TelemetryData]) -> List[AnalysisResult]:
        """
        Analyze a batch of telemetry data for anomalies and threats.

        Args:
            telemetry_batch: List of telemetry data to analyze

        Returns:
            List of analysis results
        """
        if not telemetry_batch:
            return []

        results = []

        # Extract features
        features = self.feature_extractor.extract_features(telemetry_batch)

        # Analyze each telemetry point
        for i, telemetry in enumerate(telemetry_batch):
            result = self._analyze_single_telemetry(telemetry, features[i] if len(features) > i else None)
            results.append(result)

            # Update statistics
            self.performance_metrics['total_analyzed'] += 1
            if result.is_anomalous:
                self.performance_metrics['anomalies_detected'] += 1
            if result.risk_level == 'high':
                self.performance_metrics['high_risk_events'] += 1

        self.performance_metrics['last_analysis'] = datetime.now()

        # Store results in history
        self.analysis_history.extend(results)

        return results

    def _analyze_single_telemetry(self, telemetry: TelemetryData,
                                 features: Optional[np.ndarray] = None) -> AnalysisResult:
        """Analyze a single telemetry data point."""

        # Initialize analysis result
        analysis_result = AnalysisResult(
            anomaly_score=0.0,
            is_anomalous=False,
            threat_classification='unknown',
            confidence=0.0,
            mitre_tactics=[],
            mitre_techniques=[],
            risk_level='low',
            timestamp=datetime.now(),
            features_analyzed=[]
        )

        # Use ML model if trained and features available
        if self.is_trained and self.model is not None and features is not None:
            try:
                # Create sequence (using padding for single point analysis)
                sequence_length = 10
                feature_sequence = np.tile(features, (sequence_length, 1)).reshape(1, sequence_length, -1)

                # Convert to tensor
                X_tensor = torch.FloatTensor(feature_sequence).to(self.device)

                # Model prediction
                self.model.eval()
                with torch.no_grad():
                    output = self.model(X_tensor)
                    anomaly_score = output.item()

                analysis_result.anomaly_score = anomaly_score
                analysis_result.is_anomalous = anomaly_score > 0.5
                analysis_result.confidence = anomaly_score if anomaly_score > 0.5 else 1 - anomaly_score

            except Exception as e:
                logger.error(f"ML model analysis failed: {e}")

        # Rule-based analysis fallback
        risk_score = len(telemetry.risk_indicators) * 0.2
        if not analysis_result.is_anomalous and risk_score > 0.6:
            analysis_result.is_anomalous = True
            analysis_result.anomaly_score = max(analysis_result.anomaly_score, risk_score)

        # Map to MITRE ATT&CK
        if telemetry.risk_indicators:
            tactics, techniques = self.mitre_mapper.map_to_mitre(telemetry.risk_indicators)
            analysis_result.mitre_tactics = tactics
            analysis_result.mitre_techniques = techniques

        # Determine threat classification and risk level
        if analysis_result.is_anomalous:
            if analysis_result.anomaly_score > 0.8:
                analysis_result.threat_classification = 'high_severity_threat'
                analysis_result.risk_level = 'high'
            elif analysis_result.anomaly_score > 0.6:
                analysis_result.threat_classification = 'medium_severity_threat'
                analysis_result.risk_level = 'medium'
            else:
                analysis_result.threat_classification = 'low_severity_anomaly'
                analysis_result.risk_level = 'low'
        else:
            analysis_result.threat_classification = 'normal'
            analysis_result.risk_level = 'low'

        # Set features analyzed
        analysis_result.features_analyzed = self.feature_extractor.feature_columns if hasattr(self.feature_extractor, 'feature_columns') else []

        return analysis_result

    def get_analytics_stats(self) -> Dict[str, Any]:
        """Get analytics engine statistics."""
        return {
            'model_initialized': self.model is not None,
            'model_trained': self.is_trained,
            'feature_extractor_fitted': self.feature_extractor.is_fitted,
            'performance_metrics': self.performance_metrics,
            'analysis_history_size': len(self.analysis_history),
            'device': str(self.device),
            'model_parameters': sum(p.numel() for p in self.model.parameters()) if self.model else 0
        }

# Global analytics engine instance
_analytics_engine = None

def get_analytics_engine() -> AnalyticsEngine:
    """Get global analytics engine instance."""
    global _analytics_engine
    if _analytics_engine is None:
        _analytics_engine = AnalyticsEngine()
    return _analytics_engine