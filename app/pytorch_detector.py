"""
PyTorch ML Detection Runtime - Chapter 4 Analysis
Executes deep learning models in PyTorch runtime for real-time threat detection.
Integrates with data preprocessing pipeline and telemetry collection.
"""

import logging
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, TensorDataset
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import joblib
import json
from pathlib import Path
from collections import deque

# Import preprocessing components
from .data_preprocessing import get_dataset_processor, DatasetProcessor
from .architecture.telemetry_collection import TelemetryData, get_telemetry_processor
from .architecture.analytics_layer import HybridAnomalyDetector, MitreAttackMapper

logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    """Detection result from PyTorch model."""
    is_threat: bool
    confidence: float
    threat_type: str
    anomaly_score: float
    mitre_tactics: List[str]
    model_version: str
    inference_time_ms: float
    timestamp: datetime

class CNNThreatDetector(nn.Module):
    """
    1D CNN for spatial pattern detection in network traffic.
    Effective for detecting payload-based attacks (XSS, SQLi).
    """

    def __init__(self, input_dim: int, num_classes: int = 2):
        super(CNNThreatDetector, self).__init__()

        self.input_dim = input_dim
        self.num_classes = num_classes

        # 1D Convolutional layers for pattern recognition
        self.conv_layers = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.MaxPool1d(2),
            nn.Dropout(0.2),

            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.MaxPool1d(2),
            nn.Dropout(0.3),

            nn.Conv1d(128, 256, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.BatchNorm1d(256),
            nn.AdaptiveAvgPool1d(1)
        )

        # Fully connected layers
        self.fc_layers = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes)
        )

        self._init_weights()

    def _init_weights(self):
        """Initialize weights using Xavier initialization."""
        for m in self.modules():
            if isinstance(m, nn.Conv1d) or isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x):
        """
        Forward pass.
        Args:
            x: Input tensor (batch_size, input_dim) or (batch_size, 1, input_dim)
        Returns:
            Class logits
        """
        # Reshape if necessary
        if x.dim() == 2:
            x = x.unsqueeze(1)  # Add channel dimension

        # Convolutional feature extraction
        features = self.conv_layers(x)

        # Flatten
        features = features.view(features.size(0), -1)

        # Classification
        output = self.fc_layers(features)

        return output

class AutoencoderAnomalyDetector(nn.Module):
    """
    Autoencoder for unsupervised anomaly detection.
    Reconstruction error serves as anomaly score.
    """

    def __init__(self, input_dim: int, latent_dim: int = 32):
        super(AutoencoderAnomalyDetector, self).__init__()

        self.input_dim = input_dim
        self.latent_dim = latent_dim

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.BatchNorm1d(256),
            nn.Dropout(0.2),

            nn.Linear(256, 128),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.Dropout(0.2),

            nn.Linear(128, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),

            nn.Linear(64, latent_dim)
        )

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),

            nn.Linear(64, 128),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.Dropout(0.2),

            nn.Linear(128, 256),
            nn.ReLU(),
            nn.BatchNorm1d(256),
            nn.Dropout(0.2),

            nn.Linear(256, input_dim)
        )

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_uniform_(m.weight, nonlinearity='relu')
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x):
        """
        Forward pass through autoencoder.
        Args:
            x: Input tensor (batch_size, input_dim)
        Returns:
            Reconstructed tensor
        """
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

    def get_reconstruction_error(self, x):
        """Calculate reconstruction error for anomaly detection."""
        with torch.no_grad():
            reconstructed = self.forward(x)
            error = torch.mean((x - reconstructed) ** 2, dim=1)
        return error

class DeepMLPClassifier(nn.Module):
    """
    Deep Multi-Layer Perceptron for threat classification.
    General-purpose classifier for various attack types.
    """

    def __init__(self, input_dim: int, num_classes: int = 10):
        super(DeepMLPClassifier, self).__init__()

        self.input_dim = input_dim
        self.num_classes = num_classes

        # Deep architecture with residual connections
        self.input_layer = nn.Linear(input_dim, 512)

        self.hidden_blocks = nn.ModuleList([
            self._make_residual_block(512, 512),
            self._make_residual_block(512, 256),
            self._make_residual_block(256, 128)
        ])

        self.output_layer = nn.Linear(128, num_classes)

        self._init_weights()

    def _make_residual_block(self, in_features, out_features):
        """Create residual block with skip connection."""
        block = nn.ModuleDict({
            'fc1': nn.Linear(in_features, out_features),
            'bn1': nn.BatchNorm1d(out_features),
            'fc2': nn.Linear(out_features, out_features),
            'bn2': nn.BatchNorm1d(out_features),
            'shortcut': nn.Linear(in_features, out_features) if in_features != out_features else nn.Identity(),
            'dropout': nn.Dropout(0.3)
        })
        return block

    def _forward_block(self, x, block):
        """Forward pass through residual block."""
        identity = block['shortcut'](x)

        out = block['fc1'](x)
        out = block['bn1'](out)
        out = torch.relu(out)
        out = block['dropout'](out)

        out = block['fc2'](out)
        out = block['bn2'](out)

        out += identity
        out = torch.relu(out)

        return out

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)

    def forward(self, x):
        """Forward pass."""
        x = torch.relu(self.input_layer(x))

        for block in self.hidden_blocks:
            x = self._forward_block(x, block)

        output = self.output_layer(x)
        return output

class PyTorchDetectionRuntime:
    """
    PyTorch runtime for executing ML detection models.
    Manages model loading, inference, and integration with preprocessing.
    """

    def __init__(self, model_dir: str = "models/pytorch", device: str = None):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Auto-detect device
        if device is None:
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        else:
            self.device = torch.device(device)

        logger.info(f"PyTorch runtime initialized on device: {self.device}")

        # Model registry
        self.models = {}
        self.model_configs = {}

        # Preprocessing components
        self.preprocessor = get_dataset_processor()
        self.mitre_mapper = MitreAttackMapper()

        # Inference history
        self.inference_history = deque(maxlen=10000)

        # Performance metrics
        self.performance_stats = {
            'total_inferences': 0,
            'avg_inference_time_ms': 0.0,
            'threats_detected': 0,
            'false_positive_rate': 0.0
        }

        # Initialize models
        self._initialize_models()

    def _initialize_models(self):
        """Initialize default PyTorch models."""
        logger.info("Initializing PyTorch detection models...")

        # Determine input dimension from preprocessor
        input_dim = 100  # Default, will be updated based on actual data

        # 1. CNN Threat Detector
        self.models['cnn_detector'] = CNNThreatDetector(
            input_dim=input_dim,
            num_classes=10  # Multi-class: normal + 9 attack types
        ).to(self.device)

        # 2. Autoencoder Anomaly Detector
        self.models['autoencoder'] = AutoencoderAnomalyDetector(
            input_dim=input_dim,
            latent_dim=32
        ).to(self.device)

        # 3. Deep MLP Classifier
        self.models['mlp_classifier'] = DeepMLPClassifier(
            input_dim=input_dim,
            num_classes=10
        ).to(self.device)

        # 4. Hybrid LSTM-Transformer (from analytics_layer)
        self.models['hybrid_detector'] = HybridAnomalyDetector(
            input_dim=input_dim,
            hidden_dim=256,
            num_lstm_layers=3,
            num_transformer_layers=2
        ).to(self.device)

        # Load pretrained weights if available
        self._load_pretrained_models()

        logger.info(f"Initialized {len(self.models)} PyTorch models")

    def _load_pretrained_models(self):
        """Load pretrained model weights if available."""
        for model_name, model in self.models.items():
            model_path = self.model_dir / f"{model_name}.pt"
            if model_path.exists():
                try:
                    checkpoint = torch.load(model_path, map_location=self.device)
                    model.load_state_dict(checkpoint['model_state_dict'])
                    model.eval()
                    logger.info(f"Loaded pretrained weights for {model_name}")
                except Exception as e:
                    logger.warning(f"Failed to load {model_name}: {e}")

    def preprocess_input(self, raw_data: Dict[str, Any]) -> torch.Tensor:
        """
        Preprocess raw input data for model inference.

        Args:
            raw_data: Raw telemetry or security event data

        Returns:
            Preprocessed tensor ready for model input
        """
        # Convert to DataFrame
        if isinstance(raw_data, dict):
            df = pd.DataFrame([raw_data])
        elif isinstance(raw_data, pd.DataFrame):
            df = raw_data
        else:
            raise ValueError("Input must be dict or DataFrame")

        # Apply preprocessing pipeline (without target column)
        processed = self.preprocessor.process_dataset(
            df,
            dataset_name='runtime_input',
            target_column=None,
            apply_privacy=False
        )

        # Convert to tensor
        X = processed['X_train']  # Use train split (no actual split needed)
        X_tensor = torch.FloatTensor(X.values).to(self.device)

        return X_tensor

    def detect_threats(self, data: Dict[str, Any],
                      model_name: str = 'ensemble') -> DetectionResult:
        """
        Execute threat detection using PyTorch models.

        Args:
            data: Input data (telemetry or security event)
            model_name: Model to use ('cnn_detector', 'autoencoder', 'mlp_classifier',
                       'hybrid_detector', or 'ensemble')

        Returns:
            DetectionResult with threat analysis
        """
        start_time = datetime.now()

        try:
            # Preprocess input
            X = self.preprocess_input(data)

            # Ensemble detection (default)
            if model_name == 'ensemble':
                result = self._ensemble_detection(X, data)
            else:
                result = self._single_model_detection(X, data, model_name)

            # Calculate inference time
            inference_time = (datetime.now() - start_time).total_seconds() * 1000
            result.inference_time_ms = inference_time

            # Update statistics
            self._update_stats(result, inference_time)

            # Store in history
            self.inference_history.append(result)

            return result

        except Exception as e:
            logger.error(f"Detection error: {e}")
            return DetectionResult(
                is_threat=False,
                confidence=0.0,
                threat_type='error',
                anomaly_score=0.0,
                mitre_tactics=[],
                model_version='error',
                inference_time_ms=0.0,
                timestamp=datetime.now()
            )

    def _single_model_detection(self, X: torch.Tensor, raw_data: Dict,
                               model_name: str) -> DetectionResult:
        """Perform detection using a single model."""
        model = self.models[model_name]
        model.eval()

        with torch.no_grad():
            if model_name == 'autoencoder':
                # Anomaly detection via reconstruction error
                recon_error = model.get_reconstruction_error(X)
                anomaly_score = recon_error.mean().item()
                is_threat = anomaly_score > 0.5  # Threshold
                confidence = min(anomaly_score, 1.0)
                threat_type = 'anomaly' if is_threat else 'normal'

            elif model_name == 'hybrid_detector':
                # Sequence-based detection (reshape for LSTM)
                X_seq = X.unsqueeze(1)  # Add sequence dimension
                output = model(X_seq)
                confidence = output.squeeze().item()
                is_threat = confidence > 0.5
                anomaly_score = confidence
                threat_type = 'sequence_anomaly' if is_threat else 'normal'

            else:
                # Classification models (CNN, MLP)
                logits = model(X)
                probs = torch.softmax(logits, dim=1)
                confidence, predicted_class = torch.max(probs, dim=1)

                confidence = confidence.item()
                predicted_class = predicted_class.item()

                is_threat = predicted_class > 0  # Class 0 = normal
                anomaly_score = 1.0 - probs[0, 0].item()  # Inverse of normal probability

                # Map class to threat type
                threat_types = [
                    'normal', 'sql_injection', 'xss', 'ddos', 'port_scan',
                    'brute_force', 'malware', 'privilege_escalation',
                    'data_exfiltration', 'unknown'
                ]
                threat_type = threat_types[predicted_class] if predicted_class < len(threat_types) else 'unknown'

        # Map to MITRE ATT&CK
        mitre_tactics = self._map_to_mitre(threat_type, raw_data)

        return DetectionResult(
            is_threat=is_threat,
            confidence=float(confidence),
            threat_type=threat_type,
            anomaly_score=float(anomaly_score),
            mitre_tactics=mitre_tactics,
            model_version=f"{model_name}_v1.0",
            inference_time_ms=0.0,  # Will be updated
            timestamp=datetime.now()
        )

    def _ensemble_detection(self, X: torch.Tensor, raw_data: Dict) -> DetectionResult:
        """Perform ensemble detection using multiple models."""
        predictions = []

        # Get predictions from all models
        for model_name in ['cnn_detector', 'autoencoder', 'mlp_classifier', 'hybrid_detector']:
            result = self._single_model_detection(X, raw_data, model_name)
            predictions.append(result)

        # Ensemble voting
        threat_votes = sum(1 for p in predictions if p.is_threat)
        is_threat = threat_votes >= 2  # Majority voting

        # Average confidence and anomaly scores
        avg_confidence = np.mean([p.confidence for p in predictions])
        avg_anomaly = np.mean([p.anomaly_score for p in predictions])

        # Aggregate threat types
        threat_types = [p.threat_type for p in predictions if p.is_threat]
        final_threat_type = max(set(threat_types), key=threat_types.count) if threat_types else 'normal'

        # Aggregate MITRE tactics
        all_tactics = []
        for p in predictions:
            all_tactics.extend(p.mitre_tactics)
        unique_tactics = list(set(all_tactics))

        return DetectionResult(
            is_threat=is_threat,
            confidence=float(avg_confidence),
            threat_type=final_threat_type,
            anomaly_score=float(avg_anomaly),
            mitre_tactics=unique_tactics,
            model_version='ensemble_v1.0',
            inference_time_ms=0.0,
            timestamp=datetime.now()
        )

    def _map_to_mitre(self, threat_type: str, raw_data: Dict) -> List[str]:
        """Map detected threat to MITRE ATT&CK tactics."""
        tactic_mapping = {
            'sql_injection': ['initial_access', 'execution'],
            'xss': ['initial_access', 'execution', 'persistence'],
            'ddos': ['impact'],
            'port_scan': ['discovery', 'reconnaissance'],
            'brute_force': ['credential_access', 'initial_access'],
            'malware': ['execution', 'persistence', 'defense_evasion'],
            'privilege_escalation': ['privilege_escalation'],
            'data_exfiltration': ['exfiltration', 'collection']
        }

        return tactic_mapping.get(threat_type, [])

    def _update_stats(self, result: DetectionResult, inference_time: float):
        """Update performance statistics."""
        self.performance_stats['total_inferences'] += 1

        # Running average of inference time
        n = self.performance_stats['total_inferences']
        current_avg = self.performance_stats['avg_inference_time_ms']
        self.performance_stats['avg_inference_time_ms'] = (
            (current_avg * (n - 1) + inference_time) / n
        )

        if result.is_threat:
            self.performance_stats['threats_detected'] += 1

    def train_model(self, model_name: str, train_data: pd.DataFrame,
                   target_column: str, epochs: int = 50,
                   batch_size: int = 64, learning_rate: float = 0.001):
        """
        Train a PyTorch model with preprocessed data.

        Args:
            model_name: Name of model to train
            train_data: Training DataFrame
            target_column: Name of target column
            epochs: Number of training epochs
            batch_size: Batch size for training
            learning_rate: Learning rate
        """
        logger.info(f"Training {model_name} with {len(train_data)} samples...")

        # Preprocess data
        processed = self.preprocessor.process_dataset(
            train_data,
            dataset_name='training',
            target_column=target_column,
            test_size=0.2,
            validation_size=0.1,
            apply_privacy=False
        )

        # Convert to tensors
        X_train = torch.FloatTensor(processed['X_train'].values).to(self.device)
        y_train = torch.LongTensor(processed['y_train']).to(self.device)
        X_val = torch.FloatTensor(processed['X_val'].values).to(self.device)
        y_val = torch.LongTensor(processed['y_val']).to(self.device)

        # Create data loaders
        train_dataset = TensorDataset(X_train, y_train)
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

        # Get model
        model = self.models[model_name]
        model.train()

        # Loss and optimizer
        if model_name == 'autoencoder':
            criterion = nn.MSELoss()
        else:
            criterion = nn.CrossEntropyLoss()

        optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, 'min', patience=5)

        # Training loop
        best_val_loss = float('inf')

        for epoch in range(epochs):
            epoch_loss = 0.0

            for batch_X, batch_y in train_loader:
                optimizer.zero_grad()

                if model_name == 'autoencoder':
                    # Autoencoder training
                    output = model(batch_X)
                    loss = criterion(output, batch_X)
                elif model_name == 'hybrid_detector':
                    # Sequence model training
                    batch_X_seq = batch_X.unsqueeze(1)
                    output = model(batch_X_seq)
                    loss = nn.BCELoss()(output.squeeze(), batch_y.float())
                else:
                    # Classification model training
                    output = model(batch_X)
                    loss = criterion(output, batch_y)

                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()

            # Validation
            model.eval()
            with torch.no_grad():
                if model_name == 'autoencoder':
                    val_output = model(X_val)
                    val_loss = criterion(val_output, X_val).item()
                elif model_name == 'hybrid_detector':
                    X_val_seq = X_val.unsqueeze(1)
                    val_output = model(X_val_seq)
                    val_loss = nn.BCELoss()(val_output.squeeze(), y_val.float()).item()
                else:
                    val_output = model(X_val)
                    val_loss = criterion(val_output, y_val).item()

            model.train()

            # Learning rate scheduling
            scheduler.step(val_loss)

            # Save best model
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                self.save_model(model_name, epoch, val_loss)

            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch [{epoch+1}/{epochs}] - Loss: {epoch_loss/len(train_loader):.4f}, Val Loss: {val_loss:.4f}")

        logger.info(f"Training completed for {model_name}")

    def save_model(self, model_name: str, epoch: int = 0, val_loss: float = 0.0):
        """Save model checkpoint."""
        model_path = self.model_dir / f"{model_name}.pt"

        torch.save({
            'epoch': epoch,
            'model_state_dict': self.models[model_name].state_dict(),
            'val_loss': val_loss,
            'timestamp': datetime.now().isoformat()
        }, model_path)

        logger.info(f"Model {model_name} saved to {model_path}")

    def get_runtime_stats(self) -> Dict[str, Any]:
        """Get runtime performance statistics."""
        return {
            'device': str(self.device),
            'models_loaded': list(self.models.keys()),
            'performance': self.performance_stats,
            'inference_history_size': len(self.inference_history),
            'recent_detections': [
                asdict(r) for r in list(self.inference_history)[-10:]
            ]
        }

# Global runtime instance
_pytorch_runtime = None

def get_pytorch_runtime() -> PyTorchDetectionRuntime:
    """Get global PyTorch runtime instance."""
    global _pytorch_runtime
    if _pytorch_runtime is None:
        _pytorch_runtime = PyTorchDetectionRuntime()
    return _pytorch_runtime
