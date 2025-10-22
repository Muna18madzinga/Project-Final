"""
Model Training Module - Adaptive Security Suite
Trains ML models with various cybersecurity datasets
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import logging
from datetime import datetime
import os

logger = logging.getLogger(__name__)


class SecurityDatasetGenerator:
    """Generate synthetic security datasets for training"""

    @staticmethod
    def generate_network_traffic_dataset(n_samples=10000):
        """Generate network traffic dataset with normal and attack patterns"""
        np.random.seed(42)

        # Normal traffic (70%)
        n_normal = int(n_samples * 0.7)
        normal_data = {
            'packet_size': np.random.normal(500, 150, n_normal),
            'packets_per_sec': np.random.normal(50, 15, n_normal),
            'port': np.random.choice([80, 443, 22, 21], n_normal),
            'duration': np.random.exponential(5, n_normal),
            'protocol': np.random.choice([0, 1, 2], n_normal),  # TCP, UDP, ICMP
            'label': np.zeros(n_normal)  # 0 = normal
        }

        # DDoS attacks (10%)
        n_ddos = int(n_samples * 0.1)
        ddos_data = {
            'packet_size': np.random.normal(64, 20, n_ddos),  # Small packets
            'packets_per_sec': np.random.normal(1000, 200, n_ddos),  # High rate
            'port': np.random.choice([80, 443], n_ddos),
            'duration': np.random.exponential(0.1, n_ddos),  # Short duration
            'protocol': np.random.choice([0, 2], n_ddos),
            'label': np.ones(n_ddos) * 1  # 1 = DDoS
        }

        # Port scans (10%)
        n_portscan = int(n_samples * 0.1)
        portscan_data = {
            'packet_size': np.random.normal(40, 10, n_portscan),
            'packets_per_sec': np.random.normal(100, 30, n_portscan),
            'port': np.random.randint(1, 65535, n_portscan),  # Random ports
            'duration': np.random.exponential(0.5, n_portscan),
            'protocol': np.ones(n_portscan) * 0,  # TCP
            'label': np.ones(n_portscan) * 2  # 2 = Port Scan
        }

        # SQL Injection attempts (5%)
        n_sqli = int(n_samples * 0.05)
        sqli_data = {
            'packet_size': np.random.normal(800, 200, n_sqli),  # Larger packets
            'packets_per_sec': np.random.normal(20, 10, n_sqli),
            'port': np.ones(n_sqli) * 80,  # HTTP
            'duration': np.random.exponential(2, n_sqli),
            'protocol': np.zeros(n_sqli),
            'label': np.ones(n_sqli) * 3  # 3 = SQL Injection
        }

        # Malware C&C (5%)
        n_malware = n_samples - n_normal - n_ddos - n_portscan - n_sqli
        malware_data = {
            'packet_size': np.random.normal(300, 100, n_malware),
            'packets_per_sec': np.random.normal(5, 2, n_malware),  # Low rate
            'port': np.random.choice([8080, 8443, 6667], n_malware),  # Suspicious ports
            'duration': np.random.exponential(60, n_malware),  # Long duration
            'protocol': np.zeros(n_malware),
            'label': np.ones(n_malware) * 4  # 4 = Malware C&C
        }

        # Combine all datasets
        all_data = {}
        for key in normal_data.keys():
            all_data[key] = np.concatenate([
                normal_data[key],
                ddos_data[key],
                portscan_data[key],
                sqli_data[key],
                malware_data[key]
            ])

        df = pd.DataFrame(all_data)

        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        logger.info(f"Generated network traffic dataset: {len(df)} samples")
        return df

    @staticmethod
    def generate_authentication_dataset(n_samples=5000):
        """Generate authentication attempt dataset"""
        np.random.seed(42)

        # Normal logins (80%)
        n_normal = int(n_samples * 0.8)
        normal_auth = {
            'failed_attempts': np.random.poisson(0.5, n_normal),
            'time_of_day': np.random.normal(12, 4, n_normal),  # Business hours
            'location_change': np.random.binomial(1, 0.1, n_normal),
            'password_strength': np.random.normal(80, 10, n_normal),
            'session_duration': np.random.exponential(30, n_normal),
            'label': np.zeros(n_normal)  # 0 = legitimate
        }

        # Brute force (10%)
        n_bruteforce = int(n_samples * 0.1)
        bruteforce = {
            'failed_attempts': np.random.randint(10, 50, n_bruteforce),
            'time_of_day': np.random.uniform(0, 24, n_bruteforce),
            'location_change': np.random.binomial(1, 0.3, n_bruteforce),
            'password_strength': np.random.normal(40, 15, n_bruteforce),
            'session_duration': np.random.exponential(1, n_bruteforce),
            'label': np.ones(n_bruteforce) * 1  # 1 = brute force
        }

        # Credential stuffing (10%)
        n_credstuff = n_samples - n_normal - n_bruteforce
        credstuff = {
            'failed_attempts': np.random.randint(5, 20, n_credstuff),
            'time_of_day': np.random.uniform(0, 24, n_credstuff),
            'location_change': np.random.binomial(1, 0.7, n_credstuff),  # High location change
            'password_strength': np.random.normal(50, 20, n_credstuff),
            'session_duration': np.random.exponential(2, n_credstuff),
            'label': np.ones(n_credstuff) * 2  # 2 = credential stuffing
        }

        # Combine
        all_data = {}
        for key in normal_auth.keys():
            all_data[key] = np.concatenate([
                normal_auth[key],
                bruteforce[key],
                credstuff[key]
            ])

        df = pd.DataFrame(all_data)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        logger.info(f"Generated authentication dataset: {len(df)} samples")
        return df

    @staticmethod
    def generate_anomaly_dataset(n_samples=8000):
        """Generate dataset for anomaly detection"""
        np.random.seed(42)

        # Normal behavior (90%)
        n_normal = int(n_samples * 0.9)
        normal = {
            'cpu_usage': np.random.normal(40, 10, n_normal),
            'memory_usage': np.random.normal(50, 15, n_normal),
            'disk_io': np.random.normal(100, 30, n_normal),
            'network_traffic': np.random.normal(500, 100, n_normal),
            'process_count': np.random.poisson(50, n_normal),
            'label': np.zeros(n_normal)
        }

        # Anomalies (10%)
        n_anomaly = n_samples - n_normal
        anomaly = {
            'cpu_usage': np.random.uniform(80, 100, n_anomaly),
            'memory_usage': np.random.uniform(80, 100, n_anomaly),
            'disk_io': np.random.uniform(500, 1000, n_anomaly),
            'network_traffic': np.random.uniform(2000, 5000, n_anomaly),
            'process_count': np.random.randint(100, 200, n_anomaly),
            'label': np.ones(n_anomaly)
        }

        # Combine
        all_data = {}
        for key in normal.keys():
            all_data[key] = np.concatenate([normal[key], anomaly[key]])

        df = pd.DataFrame(all_data)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        logger.info(f"Generated anomaly detection dataset: {len(df)} samples")
        return df


class ModelTrainer:
    """Train and evaluate security ML models"""

    def __init__(self):
        self.models = {}
        self.training_history = []
        self.model_dir = 'models'
        os.makedirs(self.model_dir, exist_ok=True)

    def train_network_threat_model(self, df):
        """Train Random Forest for network threat classification"""
        logger.info("Training network threat detection model...")

        X = df.drop('label', axis=1)
        y = df['label']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )

        model.fit(X_train, y_train)

        # Evaluate
        y_pred = model.predict(X_test)

        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_test, y_pred, average='weighted', zero_division=0)
        }

        # Save model
        model_path = os.path.join(self.model_dir, 'network_threat_model.pkl')
        joblib.dump(model, model_path)

        self.models['network_threat'] = model

        logger.info(f"Network threat model trained - Accuracy: {metrics['accuracy']:.4f}")

        return {
            'model_name': 'Network Threat Detection',
            'model_type': 'RandomForest',
            'samples_trained': len(X_train),
            'samples_tested': len(X_test),
            'metrics': metrics,
            'timestamp': str(datetime.now())
        }

    def train_authentication_model(self, df):
        """Train model for authentication threat detection"""
        logger.info("Training authentication security model...")

        X = df.drop('label', axis=1)
        y = df['label']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        model = RandomForestClassifier(
            n_estimators=80,
            max_depth=8,
            random_state=42,
            n_jobs=-1
        )

        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_test, y_pred, average='weighted', zero_division=0)
        }

        model_path = os.path.join(self.model_dir, 'auth_security_model.pkl')
        joblib.dump(model, model_path)

        self.models['auth_security'] = model

        logger.info(f"Auth security model trained - Accuracy: {metrics['accuracy']:.4f}")

        return {
            'model_name': 'Authentication Security',
            'model_type': 'RandomForest',
            'samples_trained': len(X_train),
            'samples_tested': len(X_test),
            'metrics': metrics,
            'timestamp': str(datetime.now())
        }

    def train_anomaly_model(self, df):
        """Train Isolation Forest for anomaly detection"""
        logger.info("Training anomaly detection model...")

        X = df.drop('label', axis=1)
        y = df['label']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )

        model.fit(X_train)

        # Predict (-1 for anomaly, 1 for normal)
        y_pred = model.predict(X_test)
        # Convert to 0/1
        y_pred = np.where(y_pred == -1, 1, 0)

        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1_score': f1_score(y_test, y_pred, zero_division=0)
        }

        model_path = os.path.join(self.model_dir, 'anomaly_detection_model.pkl')
        joblib.dump(model, model_path)

        self.models['anomaly_detection'] = model

        logger.info(f"Anomaly detection model trained - Accuracy: {metrics['accuracy']:.4f}")

        return {
            'model_name': 'Anomaly Detection',
            'model_type': 'IsolationForest',
            'samples_trained': len(X_train),
            'samples_tested': len(X_test),
            'metrics': metrics,
            'timestamp': str(datetime.now())
        }

    def train_all_models(self):
        """Train all security models with generated datasets"""
        results = []

        # Generate datasets
        network_df = SecurityDatasetGenerator.generate_network_traffic_dataset()
        auth_df = SecurityDatasetGenerator.generate_authentication_dataset()
        anomaly_df = SecurityDatasetGenerator.generate_anomaly_dataset()

        # Train models
        results.append(self.train_network_threat_model(network_df))
        results.append(self.train_authentication_model(auth_df))
        results.append(self.train_anomaly_model(anomaly_df))

        # Record training history
        self.training_history.append({
            'timestamp': str(datetime.now()),
            'models_trained': len(results),
            'results': results
        })

        return results


# Global trainer instance
_trainer = None

def get_trainer():
    """Get or create global trainer instance"""
    global _trainer
    if _trainer is None:
        _trainer = ModelTrainer()
    return _trainer
