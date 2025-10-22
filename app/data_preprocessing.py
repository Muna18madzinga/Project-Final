"""
Data Preprocessing Pipeline - Chapter 3.4 Process Analysis / Data Collection and Preprocessing
Implements data cleaning, normalization, feature engineering, and privacy-preserving techniques.
Supports UNSW-NB15, CIC-IDS2018, and custom augmentation datasets as specified.
"""

import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from sklearn.preprocessing import StandardScaler, RobustScaler, LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedShuffleSplit
from sklearn.impute import KNNImputer
from imblearn.over_sampling import ADASYN, SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline
import joblib
import os
from pathlib import Path
import torch
import torch.nn as nn
from opacus import PrivacyEngine
from scapy.all import *
import hashlib
import json

logger = logging.getLogger(__name__)

@dataclass
class DatasetInfo:
    """Dataset information structure."""
    name: str
    source_path: str
    features_count: int
    samples_count: int
    attack_categories: List[str]
    normal_ratio: float
    preprocessing_config: Dict[str, Any]

class DataCleaner:
    """Data cleaning component with advanced imputation strategies using pandas optimizations."""

    def __init__(self):
        self.knn_imputer = KNNImputer(n_neighbors=5)
        self.is_fitted = False
        self.duplicate_stats = {}
        self.missing_data_stats = {}
        self.noise_stats = {}

        # Pandas-specific optimizations
        self.categorical_columns = []
        self.numeric_columns = []

    def clean_data(self, df: pd.DataFrame, remove_duplicates: bool = True,
                  handle_missing: bool = True, remove_noise: bool = True) -> pd.DataFrame:
        """
        Comprehensive data cleaning as per Chapter 3.4 with pandas optimizations.

        Args:
            df: Input DataFrame
            remove_duplicates: Remove duplicate records
            handle_missing: Handle missing data with advanced imputation
            remove_noise: Remove noise based on statistical thresholds

        Returns:
            Cleaned DataFrame
        """
        logger.info(f"Starting data cleaning for {len(df)} samples with {len(df.columns)} features")

        original_shape = df.shape

        # Use pandas copy-on-write optimization
        cleaned_df = df.copy(deep=False)

        # Cache column types for faster access
        self.categorical_columns = cleaned_df.select_dtypes(include=['object', 'category']).columns.tolist()
        self.numeric_columns = cleaned_df.select_dtypes(include=[np.number]).columns.tolist()

        # 1. Remove duplicates using pandas optimized method
        if remove_duplicates:
            duplicates_before = len(cleaned_df)
            # Use subset parameter for faster duplicate detection on key columns
            cleaned_df = cleaned_df.drop_duplicates(keep='first')
            duplicates_removed = duplicates_before - len(cleaned_df)
            self.duplicate_stats['removed'] = duplicates_removed
            logger.info(f"Removed {duplicates_removed} duplicate records")

        # 2. Handle missing data using pandas vectorized operations
        if handle_missing:
            cleaned_df = self._handle_missing_data_optimized(cleaned_df)

        # 3. Remove noise using pandas query and boolean indexing
        if remove_noise:
            cleaned_df = self._remove_noise_optimized(cleaned_df)

        logger_df = cleaned_df.copy(deep=True)
        logger.info(f"Data cleaning completed: {original_shape} -> {cleaned_df.shape}")
        return logger_df

    def _handle_missing_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing data using contextual filling strategies."""
        missing_stats = {}

        # Identify missing data patterns
        for column in df.columns:
            missing_count = df[column].isnull().sum()
            missing_ratio = missing_count / len(df)
            missing_stats[column] = {'count': missing_count, 'ratio': missing_ratio}

            # Different strategies based on missing ratio
            if missing_ratio > 0.5:
                # Too much missing data, consider dropping column
                logger.warning(f"Column {column} has {missing_ratio:.2%} missing data - consider dropping")
            elif missing_ratio > 0.1:
                # Use KNN imputation for contextual filling
                if df[column].dtype in ['int64', 'float64']:
                    df[column] = self.knn_imputer.fit_transform(df[[column]]).flatten()
                else:
                    # For categorical, use mode
                    df[column] = df[column].fillna(df[column].mode()[0] if not df[column].mode().empty else 'unknown')
            elif missing_ratio > 0:
                # Simple imputation for low missing ratios
                if df[column].dtype in ['int64', 'float64']:
                    df[column] = df[column].fillna(df[column].median())
                else:
                    df[column] = df[column].fillna(df[column].mode()[0] if not df[column].mode().empty else 'unknown')

        self.missing_data_stats = missing_stats
        return df

    def _handle_missing_data_optimized(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing data using optimized pandas operations."""
        # Use pandas isnull() which is faster than iterating
        missing_stats = df.isnull().sum()
        missing_ratios = missing_stats / len(df)

        # Batch process columns by missing ratio using pandas groupby-like logic
        high_missing_cols = missing_ratios[missing_ratios > 0.5].index.tolist()
        medium_missing_cols = missing_ratios[(missing_ratios > 0.1) & (missing_ratios <= 0.5)].index.tolist()
        low_missing_cols = missing_ratios[(missing_ratios > 0) & (missing_ratios <= 0.1)].index.tolist()

        if high_missing_cols:
            logger.warning(f"{len(high_missing_cols)} columns have >50% missing data")

        # Vectorized imputation for low missing columns
        for col in low_missing_cols:
            if col in self.numeric_columns:
                # Use pandas fillna with method parameter for speed
                df[col] = df[col].fillna(df[col].median())
            else:
                # Use pandas mode() which is optimized
                mode_val = df[col].mode()
                df[col] = df[col].fillna(mode_val[0] if len(mode_val) > 0 else 'unknown')

        # KNN imputation for medium missing (batch process)
        if medium_missing_cols:
            numeric_medium = [col for col in medium_missing_cols if col in self.numeric_columns]
            if numeric_medium:
                df[numeric_medium] = pd.DataFrame(
                    self.knn_imputer.fit_transform(df[numeric_medium]),
                    columns=numeric_medium,
                    index=df.index
                )

            categorical_medium = [col for col in medium_missing_cols if col in self.categorical_columns]
            for col in categorical_medium:
                mode_val = df[col].mode()
                df[col] = df[col].fillna(mode_val[0] if len(mode_val) > 0 else 'unknown')

        self.missing_data_stats = {
            'high_missing': high_missing_cols,
            'medium_missing': medium_missing_cols,
            'low_missing': low_missing_cols
        }

        return df

    def _remove_noise(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove noise based on statistical thresholds."""
        noise_removed = 0

        for column in df.select_dtypes(include=[np.number]).columns:
            # Use IQR method to identify outliers
            Q1 = df[column].quantile(0.25)
            Q3 = df[column].quantile(0.75)
            IQR = Q3 - Q1

            # Define outlier bounds (conservative approach)
            lower_bound = Q1 - 3 * IQR  # More conservative than 1.5
            upper_bound = Q3 + 3 * IQR

            # Count outliers
            outliers = ((df[column] < lower_bound) | (df[column] > upper_bound)).sum()

            # Only remove extreme outliers (>5% from bounds)
            extreme_outliers = ((df[column] < lower_bound - 0.05 * abs(lower_bound)) |
                              (df[column] > upper_bound + 0.05 * abs(upper_bound)))

            df = df[~extreme_outliers]
            noise_removed += extreme_outliers.sum()

        self.noise_stats = {'noise_records_removed': noise_removed}
        logger.info(f"Removed {noise_removed} noisy records")

        return df

    def _remove_noise_optimized(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove noise using optimized pandas vectorized operations."""
        # Use pandas quantile with interpolation for speed
        numeric_df = df[self.numeric_columns]

        # Vectorized IQR calculation across all columns at once
        Q1 = numeric_df.quantile(0.25)
        Q3 = numeric_df.quantile(0.75)
        IQR = Q3 - Q1

        # Vectorized outlier detection using pandas boolean indexing
        lower_bound = Q1 - 3 * IQR
        upper_bound = Q3 + 3 * IQR

        # Create boolean mask for all columns at once
        outlier_mask = ((numeric_df < lower_bound) | (numeric_df > upper_bound)).any(axis=1)

        # More conservative - only remove extreme outliers
        extreme_lower = lower_bound - 0.05 * lower_bound.abs()
        extreme_upper = upper_bound + 0.05 * upper_bound.abs()
        extreme_mask = ((numeric_df < extreme_lower) | (numeric_df > extreme_upper)).any(axis=1)

        # Use pandas boolean indexing for fast filtering
        noise_removed = extreme_mask.sum()
        df_cleaned = df[~extreme_mask].copy()

        self.noise_stats = {
            'noise_records_removed': noise_removed,
            'outliers_detected': outlier_mask.sum(),
            'extreme_outliers_removed': noise_removed
        }

        logger.info(f"Removed {noise_removed} noisy records using vectorized pandas operations")
        return df_cleaned

class FeatureEngineer:
    """Feature engineering component for advanced feature creation."""

    def __init__(self):
        self.feature_stats = {}
        self.temporal_features = []
        self.statistical_features = []

    def engineer_features(self, df: pd.DataFrame, target_column: Optional[str] = None) -> pd.DataFrame:
        """
        Engineer features as specified in Chapter 3.4.

        Creates:
        - Higher-level features (entropy statistics for payload)
        - Time-series aggregates (exponentially weighted moving averages)
        - Embeddings through autoencoders for dimensionality reduction
        """
        logger.info("Starting feature engineering")

        engineered_df = df.copy()

        # 1. Derive higher-level features
        engineered_df = self._create_entropy_features(engineered_df)
        engineered_df = self._create_statistical_aggregates(engineered_df)

        # 2. Time-series features (if timestamp available)
        if 'timestamp' in engineered_df.columns or any('time' in col.lower() for col in engineered_df.columns):
            engineered_df = self._create_temporal_features(engineered_df)

        # 3. Network-specific features
        engineered_df = self._create_network_features(engineered_df)

        # 4. Interaction features
        engineered_df = self._create_interaction_features(engineered_df)

        logger.info(f"Feature engineering completed: {len(df.columns)} -> {len(engineered_df.columns)} features")
        return engineered_df

    def _create_entropy_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create entropy statistics for payload feature exploration."""
        # Simulate payload entropy calculation
        for column in df.select_dtypes(include=[np.number]).columns:
            if 'payload' in column.lower() or 'bytes' in column.lower():
                # Calculate Shannon entropy
                df[f'{column}_entropy'] = df[column].apply(self._calculate_shannon_entropy)

                # Calculate byte frequency entropy
                df[f'{column}_byte_entropy'] = df[column].apply(self._calculate_byte_entropy)

        return df

    def _create_statistical_aggregates(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create statistical aggregates and EWMA features."""
        numeric_columns = df.select_dtypes(include=[np.number]).columns

        for column in numeric_columns:
            # Rolling statistics (simulated time-series)
            df[f'{column}_rolling_mean_5'] = df[column].rolling(window=5, min_periods=1).mean()
            df[f'{column}_rolling_std_5'] = df[column].rolling(window=5, min_periods=1).std().fillna(0)

            # Exponentially weighted moving averages
            df[f'{column}_ewm_alpha_02'] = df[column].ewm(alpha=0.2).mean()

            # Statistical features
            df[f'{column}_zscore'] = (df[column] - df[column].mean()) / (df[column].std() + 1e-8)

        return df

    def _create_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create temporal features from timestamp data."""
        # Find timestamp columns
        timestamp_cols = [col for col in df.columns if 'time' in col.lower() or 'date' in col.lower()]

        for col in timestamp_cols:
            try:
                # Convert to datetime if not already
                if not pd.api.types.is_datetime64_any_dtype(df[col]):
                    df[col] = pd.to_datetime(df[col], errors='coerce')

                # Extract temporal features
                df[f'{col}_hour'] = df[col].dt.hour
                df[f'{col}_day_of_week'] = df[col].dt.dayofweek
                df[f'{col}_month'] = df[col].dt.month
                df[f'{col}_is_weekend'] = (df[col].dt.dayofweek >= 5).astype(int)

                # Time-based aggregations
                df[f'{col}_hour_sin'] = np.sin(2 * np.pi * df[col].dt.hour / 24)
                df[f'{col}_hour_cos'] = np.cos(2 * np.pi * df[col].dt.hour / 24)

            except Exception as e:
                logger.warning(f"Failed to process timestamp column {col}: {e}")

        return df

    def _create_network_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create network-specific features."""
        # Port-based features
        port_columns = [col for col in df.columns if 'port' in col.lower()]
        for col in port_columns:
            if col in df.columns:
                # Well-known ports
                df[f'{col}_is_well_known'] = (df[col] < 1024).astype(int)
                # Dynamic ports
                df[f'{col}_is_dynamic'] = (df[col] > 49152).astype(int)

        # Packet size features
        size_columns = [col for col in df.columns if any(x in col.lower() for x in ['size', 'length', 'bytes'])]
        for col in size_columns:
            if col in df.columns:
                # Log transform for skewed distributions
                df[f'{col}_log'] = np.log1p(df[col])

        # Protocol features
        protocol_columns = [col for col in df.columns if 'protocol' in col.lower()]
        for col in protocol_columns:
            if col in df.columns and df[col].dtype == 'object':
                # One-hot encode protocols
                protocol_dummies = pd.get_dummies(df[col], prefix=f'{col}_is')
                df = pd.concat([df, protocol_dummies], axis=1)

        return df

    def _create_interaction_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create interaction features between important variables."""
        numeric_columns = df.select_dtypes(include=[np.number]).columns[:10]  # Limit to avoid explosion

        # Create polynomial features for top numeric columns
        for i, col1 in enumerate(numeric_columns):
            for col2 in numeric_columns[i+1:i+3]:  # Limit interactions
                if col1 != col2:
                    # Multiplication interaction
                    df[f'{col1}_x_{col2}'] = df[col1] * df[col2]

                    # Ratio interaction (avoid division by zero)
                    df[f'{col1}_div_{col2}'] = df[col1] / (df[col2] + 1e-8)

        return df

    def _calculate_shannon_entropy(self, data: Union[int, float, str]) -> float:
        """Calculate Shannon entropy for data."""
        if pd.isna(data):
            return 0.0

        # Convert to string representation for byte analysis
        data_str = str(data)
        if not data_str:
            return 0.0

        # Calculate entropy
        byte_counts = {}
        for char in data_str:
            byte_counts[char] = byte_counts.get(char, 0) + 1

        entropy = 0.0
        total_chars = len(data_str)

        for count in byte_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * np.log2(probability)

        return entropy

    def _calculate_byte_entropy(self, data: Union[int, float]) -> float:
        """Calculate byte-level entropy."""
        if pd.isna(data):
            return 0.0

        # Convert number to bytes representation
        try:
            if isinstance(data, (int, float)):
                # Convert to bytes (simulate network packet bytes)
                byte_data = data.to_bytes(8, byteorder='big', signed=False)
            else:
                byte_data = str(data).encode()

            # Calculate entropy of byte values
            byte_counts = {}
            for byte_val in byte_data:
                byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1

            entropy = 0.0
            total_bytes = len(byte_data)

            for count in byte_counts.values():
                probability = count / total_bytes
                if probability > 0:
                    entropy -= probability * np.log2(probability)

            return entropy

        except Exception:
            return 0.0

class DataNormalizer:
    """Data normalization component with multiple scaling strategies."""

    def __init__(self, strategy: str = 'standard'):
        self.strategy = strategy
        self.scaler = None
        self.is_fitted = False
        self._initialize_scaler()

    def _initialize_scaler(self):
        """Initialize scaler based on strategy."""
        if self.strategy == 'standard':
            self.scaler = StandardScaler()
        elif self.strategy == 'robust':
            self.scaler = RobustScaler()
        else:
            raise ValueError(f"Unknown scaling strategy: {self.strategy}")

    def normalize_features(self, df: pd.DataFrame, feature_columns: List[str] = None) -> pd.DataFrame:
        """
        Apply normalization using StandardScaler or RobustScaler.
        Features like byte counts are normalized to obtain scale invariance for DL inputs.
        """
        if feature_columns is None:
            feature_columns = df.select_dtypes(include=[np.number]).columns.tolist()

        normalized_df = df.copy()

        # Apply scaling to numerical features
        if feature_columns:
            if not self.is_fitted:
                normalized_df[feature_columns] = self.scaler.fit_transform(df[feature_columns])
                self.is_fitted = True
                logger.info(f"Fitted {self.strategy} scaler on {len(feature_columns)} features")
            else:
                normalized_df[feature_columns] = self.scaler.transform(df[feature_columns])

        return normalized_df

    def inverse_transform(self, df: pd.DataFrame, feature_columns: List[str] = None) -> pd.DataFrame:
        """Inverse transform normalized features."""
        if not self.is_fitted:
            raise ValueError("Scaler not fitted. Call normalize_features first.")

        if feature_columns is None:
            feature_columns = df.select_dtypes(include=[np.number]).columns.tolist()

        inverse_df = df.copy()
        if feature_columns:
            inverse_df[feature_columns] = self.scaler.inverse_transform(df[feature_columns])

        return inverse_df

class DataBalancer:
    """Data balancing component using ADASYN and SMOTE."""

    def __init__(self, strategy: str = 'adasyn'):
        self.strategy = strategy
        self.balancer = None
        self._initialize_balancer()

    def _initialize_balancer(self):
        """Initialize balancing strategy."""
        if self.strategy == 'adasyn':
            self.balancer = ADASYN(random_state=42, n_neighbors=5)
        elif self.strategy == 'smote':
            self.balancer = SMOTE(random_state=42, k_neighbors=5)
        elif self.strategy == 'smote_variants':
            # Using advanced SMOTE variants for network intrusion detection
            from imblearn.over_sampling import BorderlineSMOTE
            self.balancer = BorderlineSMOTE(random_state=42, k_neighbors=5)
        else:
            raise ValueError(f"Unknown balancing strategy: {self.strategy}")

    def balance_data(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Balance data using ADASYN for adaptive oversampling of minority classes.
        Addresses software pipeline imbalance as specified in Chapter 3.4.
        """
        original_distribution = np.bincount(y)
        logger.info(f"Original class distribution: {original_distribution}")

        # Apply balancing
        X_balanced, y_balanced = self.balancer.fit_resample(X, y)

        balanced_distribution = np.bincount(y_balanced)
        logger.info(f"Balanced class distribution: {balanced_distribution}")
        logger.info(f"Data balancing: {X.shape} -> {X_balanced.shape}")

        return X_balanced, y_balanced

class PrivacyPreserver:
    """Privacy-preserving techniques using differential privacy."""

    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        self.epsilon = epsilon  # Privacy budget
        self.delta = delta      # Failure probability
        self.privacy_engine = None

    def add_differential_privacy_noise(self, data: np.ndarray, sensitivity: float = 1.0) -> np.ndarray:
        """
        Add differential privacy noise using Laplace mechanism.
        Uses differential privacy noise addition via libraries like Opacus in PyTorch.
        """
        # Laplace noise for differential privacy
        scale = sensitivity / self.epsilon
        noise = np.random.laplace(0, scale, data.shape)

        private_data = data + noise

        logger.info(f"Added differential privacy noise with ε={self.epsilon}, δ={self.delta}")
        return private_data

    def setup_private_training(self, model: torch.nn.Module, optimizer: torch.optim.Optimizer,
                             noise_multiplier: float = 1.0, max_grad_norm: float = 1.0) -> PrivacyEngine:
        """Setup private training using Opacus."""
        try:
            from opacus import PrivacyEngine

            privacy_engine = PrivacyEngine()

            model, optimizer, data_loader = privacy_engine.make_private(
                module=model,
                optimizer=optimizer,
                data_loader=None,  # Will be set later
                noise_multiplier=noise_multiplier,
                max_grad_norm=max_grad_norm,
            )

            self.privacy_engine = privacy_engine
            logger.info(f"Setup differential privacy training with noise_multiplier={noise_multiplier}")

            return privacy_engine

        except ImportError:
            logger.warning("Opacus not available for differential privacy")
            return None

class DatasetProcessor:
    """Main dataset processor implementing Chapter 3.4 preprocessing pipeline."""

    def __init__(self, privacy_epsilon: float = 1.0):
        self.cleaner = DataCleaner()
        self.feature_engineer = FeatureEngineer()
        self.normalizer = DataNormalizer(strategy='standard')
        self.balancer = DataBalancer(strategy='adasyn')
        self.privacy_preserver = PrivacyPreserver(epsilon=privacy_epsilon)

        # Dataset configurations
        self.dataset_configs = {
            'unsw_nb15': {
                'features': 49,
                'attack_categories': 9,
                'target_column': 'attack_cat',
                'normal_ratio': 0.87
            },
            'cic_ids2018': {
                'features': 80,
                'attack_categories': 16,
                'target_column': 'Label',
                'normal_ratio': 0.81
            }
        }

    def process_dataset(self, df: pd.DataFrame, dataset_name: str = 'custom',
                       target_column: Optional[str] = None,
                       test_size: float = 0.2, validation_size: float = 0.1,
                       apply_privacy: bool = False) -> Dict[str, Any]:
        """
        Complete preprocessing pipeline as specified in Chapter 3.4.

        Process:
        1. Cleaning: Remove duplicates, handle missing data, remove noise
        2. Normalization: Apply StandardScaler/RobustScaler for DL inputs
        3. Feature Engineering: Derive higher-level features, time-series aggregates
        4. Splitting and Balancing: Stratified split with ADASYN
        5. Privacy-Preserving: Differential privacy noise addition
        """
        logger.info(f"Starting complete preprocessing pipeline for {dataset_name}")
        logger.info(f"Initial dataset shape: {df.shape}")

        processing_stats = {
            'dataset_name': dataset_name,
            'initial_shape': df.shape,
            'processing_steps': []
        }

        # Step 1: Data Cleaning
        logger.info("Step 1: Data Cleaning")
        cleaned_df = self.cleaner.clean_data(df)
        processing_stats['processing_steps'].append({
            'step': 'cleaning',
            'shape_after': cleaned_df.shape,
            'duplicates_removed': self.cleaner.duplicate_stats.get('removed', 0),
            'missing_stats': self.cleaner.missing_data_stats,
            'noise_stats': self.cleaner.noise_stats
        })

        # Step 2: Feature Engineering
        logger.info("Step 2: Feature Engineering")
        engineered_df = self.feature_engineer.engineer_features(cleaned_df, target_column)
        processing_stats['processing_steps'].append({
            'step': 'feature_engineering',
            'shape_after': engineered_df.shape,
            'features_added': len(engineered_df.columns) - len(cleaned_df.columns)
        })

        # Step 3: Prepare features and target
        if target_column and target_column in engineered_df.columns:
            X = engineered_df.drop(columns=[target_column])
            y = engineered_df[target_column]

            # Encode categorical target if necessary
            if y.dtype == 'object':
                label_encoder = LabelEncoder()
                y = label_encoder.fit_transform(y)
                processing_stats['label_encoder'] = label_encoder
        else:
            X = engineered_df
            y = None

        # Step 4: Normalization
        logger.info("Step 3: Normalization")
        normalized_X = self.normalizer.normalize_features(X)
        processing_stats['processing_steps'].append({
            'step': 'normalization',
            'strategy': self.normalizer.strategy,
            'features_normalized': len(X.select_dtypes(include=[np.number]).columns)
        })

        # Step 5: Train-Validation-Test Split (Stratified)
        logger.info("Step 4: Train-Validation-Test Split")
        if y is not None:
            # First split: train+val vs test
            X_temp, X_test, y_temp, y_test = train_test_split(
                normalized_X, y, test_size=test_size, random_state=42,
                stratify=y if len(np.unique(y)) > 1 else None
            )

            # Second split: train vs val
            val_size_adjusted = validation_size / (1 - test_size)
            X_train, X_val, y_train, y_val = train_test_split(
                X_temp, y_temp, test_size=val_size_adjusted, random_state=42,
                stratify=y_temp if len(np.unique(y_temp)) > 1 else None
            )
        else:
            # No target, just split features
            train_size = 1 - test_size - validation_size
            X_train, X_temp = train_test_split(normalized_X, test_size=test_size+validation_size, random_state=42)
            val_size_adjusted = validation_size / (test_size + validation_size)
            X_val, X_test = train_test_split(X_temp, test_size=val_size_adjusted, random_state=42)
            y_train = y_val = y_test = None

        processing_stats['processing_steps'].append({
            'step': 'splitting',
            'train_size': X_train.shape[0],
            'val_size': X_val.shape[0],
            'test_size': X_test.shape[0],
            'split_ratios': f"train: {1-test_size-validation_size:.1f}, val: {validation_size:.1f}, test: {test_size:.1f}"
        })

        # Step 6: Data Balancing (only on training set)
        if y_train is not None and len(np.unique(y_train)) > 1:
            logger.info("Step 5: Data Balancing")
            X_train_balanced, y_train_balanced = self.balancer.balance_data(
                X_train.values, y_train
            )
            X_train = pd.DataFrame(X_train_balanced, columns=X_train.columns)
            y_train = y_train_balanced

            processing_stats['processing_steps'].append({
                'step': 'balancing',
                'strategy': self.balancer.strategy,
                'train_size_after_balancing': X_train.shape[0],
                'class_distribution': np.bincount(y_train).tolist()
            })

        # Step 7: Privacy-Preserving Techniques (if requested)
        if apply_privacy:
            logger.info("Step 6: Privacy-Preserving Techniques")
            X_train_private = self.privacy_preserver.add_differential_privacy_noise(
                X_train.values
            )
            X_train = pd.DataFrame(X_train_private, columns=X_train.columns)

            processing_stats['processing_steps'].append({
                'step': 'privacy_preservation',
                'epsilon': self.privacy_preserver.epsilon,
                'delta': self.privacy_preserver.delta
            })

        # Final statistics
        processing_stats['final_shapes'] = {
            'X_train': X_train.shape,
            'X_val': X_val.shape,
            'X_test': X_test.shape,
            'y_train': y_train.shape if y_train is not None else None,
            'y_val': y_val.shape if y_val is not None else None,
            'y_test': y_test.shape if y_test is not None else None
        }

        logger.info("Preprocessing pipeline completed successfully")
        logger.info(f"Final shapes - Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")

        return {
            'X_train': X_train,
            'X_val': X_val,
            'X_test': X_test,
            'y_train': y_train,
            'y_val': y_val,
            'y_test': y_test,
            'processing_stats': processing_stats,
            'feature_columns': X_train.columns.tolist(),
            'preprocessors': {
                'cleaner': self.cleaner,
                'feature_engineer': self.feature_engineer,
                'normalizer': self.normalizer,
                'balancer': self.balancer,
                'privacy_preserver': self.privacy_preserver
            }
        }

    def load_unsw_nb15(self, data_path: str) -> pd.DataFrame:
        """Load and prepare UNSW-NB15 dataset."""
        logger.info(f"Loading UNSW-NB15 dataset from {data_path}")

        try:
            # Load dataset (assuming CSV format)
            df = pd.read_csv(data_path)

            # UNSW-NB15 specific preprocessing
            if 'attack_cat' in df.columns:
                # Map attack categories
                attack_mapping = {
                    'Normal': 0, 'Generic': 1, 'Exploits': 2, 'Fuzzers': 3,
                    'DoS': 4, 'Reconnaissance': 5, 'Analysis': 6,
                    'Backdoor': 7, 'Shellcode': 8, 'Worms': 9
                }
                df['attack_cat'] = df['attack_cat'].map(attack_mapping).fillna(0)

            logger.info(f"Loaded UNSW-NB15: {df.shape}")
            return df

        except Exception as e:
            logger.error(f"Failed to load UNSW-NB15: {e}")
            # Return synthetic data for demonstration
            return self._generate_synthetic_unsw_nb15(2500)

    def load_cic_ids2018(self, data_path: str) -> pd.DataFrame:
        """Load and prepare CIC-IDS2018 dataset."""
        logger.info(f"Loading CIC-IDS2018 dataset from {data_path}")

        try:
            df = pd.read_csv(data_path)

            # CIC-IDS2018 specific preprocessing
            if 'Label' in df.columns:
                # Encode labels
                label_encoder = LabelEncoder()
                df['Label'] = label_encoder.fit_transform(df['Label'])

            logger.info(f"Loaded CIC-IDS2018: {df.shape}")
            return df

        except Exception as e:
            logger.error(f"Failed to load CIC-IDS2018: {e}")
            # Return synthetic data for demonstration
            return self._generate_synthetic_cic_ids2018(16000)

    def _generate_synthetic_unsw_nb15(self, n_samples: int = 2500) -> pd.DataFrame:
        """Generate synthetic UNSW-NB15-like dataset for demonstration."""
        logger.info(f"Generating synthetic UNSW-NB15 dataset with {n_samples} samples")

        np.random.seed(42)

        # Generate 49 features as per UNSW-NB15
        features = {}
        feature_names = [
            'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
            'rate', 'sttl', 'dttl', 'sloss', 'dloss', 'service_code', 'sload', 'dload',
            'slength', 'dlength', 'sintpkt', 'dintpkt', 'sjit', 'djit', 'swin', 'dwin',
            'stcpb', 'dtcpb', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports',
            'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
            'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
            'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'response_body_len', 'ct_srv_dst_2',
            'ct_state_ttl_2', 'ct_flw_http_mthd_2', 'ct_state_ttl_3', 'response_body_len_2',
            'ct_srv_dst_3', 'attack_cat'
        ]

        for i, name in enumerate(feature_names[:-1]):  # Exclude target
            if name in ['proto', 'service', 'state']:
                # Categorical features
                features[name] = np.random.randint(0, 10, n_samples)
            elif 'is_' in name:
                # Binary features
                features[name] = np.random.binomial(1, 0.3, n_samples)
            else:
                # Continuous features
                features[name] = np.random.exponential(scale=2.0, size=n_samples)

        # Target variable (attack categories)
        features['attack_cat'] = np.random.choice(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            size=n_samples,
            p=[0.87, 0.02, 0.03, 0.02, 0.02, 0.01, 0.01, 0.01, 0.005, 0.005]  # Normal-heavy
        )

        return pd.DataFrame(features)

    def _generate_synthetic_cic_ids2018(self, n_samples: int = 16000) -> pd.DataFrame:
        """Generate synthetic CIC-IDS2018-like dataset for demonstration."""
        logger.info(f"Generating synthetic CIC-IDS2018 dataset with {n_samples} samples")

        np.random.seed(42)

        # Generate 80 features as per CIC-IDS2018
        features = {}

        # Network flow features
        flow_features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s'
        ]

        # Generate features
        for i, name in enumerate(flow_features):
            if 'Duration' in name:
                features[name] = np.random.exponential(scale=100000, size=n_samples)
            elif 'Packets' in name and '/s' not in name:
                features[name] = np.random.poisson(lam=50, size=n_samples)
            elif 'Length' in name:
                features[name] = np.random.gamma(shape=2, scale=500, size=n_samples)
            elif '/s' in name:
                features[name] = np.random.exponential(scale=1000, size=n_samples)
            else:
                features[name] = np.random.normal(loc=1000, scale=500, size=n_samples)

        # Generate additional features to reach 80
        for i in range(len(flow_features), 79):
            features[f'Feature_{i}'] = np.random.normal(loc=0, scale=1, size=n_samples)

        # Target variable
        features['Label'] = np.random.choice(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            size=n_samples,
            p=[0.81] + [0.012] * 15 + [0.007]  # Normal-heavy with 16 classes
        )

        return pd.DataFrame(features)

    def save_processed_data(self, processed_data: Dict[str, Any], output_dir: str):
        """Save processed data and preprocessing components."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save datasets
        processed_data['X_train'].to_csv(output_path / 'X_train.csv', index=False)
        processed_data['X_val'].to_csv(output_path / 'X_val.csv', index=False)
        processed_data['X_test'].to_csv(output_path / 'X_test.csv', index=False)

        if processed_data['y_train'] is not None:
            np.save(output_path / 'y_train.npy', processed_data['y_train'])
            np.save(output_path / 'y_val.npy', processed_data['y_val'])
            np.save(output_path / 'y_test.npy', processed_data['y_test'])

        # Save preprocessors
        joblib.dump(processed_data['preprocessors'], output_path / 'preprocessors.pkl')

        # Save processing statistics
        with open(output_path / 'processing_stats.json', 'w') as f:
            json.dump(processed_data['processing_stats'], f, indent=2, default=str)

        logger.info(f"Processed data saved to {output_dir}")

# Global dataset processor instance
_dataset_processor = None

def get_dataset_processor() -> DatasetProcessor:
    """Get global dataset processor instance."""
    global _dataset_processor
    if _dataset_processor is None:
        _dataset_processor = DatasetProcessor()
    return _dataset_processor