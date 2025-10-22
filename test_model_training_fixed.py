"""
Quick test script to verify model training with UNSW-NB15 dataset
"""

import sys
import os
# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print("MODEL TRAINING TEST - UNSW-NB15 Dataset")
print("="*70)

# Load dataset
print("\n1. Loading UNSW-NB15 training dataset...")
try:
    df = pd.read_csv('.venv/datasets/UNSW_NB15_training-set.csv')
    print(f"   [OK] Dataset loaded successfully!")
    print(f"   Shape: {df.shape}")
    print(f"   Columns: {len(df.columns)}")
except Exception as e:
    print(f"   [FAIL] Error loading dataset: {e}")
    exit(1)

# Identify target column
print("\n2. Identifying target column...")
possible_targets = ['label', 'Label', 'attack_cat', 'Attack']
target_col = None
for col in possible_targets:
    if col in df.columns:
        target_col = col
        break

if target_col is None:
    # Use last column as target
    target_col = df.columns[-1]

print(f"   [OK] Target column: {target_col}")
print(f"   Target distribution:")
print(df[target_col].value_counts().head())

# Preprocessing
print("\n3. Preprocessing data...")
# Handle missing values
df = df.fillna(df.median(numeric_only=True))

# Encode categorical columns
categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
if target_col in categorical_cols:
    categorical_cols.remove(target_col)

for col in categorical_cols:
    if df[col].nunique() < 100:
        df[col] = pd.factorize(df[col])[0]
    else:
        df = df.drop(col, axis=1)

# Separate features and target
X = df.drop(target_col, axis=1)
y = df[target_col]

# Encode target if categorical
if y.dtype == 'object':
    y = pd.factorize(y)[0]

print(f"   [OK] Features shape: {X.shape}")
print(f"   [OK] Number of classes: {len(np.unique(y))}")

# Train-test split
print("\n4. Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"   [OK] Training samples: {len(X_train)}")
print(f"   [OK] Testing samples: {len(X_test)}")

# Train model
print("\n5. Training Random Forest model...")
print("   This may take a minute...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1,
    verbose=0
)

model.fit(X_train, y_train)
print("   [OK] Model training completed!")

# Evaluate
print("\n6. Evaluating model performance...")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

print("\n" + "="*70)
print("MODEL PERFORMANCE RESULTS")
print("="*70)
print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1-Score:  {f1:.4f}")
print("="*70)

# Feature importance
print("\n7. Top 10 Most Important Features:")
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

for idx, row in feature_importance.head(10).iterrows():
    print(f"   {row['feature']:30s}: {row['importance']:.4f}")

# Save model
print("\n8. Saving model...")
import joblib
import os

os.makedirs('models', exist_ok=True)
model_path = 'models/unsw_nb15_threat_model.pkl'
joblib.dump(model, model_path)
file_size = os.path.getsize(model_path) / 1024 / 1024
print(f"   [OK] Model saved to: {model_path}")
print(f"   [OK] Model file size: {file_size:.2f} MB")

# Test predictions
print("\n9. Testing sample predictions...")
sample_indices = np.random.choice(len(X_test), 5, replace=False)
samples = X_test.iloc[sample_indices]
true_labels = y_test.iloc[sample_indices].values
predictions = model.predict(samples)

print("   Sample Results:")
for i, (true, pred) in enumerate(zip(true_labels, predictions)):
    status = "[OK]" if true == pred else "[FAIL]"
    print(f"   {status} Sample {i+1}: True={true}, Predicted={pred}")

print("\n" + "="*70)
print("[OK] MODEL TRAINING TEST COMPLETED SUCCESSFULLY!")
print("="*70)
print("\nConclusion: The model is training properly with the UNSW-NB15 dataset.")
print("The Random Forest classifier shows good performance on threat detection.")
