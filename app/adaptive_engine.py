import logging
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
import numpy as np
from marshmallow import ValidationError
from .utils import log_activity, require_auth, require_admin_auth, RiskAssessmentSchema, ThreatUpdateSchema, sanitize_input

adaptive_blueprint = Blueprint('adaptive', __name__)
logger = logging.getLogger(__name__)

class AdaptiveEngine:
    def __init__(self):
        # Initialize with more robust anomaly detection
        self.anomaly_detector = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=100
        )
        
        # Train on initial normal behavior patterns
        self._train_initial_model()
        
        self.security_rules = {
            'password_complexity': 12,  # Increased from 8
            'max_failed_attempts': 3,
            'session_timeout': 30,  # minutes
            'mfa_required': True,
            'ip_whitelist': set(),
            'suspicious_patterns': set(['multiple_failed_logins', 'unusual_time_access', 'rapid_requests']),
            'rate_limit_threshold': 100,  # requests per hour
            'geo_location_check': True,
            'device_fingerprint_check': True
        }
        self.threat_scores = {}
        self.last_update = datetime.now()
        self.threat_history = []
        
    def _train_initial_model(self):
        """Train the anomaly detection model with initial normal patterns."""
        # Generate synthetic normal behavior patterns
        normal_patterns = []
        for _ in range(1000):
            # Normal working hours (9 AM to 6 PM represented as 0.375 to 0.75)
            time_of_day = np.random.uniform(0.375, 0.75)
            # Few failed attempts (0-1)
            failed_attempts = np.random.choice([0, 1], p=[0.9, 0.1])
            # Rare location changes
            location_change = np.random.choice([0, 1], p=[0.95, 0.05])
            # Rare device changes
            device_change = np.random.choice([0, 1], p=[0.98, 0.02])
            
            normal_patterns.append([time_of_day, failed_attempts, location_change, device_change])
        
        self.anomaly_detector.fit(normal_patterns)
        logger.info("Adaptive engine initialized with trained anomaly detection model")

    def update_security_rules(self, new_threats):
        """Update security rules based on new threat data with validation."""
        try:
            updates_made = []
            
            if new_threats.get('failed_login_patterns'):
                old_attempts = self.security_rules['max_failed_attempts']
                self.security_rules['max_failed_attempts'] = min(old_attempts + 1, 5)
                updates_made.append(f"Max failed attempts: {old_attempts} -> {self.security_rules['max_failed_attempts']}")
            
            if new_threats.get('password_attacks'):
                old_complexity = self.security_rules['password_complexity']
                self.security_rules['password_complexity'] = min(old_complexity + 2, 16)
                updates_made.append(f"Password complexity: {old_complexity} -> {self.security_rules['password_complexity']}")
            
            if new_threats.get('rate_limit_exceeded'):
                old_limit = self.security_rules['rate_limit_threshold']
                self.security_rules['rate_limit_threshold'] = max(old_limit - 10, 20)
                updates_made.append(f"Rate limit: {old_limit} -> {self.security_rules['rate_limit_threshold']}")

            # Add new suspicious patterns (sanitized)
            if new_threats.get('new_patterns'):
                new_patterns = set()
                for pattern in new_threats['new_patterns']:
                    sanitized_pattern = sanitize_input(str(pattern), max_length=50)
                    if sanitized_pattern:
                        new_patterns.add(sanitized_pattern)
                
                if new_patterns:
                    self.security_rules['suspicious_patterns'].update(new_patterns)
                    updates_made.append(f"Added patterns: {list(new_patterns)}")
            
            self.last_update = datetime.now()
            self.threat_history.append({
                'timestamp': self.last_update,
                'threats': new_threats,
                'updates': updates_made
            })
            
            # Keep only last 100 threat history entries
            if len(self.threat_history) > 100:
                self.threat_history = self.threat_history[-100:]
            
            logger.info(f"Security rules updated: {updates_made}")
            return updates_made
            
        except Exception as e:
            logger.error(f"Failed to update security rules: {str(e)}")
            return []

    def calculate_risk_score(self, user_id, context):
        """Calculate risk score with enhanced validation and feature engineering."""
        try:
            # Sanitize user_id
            user_id = sanitize_input(str(user_id), max_length=50)
            
            # Extract and validate features
            features = [
                max(0, min(1, context.get('time_of_day', 0.5))),  # Normalize to 0-1
                max(0, min(10, context.get('failed_attempts', 0))),  # Cap at 10
                1 if context.get('location_change', False) else 0,
                1 if context.get('device_change', False) else 0,
                max(0, min(1, context.get('unusual_activity', 0))),  # Additional feature
                max(0, min(100, context.get('request_frequency', 1))) / 100.0  # Normalize request frequency
            ]
            
            # Pad or truncate features to ensure consistent shape
            while len(features) < 6:
                features.append(0)
            features = features[:6]
            
            # Reshape for sklearn
            X = np.array(features).reshape(1, -1)
            
            # Get anomaly score (-1 for anomalies, 1 for normal behavior)
            anomaly_score = self.anomaly_detector.predict(X)[0]
            
            # Get anomaly score (lower values indicate more anomalous)
            decision_score = self.anomaly_detector.decision_function(X)[0]
            
            # Convert to risk score (0-1 scale where 1 is highest risk)
            if anomaly_score == -1:  # Anomalous
                normalized_score = min(0.9, 0.7 + abs(decision_score) * 0.2)
            else:  # Normal
                normalized_score = max(0.1, 0.3 - abs(decision_score) * 0.2)
            
            # Additional risk factors
            if context.get('failed_attempts', 0) > 3:
                normalized_score = min(0.95, normalized_score + 0.2)
            
            if context.get('location_change') and context.get('device_change'):
                normalized_score = min(0.95, normalized_score + 0.15)
            
            # Store the score
            self.threat_scores[user_id] = {
                'score': normalized_score,
                'timestamp': datetime.now(),
                'features': features,
                'context': context
            }
            
            return round(normalized_score, 2)
            
        except Exception as e:
            logger.error(f"Failed to calculate risk score: {str(e)}")
            return 0.5  # Return moderate risk on error

    def get_required_factors(self, risk_score):
        """Determine required authentication factors based on risk score."""
        if risk_score >= 0.8:
            return ['password', 'totp', 'biometric', 'location_verification']
        elif risk_score >= 0.6:
            return ['password', 'totp', 'device_verification']
        elif risk_score >= 0.4:
            return ['password', 'totp']
        return ['password']

# Initialize the adaptive engine
engine = AdaptiveEngine()

@adaptive_blueprint.route('/evolve', methods=['POST'])
@require_admin_auth
def evolve():
    """Update the adaptive engine with new threat intelligence."""
    try:
        # Validate request
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        schema = ThreatUpdateSchema()
        data = schema.load(request.json)
        
        current_user = get_jwt_identity()
        new_threats = data['threats']
        
        # Update security rules
        updates_made = engine.update_security_rules(new_threats)
        
        # Log the update
        log_activity('adaptive_update', current_user, {
            'new_threats': new_threats,
            'updates_made': updates_made,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'message': 'Adaptive engine updated successfully',
            'updates_made': updates_made,
            'current_rules': {k: v if not isinstance(v, set) else list(v) for k, v in engine.security_rules.items()},
            'last_update': engine.last_update.isoformat()
        }), 200
        
    except ValidationError as e:
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        logger.error(f"Adaptive engine update error: {str(e)}")
        return jsonify({'error': 'Failed to update adaptive engine'}), 500

@adaptive_blueprint.route('/risk-assessment', methods=['POST'])
@require_auth
def assess_risk():
    """Assess risk for a given user and context."""
    try:
        # Validate request
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        schema = RiskAssessmentSchema()
        data = schema.load(request.json)
        
        current_user = get_jwt_identity()
        target_user_id = data['user_id']
        context = data['context']
        
        # Users can only assess their own risk unless they're admin
        admin_users = ['admin', 'security_admin', 'system']
        if current_user != target_user_id and current_user not in admin_users:
            return jsonify({'error': 'Insufficient permissions to assess other users'}), 403
        
        risk_score = engine.calculate_risk_score(target_user_id, context)
        required_factors = engine.get_required_factors(risk_score)
        
        # Log the assessment
        log_activity('risk_assessment', current_user, {
            'target_user': target_user_id,
            'risk_score': risk_score,
            'required_factors': required_factors
        })
        
        return jsonify({
            'user_id': target_user_id,
            'risk_score': risk_score,
            'risk_level': 'high' if risk_score >= 0.7 else 'medium' if risk_score >= 0.4 else 'low',
            'required_factors': required_factors,
            'timestamp': datetime.now().isoformat(),
            'assessed_by': current_user
        }), 200
        
    except ValidationError as e:
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        logger.error(f"Risk assessment error: {str(e)}")
        return jsonify({'error': 'Failed to perform risk assessment'}), 500

@adaptive_blueprint.route('/rules', methods=['GET'])
@require_auth
def get_security_rules():
    """Get current security rules."""
    try:
        current_user = get_jwt_identity()
        
        # Convert sets to lists for JSON serialization
        rules = {k: v if not isinstance(v, set) else list(v) for k, v in engine.security_rules.items()}
        
        return jsonify({
            'security_rules': rules,
            'last_update': engine.last_update.isoformat(),
            'requested_by': current_user
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to retrieve security rules: {str(e)}")
        return jsonify({'error': 'Failed to retrieve security rules'}), 500

@adaptive_blueprint.route('/threat-history', methods=['GET'])
@require_admin_auth
def get_threat_history():
    """Get threat update history (admin only)."""
    try:
        current_user = get_jwt_identity()
        
        # Format threat history for JSON response
        history = []
        for entry in engine.threat_history[-20:]:  # Last 20 entries
            history.append({
                'timestamp': entry['timestamp'].isoformat(),
                'threats': entry['threats'],
                'updates': entry['updates']
            })
        
        return jsonify({
            'threat_history': history,
            'total_entries': len(engine.threat_history),
            'requested_by': current_user
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to retrieve threat history: {str(e)}")
        return jsonify({'error': 'Failed to retrieve threat history'}), 500
