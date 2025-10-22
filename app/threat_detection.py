import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from marshmallow import Schema, fields, ValidationError
from .ml_threat_detector import get_threat_detector
from .advanced_adaptive_engine import get_advanced_adaptive_engine
from .utils import log_activity

threat_blueprint = Blueprint('threat', __name__)
logger = logging.getLogger(__name__)

class ThreatDetectionSchema(Schema):
    """Schema for threat detection requests."""
    data = fields.Dict(required=True)
    feedback = fields.Bool(required=False, load_default=False)
    actual_threat = fields.Bool(required=False)
    threat_type = fields.Str(required=False)

class FeatureDetectionSchema(Schema):
    """Legacy schema for feature-based detection."""
    features = fields.List(fields.Float(), required=True, validate=lambda x: len(x) > 0)

@threat_blueprint.route('/detect', methods=['POST'])
@jwt_required()
def detect():
    """Advanced threat detection using custom ML model."""
    try:
        current_user = get_jwt_identity()
        
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        # Try new data-based detection first
        try:
            schema = ThreatDetectionSchema()
            data = schema.load(request.json)
            detection_data = data['data']
            
            # Add request metadata
            detection_data.update({
                'user_id': current_user,
                'timestamp': request.environ.get('timestamp'),
                'user_agent': request.headers.get('User-Agent', ''),
                'ip_address': request.remote_addr
            })
            
        except ValidationError:
            # Fall back to legacy feature-based detection
            try:
                schema = FeatureDetectionSchema()
                data = schema.load(request.json)
                features = data['features']
                
                # Convert features to data format
                detection_data = {
                    'type': 'features',
                    'features': features,
                    'user_id': current_user,
                    'ip_address': request.remote_addr
                }
                
            except ValidationError as e:
                return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
        
        # Get threat detector instance and advanced engine
        detector = get_threat_detector()
        advanced_engine = get_advanced_adaptive_engine()
        
        # Perform standard ML threat detection
        ml_result = detector.predict(detection_data)
        
        # Perform advanced modern threat detection
        advanced_result = advanced_engine.detect_modern_threats(detection_data)
        
        # Combine results
        result = {
            'is_threat': ml_result['is_threat'] or len(advanced_result['threats_detected']) > 0,
            'confidence': max(ml_result['confidence'], advanced_result['confidence']) if advanced_result['confidence'] > 0 else ml_result['confidence'],
            'threat_type': ml_result.get('threat_type'),
            'model_version': ml_result.get('model_version'),
            'features_used': ml_result.get('features_used', 0),
            'anomaly_score': ml_result.get('anomaly_score'),
            'classification_score': ml_result.get('classification_score'),
            'advanced_threats': advanced_result['threats_detected'],
            'modern_threat_types': advanced_result['threat_types'],
            'adaptive_response': advanced_result['adaptive_response'],
            'combined_risk_score': min(1.0, ml_result['confidence'] * 0.6 + advanced_result['risk_score'] * 0.4)
        }
        
        # Log the detection
        log_activity('threat_detection', current_user, {
            'is_threat': result['is_threat'],
            'confidence': result['confidence'],
            'threat_type': result.get('threat_type'),
            'model_version': result.get('model_version')
        })
        
        # Format response
        response = {
            'threat': result['is_threat'],
            'threat_type': result.get('threat_type'),
            'confidence': round(result['confidence'], 3),
            'source': 'custom_ml_model',
            'model_version': result.get('model_version'),
            'features_analyzed': result.get('features_used', 0),
            'timestamp': log_activity('threat_detection', current_user, {})['timestamp']
        }
        
        # Add detailed scores if available
        if 'anomaly_score' in result:
            response['anomaly_score'] = round(result['anomaly_score'], 3)
        if 'classification_score' in result:
            response['classification_score'] = round(result['classification_score'], 3)
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Threat detection error: {str(e)}")
        return jsonify({'error': 'Threat detection failed', 'details': str(e)}), 500

@threat_blueprint.route('/feedback', methods=['POST'])
@jwt_required()
def add_feedback():
    """Add feedback to improve threat detection model."""
    try:
        current_user = get_jwt_identity()
        
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        required_fields = ['data', 'is_threat']
        for field in required_fields:
            if field not in request.json:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        data = request.json['data']
        is_threat = bool(request.json['is_threat'])
        threat_type = request.json.get('threat_type')
        
        # Add metadata
        data.update({
            'user_id': current_user,
            'ip_address': request.remote_addr,
            'feedback_timestamp': request.environ.get('timestamp')
        })
        
        # Get threat detector and add feedback
        detector = get_threat_detector()
        detector.add_feedback(data, is_threat, threat_type)
        
        # Log the feedback
        log_activity('threat_feedback', current_user, {
            'is_threat': is_threat,
            'threat_type': threat_type,
            'feedback_source': 'user'
        })
        
        return jsonify({
            'message': 'Feedback added successfully',
            'will_retrain': len(detector.feedback_buffer) >= 50,
            'feedback_count': len(detector.feedback_buffer)
        }), 200
        
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}")
        return jsonify({'error': 'Failed to add feedback'}), 500

@threat_blueprint.route('/model-info', methods=['GET'])
@jwt_required()
def get_model_info():
    """Get information about the current threat detection model."""
    try:
        current_user = get_jwt_identity()
        detector = get_threat_detector()
        
        model_info = detector.get_model_info()
        
        # Log the request
        log_activity('model_info_request', current_user, {
            'model_version': model_info['model_version']
        })
        
        return jsonify(model_info), 200
        
    except Exception as e:
        logger.error(f"Model info error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve model information'}), 500

@threat_blueprint.route('/retrain', methods=['POST'])
@jwt_required()
def trigger_retrain():
    """Manually trigger model retraining (admin only)."""
    try:
        current_user = get_jwt_identity()
        
        # Check admin privileges
        admin_users = ['admin', 'security_admin', 'system']
        if current_user not in admin_users:
            return jsonify({'error': 'Admin privileges required'}), 403
        
        detector = get_threat_detector()
        
        # Get current metrics before retraining
        old_metrics = detector.get_model_info()
        
        # Trigger retraining
        detector.retrain_model()
        
        # Get new metrics after retraining
        new_metrics = detector.get_model_info()
        
        # Log the retraining
        log_activity('manual_retrain', current_user, {
            'old_version': old_metrics['model_version'],
            'new_version': new_metrics['model_version'],
            'samples_used': new_metrics['samples_trained']
        })
        
        return jsonify({
            'message': 'Model retrained successfully',
            'old_version': old_metrics['model_version'],
            'new_version': new_metrics['model_version'],
            'samples_trained': new_metrics['samples_trained'],
            'new_metrics': new_metrics['metrics']
        }), 200
        
    except Exception as e:
        logger.error(f"Retrain error: {str(e)}")
        return jsonify({'error': 'Failed to retrain model'}), 500

@threat_blueprint.route('/threat-patterns', methods=['GET'])
@jwt_required()
def get_threat_patterns():
    """Get current threat patterns detected by the model."""
    try:
        current_user = get_jwt_identity()
        detector = get_threat_detector()
        
        # Get pattern information
        patterns = {}
        for threat_type, samples in detector.pattern_tracker.items():
            if samples:  # Only include types with samples
                recent_samples = samples[-10:]  # Last 10 samples
                patterns[threat_type] = {
                    'count': len(samples),
                    'recent_count': len(recent_samples),
                    'last_seen': max(sample.timestamp for sample in recent_samples).isoformat(),
                    'avg_confidence': sum(sample.confidence for sample in recent_samples) / len(recent_samples)
                }
        
        # Log the request
        log_activity('threat_patterns_request', current_user, {
            'patterns_returned': len(patterns)
        })
        
        return jsonify({
            'threat_patterns': patterns,
            'total_patterns': len(patterns),
            'model_version': detector.last_retrain.isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Threat patterns error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve threat patterns'}), 500

# Legacy endpoint for backward compatibility
@threat_blueprint.route('/detect-legacy', methods=['POST'])
@jwt_required()
def detect_legacy():
    """Legacy threat detection endpoint for backward compatibility."""
    try:
        current_user = get_jwt_identity()
        
        features = request.json.get('features')
        if not features:
            return jsonify({'error': 'No features provided'}), 400
        
        # Convert to new format and use main detection
        detection_data = {
            'type': 'legacy_features',
            'features': features,
            'user_id': current_user
        }
        
        detector = get_threat_detector()
        result = detector.predict(detection_data)
        
        # Return in legacy format
        return jsonify({
            'threat': result['is_threat'],
            'source': 'custom_ml_model',
            'confidence': round(result['confidence'], 2)
        }), 200
        
    except Exception as e:
        logger.error(f"Legacy detection error: {str(e)}")
        return jsonify({'error': 'Detection failed'}), 500

@threat_blueprint.route('/detect-advanced', methods=['POST'])
@jwt_required()
def detect_advanced():
    """Advanced threat detection for modern attack vectors (2024-2025)."""
    try:
        current_user = get_jwt_identity()
        
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        detection_data = request.json.get('data', {})
        
        # Add request metadata
        detection_data.update({
            'user_id': current_user,
            'timestamp': datetime.now().isoformat(),
            'user_agent': request.headers.get('User-Agent', ''),
            'ip_address': request.remote_addr
        })
        
        # Get advanced engine
        advanced_engine = get_advanced_adaptive_engine()
        
        # Perform advanced threat detection
        result = advanced_engine.detect_modern_threats(detection_data)
        
        # Log the detection
        log_activity('advanced_threat_detection', current_user, {
            'threats_detected': len(result['threats_detected']),
            'risk_score': result['risk_score'],
            'threat_types': result['threat_types']
        })
        
        return jsonify({
            'threats_detected': result['threats_detected'],
            'threat_types': result['threat_types'],
            'risk_score': round(result['risk_score'], 3),
            'confidence': round(result['confidence'], 3),
            'adaptive_response': result['adaptive_response'],
            'timestamp': result['timestamp'],
            'detection_engine': 'advanced_adaptive_2025'
        }), 200
        
    except Exception as e:
        logger.error(f"Advanced threat detection error: {str(e)}")
        return jsonify({'error': 'Advanced threat detection failed'}), 500

@threat_blueprint.route('/detect-adversarial-ml', methods=['POST'])
@jwt_required()
def detect_adversarial_ml():
    """Detect adversarial ML attacks on model inputs."""
    try:
        current_user = get_jwt_identity()
        
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        ml_input = request.json.get('ml_input')
        if ml_input is None:
            return jsonify({'error': 'ml_input is required'}), 400
        
        # Get advanced engine
        advanced_engine = get_advanced_adaptive_engine()
        
        # Detect adversarial attacks
        detection_data = {
            'ml_input': ml_input,
            'metadata': request.json.get('metadata', {}),
            'user_id': current_user
        }
        
        result = advanced_engine.detect_modern_threats(detection_data)
        
        # Filter for adversarial ML attacks
        adversarial_threats = [t for t in result['threats_detected'] if 'adversarial_ml' in t['threat_type']]
        
        response = {
            'is_adversarial': len(adversarial_threats) > 0,
            'adversarial_attacks': adversarial_threats,
            'confidence': max([t['confidence'] for t in adversarial_threats], default=0.0),
            'timestamp': datetime.now().isoformat()
        }
        
        # Log the detection
        log_activity('adversarial_ml_detection', current_user, response)
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Adversarial ML detection error: {str(e)}")
        return jsonify({'error': 'Adversarial ML detection failed'}), 500

@threat_blueprint.route('/detect-ai-social-engineering', methods=['POST'])
@jwt_required()
def detect_ai_social_engineering():
    """Detect AI-powered social engineering attacks."""
    try:
        current_user = get_jwt_identity()
        
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        content = request.json.get('content', '')
        audio_metadata = request.json.get('audio_metadata', {})
        
        # Get advanced engine
        advanced_engine = get_advanced_adaptive_engine()
        
        # Detect AI social engineering
        detection_data = {
            'payload': content,
            'message': content,
            'audio_metadata': audio_metadata,
            'user_id': current_user
        }
        
        result = advanced_engine.detect_modern_threats(detection_data)
        
        # Filter for AI social engineering attacks
        ai_social_threats = [t for t in result['threats_detected'] if 'ai_social_engineering' in t['threat_type']]
        
        response = {
            'is_ai_social_engineering': len(ai_social_threats) > 0,
            'detected_attacks': ai_social_threats,
            'confidence': max([t['confidence'] for t in ai_social_threats], default=0.0),
            'indicators': [indicator for t in ai_social_threats for indicator in t.get('indicators', [])],
            'timestamp': datetime.now().isoformat()
        }
        
        # Log the detection
        log_activity('ai_social_engineering_detection', current_user, response)
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"AI social engineering detection error: {str(e)}")
        return jsonify({'error': 'AI social engineering detection failed'}), 500

@threat_blueprint.route('/detect-zero-day', methods=['POST'])
@jwt_required()
def detect_zero_day():
    """Detect zero-day vulnerability exploitation attempts."""
    try:
        current_user = get_jwt_identity()
        
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        payload = request.json.get('payload', '')
        binary_data = request.json.get('binary_data')
        behavioral_data = request.json.get('behavioral_data', {})
        
        # Get advanced engine
        advanced_engine = get_advanced_adaptive_engine()
        
        # Detect zero-day exploits
        detection_data = {
            'payload': payload,
            'binary_data': binary_data,
            'request_frequency': behavioral_data.get('request_frequency', 0),
            'geographic_anomaly': behavioral_data.get('geographic_anomaly', False),
            'user_id': current_user
        }
        
        result = advanced_engine.detect_modern_threats(detection_data)
        
        # Filter for zero-day attacks
        zero_day_threats = [t for t in result['threats_detected'] if 'zero_day' in t['threat_type']]
        
        response = {
            'is_zero_day_attempt': len(zero_day_threats) > 0,
            'detected_exploits': zero_day_threats,
            'confidence': max([t['confidence'] for t in zero_day_threats], default=0.0),
            'exploit_indicators': [indicator for t in zero_day_threats for indicator in t.get('indicators', [])],
            'timestamp': datetime.now().isoformat()
        }
        
        # Log the detection
        log_activity('zero_day_detection', current_user, response)
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Zero-day detection error: {str(e)}")
        return jsonify({'error': 'Zero-day detection failed'}), 500

@threat_blueprint.route('/add-threat-intelligence', methods=['POST'])
@jwt_required()
def add_threat_intelligence():
    """Add new threat intelligence to the adaptive system."""
    try:
        current_user = get_jwt_identity()
        
        # Check admin privileges
        admin_users = ['admin', 'security_admin', 'system']
        if current_user not in admin_users:
            return jsonify({'error': 'Admin privileges required'}), 403
        
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        required_fields = ['threat_id', 'threat_type', 'indicators', 'confidence', 'attack_vector', 'severity']
        for field in required_fields:
            if field not in request.json:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Get advanced engine
        advanced_engine = get_advanced_adaptive_engine()
        
        # Create threat intelligence object
        from .advanced_adaptive_engine import ThreatIntelligence
        threat_intel = ThreatIntelligence(
            threat_id=request.json['threat_id'],
            threat_type=request.json['threat_type'],
            indicators=request.json['indicators'],
            confidence=float(request.json['confidence']),
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            attack_vector=request.json['attack_vector'],
            severity=int(request.json['severity']),
            source=request.json.get('source', 'manual'),
            metadata=request.json.get('metadata', {})
        )
        
        # Add to system
        advanced_engine.add_threat_intelligence(threat_intel)
        
        # Save model
        advanced_engine.save_advanced_model()
        
        # Log the addition
        log_activity('threat_intelligence_added', current_user, {
            'threat_id': threat_intel.threat_id,
            'threat_type': threat_intel.threat_type,
            'indicators_count': len(threat_intel.indicators)
        })
        
        return jsonify({
            'message': 'Threat intelligence added successfully',
            'threat_id': threat_intel.threat_id,
            'threat_type': threat_intel.threat_type,
            'indicators_added': len(threat_intel.indicators)
        }), 200
        
    except Exception as e:
        logger.error(f"Add threat intelligence error: {str(e)}")
        return jsonify({'error': 'Failed to add threat intelligence'}), 500

@threat_blueprint.route('/advanced-model-info', methods=['GET'])
@jwt_required()
def get_advanced_model_info():
    """Get information about the advanced adaptive model."""
    try:
        current_user = get_jwt_identity()
        
        # Get advanced engine
        advanced_engine = get_advanced_adaptive_engine()
        
        # Get model information
        model_info = advanced_engine.get_advanced_model_info()
        
        # Log the request
        log_activity('advanced_model_info_request', current_user, {
            'threat_types_supported': len(model_info['supported_threat_types'])
        })
        
        return jsonify(model_info), 200
        
    except Exception as e:
        logger.error(f"Advanced model info error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve advanced model information'}), 500

@threat_blueprint.route('/adaptive-thresholds', methods=['GET', 'POST'])
@jwt_required()
def manage_adaptive_thresholds():
    """Get or update adaptive detection thresholds."""
    try:
        current_user = get_jwt_identity()
        
        # Get advanced engine
        advanced_engine = get_advanced_adaptive_engine()
        
        if request.method == 'GET':
            # Return current thresholds
            response = {
                'adaptive_thresholds': advanced_engine.adaptive_thresholds,
                'last_adaptation': datetime.now().isoformat(),
                'requested_by': current_user
            }
            
            log_activity('adaptive_thresholds_viewed', current_user, response)
            return jsonify(response), 200
            
        elif request.method == 'POST':
            # Update thresholds (admin only)
            admin_users = ['admin', 'security_admin', 'system']
            if current_user not in admin_users:
                return jsonify({'error': 'Admin privileges required'}), 403
            
            if not request.json:
                return jsonify({'error': 'Request must be JSON'}), 400
            
            new_thresholds = request.json.get('thresholds', {})
            
            # Validate thresholds
            for threat_type, threshold in new_thresholds.items():
                if not isinstance(threshold, (int, float)) or not (0.0 <= threshold <= 1.0):
                    return jsonify({'error': f'Invalid threshold for {threat_type}: must be between 0.0 and 1.0'}), 400
            
            # Update thresholds
            old_thresholds = advanced_engine.adaptive_thresholds.copy()
            advanced_engine.adaptive_thresholds.update(new_thresholds)
            
            # Save model
            advanced_engine.save_advanced_model()
            
            # Log the update
            log_activity('adaptive_thresholds_updated', current_user, {
                'old_thresholds': old_thresholds,
                'new_thresholds': advanced_engine.adaptive_thresholds,
                'updated_types': list(new_thresholds.keys())
            })
            
            return jsonify({
                'message': 'Adaptive thresholds updated successfully',
                'updated_thresholds': advanced_engine.adaptive_thresholds,
                'changes_made': list(new_thresholds.keys())
            }), 200
        
    except Exception as e:
        logger.error(f"Adaptive thresholds error: {str(e)}")
        return jsonify({'error': 'Failed to manage adaptive thresholds'}), 500
