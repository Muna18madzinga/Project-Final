import logging
import re
from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from marshmallow import Schema, fields, ValidationError

logger = logging.getLogger(__name__)

def validate_email(email):
    """Validate email format."""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password_strength(password):
    """
    Validate password strength:
    - At least 12 characters (updated from 8)
    - Contains uppercase and lowercase
    - Contains numbers
    - Contains special characters
    """
    if not password or len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def require_auth(f):
    """Enhanced authentication decorator using flask-jwt-extended."""
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        try:
            current_user = get_jwt_identity()
            if not current_user:
                return jsonify({'error': 'Invalid user identity'}), 401
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 401
    return decorated

def require_admin_auth(f):
    """Enhanced authentication decorator for admin-only endpoints."""
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        try:
            current_user = get_jwt_identity()
            if not current_user:
                return jsonify({'error': 'Invalid user identity'}), 401
            
            # In a real application, check if user has admin role
            # For now, we'll require a specific admin username or role check
            admin_users = ['admin', 'security_admin', 'system']
            if current_user not in admin_users:
                return jsonify({'error': 'Admin privileges required'}), 403
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Admin authentication error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 401
    return decorated

def log_activity(activity_type, user_id, details=None):
    """Log security-related activities with enhanced information."""
    try:
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'activity_type': activity_type,
            'user_id': user_id,
            'details': details or {},
            'ip_address': request.remote_addr if request else 'unknown',
            'user_agent': request.headers.get('User-Agent') if request else 'unknown'
        }
        logger.info(f'Security Activity: {log_entry}')
        return log_entry
    except Exception as e:
        logger.error(f"Failed to log activity: {str(e)}")
        return None

def validate_ip_address(ip):
    """Validate IP address format."""
    if not ip:
        return False
    
    # IPv4 validation
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ipv4_pattern, ip):
        return True
    
    # IPv6 validation (basic)
    ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    if re.match(ipv6_pattern, ip):
        return True
    
    return False

def sanitize_input(data, max_length=1000):
    """Sanitize user input to prevent injection attacks."""
    if not isinstance(data, str):
        return data
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', data)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

class RiskAssessmentSchema(Schema):
    user_id = fields.Str(required=True, validate=lambda x: len(x.strip()) > 0)
    context = fields.Dict(required=True)

class ThreatUpdateSchema(Schema):
    threats = fields.Dict(required=True)
