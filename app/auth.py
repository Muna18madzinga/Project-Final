import re
import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, 
    jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, validate, ValidationError
import bcrypt
from config.security_config import PASSWORD_CONFIG

auth_blueprint = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

# Temporary in-memory storage (should be replaced with database)
users_db = {}
blacklisted_tokens = set()
failed_attempts = {}

# Pre-provision a default operator account so the dashboard can be accessed immediately.
_default_username = "Theo_Madzinga"
_default_password = "Theo@1172025"
users_db[_default_username] = {
    'password_hash': bcrypt.hashpw(_default_password.encode('utf-8'), bcrypt.gensalt(rounds=12)),
    'email': None,
    'created_at': datetime.now(),
    'is_active': True,
    'password_changed_at': datetime.now()
}

# Password validation schema
class PasswordSchema(Schema):
    password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=PASSWORD_CONFIG['min_length']),
            validate.Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                error="Password must contain uppercase, lowercase, digit and special character"
            )
        ]
    )

class UserSchema(Schema):
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=30),
            validate.Regexp(r'^[a-zA-Z0-9_]+$', error="Username can only contain letters, numbers and underscores")
        ]
    )
    password = fields.Str(required=True)
    email = fields.Email(required=False)

def validate_password_strength(password):
    """Validate password meets security requirements."""
    errors = []
    
    if len(password) < PASSWORD_CONFIG['min_length']:
        errors.append(f"Password must be at least {PASSWORD_CONFIG['min_length']} characters")
    
    if PASSWORD_CONFIG['require_uppercase'] and not re.search(r'[A-Z]', password):
        errors.append("Password must contain uppercase letters")
    
    if PASSWORD_CONFIG['require_lowercase'] and not re.search(r'[a-z]', password):
        errors.append("Password must contain lowercase letters")
    
    if PASSWORD_CONFIG['require_digits'] and not re.search(r'\d', password):
        errors.append("Password must contain digits")
    
    if PASSWORD_CONFIG['require_special_chars'] and not re.search(r'[@$!%*?&]', password):
        errors.append("Password must contain special characters (@$!%*?&)")
    
    return errors

def is_account_locked(username):
    """Check if account is locked due to failed attempts."""
    if username not in failed_attempts:
        return False
    
    attempt_data = failed_attempts[username]
    if attempt_data['count'] >= PASSWORD_CONFIG['max_attempts']:
        lockout_time = attempt_data['last_attempt'] + timedelta(minutes=PASSWORD_CONFIG['lockout_minutes'])
        if datetime.now() < lockout_time:
            return True
        else:
            # Reset failed attempts after lockout period
            del failed_attempts[username]
    
    return False

def record_failed_attempt(username):
    """Record a failed login attempt."""
    if username not in failed_attempts:
        failed_attempts[username] = {'count': 0, 'last_attempt': datetime.now()}
    
    failed_attempts[username]['count'] += 1
    failed_attempts[username]['last_attempt'] = datetime.now()

def clear_failed_attempts(username):
    """Clear failed attempts on successful login."""
    if username in failed_attempts:
        del failed_attempts[username]

@auth_blueprint.route('/register', methods=['POST'])
def register():
    try:
        # Validate request data
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        schema = UserSchema()
        data = schema.load(request.json)
        
        username = data['username']
        password = data['password']
        email = data.get('email')
        
        # Check if user already exists
        if username in users_db:
            return jsonify({'error': 'Username already exists'}), 409
        
        # Validate password strength
        password_errors = validate_password_strength(password)
        if password_errors:
            return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
        
        # Hash password
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        
        # Store user data
        users_db[username] = {
            'password_hash': hashed,
            'email': email,
            'created_at': datetime.now(),
            'is_active': True,
            'password_changed_at': datetime.now()
        }
        
        logger.info(f"User registered successfully: {username}")
        return jsonify({'message': 'User registered successfully'}), 201
        
    except ValidationError as e:
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@auth_blueprint.route('/login', methods=['POST'])
def login():
    try:
        # Validate request data
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        username = request.json.get('username')
        password = request.json.get('password')

        logger.debug("Login attempt for user %s", username)
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Check account lockout
        if is_account_locked(username):
            return jsonify({'error': 'Account temporarily locked due to failed attempts'}), 423
        
        # Check if user exists
        if username not in users_db:
            record_failed_attempt(username)
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_data = users_db[username]
        logger.debug("User data keys: %s", list(user_data.keys()))
        
        # Check if account is active
        if not user_data.get('is_active', True):
            return jsonify({'error': 'Account is disabled'}), 403
        
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash']):
            record_failed_attempt(username)
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Clear failed attempts on successful login
        clear_failed_attempts(username)
        
        # Create tokens
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        
        logger.info(f"User logged in successfully: {username}")
        
        access_expires = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        expires_seconds = (
            access_expires.total_seconds()
            if hasattr(access_expires, "total_seconds")
            else access_expires
        )

        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': expires_seconds
        }), 200
        
    except Exception as e:
        logger.exception("Login error for user %s", request.json.get('username') if request.json else None)
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500

@auth_blueprint.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user)
        return jsonify({'access_token': new_token}), 200
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_blueprint.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        blacklisted_tokens.add(jti)
        return jsonify({'message': 'Successfully logged out'}), 200
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_blueprint.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    try:
        current_user = get_jwt_identity()
        user_data = users_db.get(current_user)
        
        if not user_data:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'username': current_user,
            'email': user_data.get('email'),
            'created_at': user_data.get('created_at').isoformat() if user_data.get('created_at') else None,
            'is_active': user_data.get('is_active', True)
        }), 200
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve profile'}), 500
