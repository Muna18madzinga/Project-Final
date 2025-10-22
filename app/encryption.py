import os
import logging
import base64
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from marshmallow import Schema, fields, ValidationError

encryption_blueprint = Blueprint('encryption', __name__)
logger = logging.getLogger(__name__)

class EncryptionSchema(Schema):
    data = fields.Str(required=True, validate=lambda x: len(x.strip()) > 0)

class DecryptionSchema(Schema):
    encrypted = fields.Str(required=True, validate=lambda x: len(x.strip()) > 0)

def get_fernet_key():
    """Generate or retrieve Fernet key from environment variables."""
    # Check if encryption key exists in environment
    env_key = os.getenv('ENCRYPTION_KEY')
    
    if env_key:
        try:
            # Validate the key format
            key_bytes = base64.urlsafe_b64decode(env_key)
            if len(key_bytes) == 32:  # Fernet keys must be 32 bytes
                return env_key.encode()
        except Exception:
            logger.warning("Invalid ENCRYPTION_KEY format in environment, generating new key")
    
    # Generate key using password-based key derivation
    password = os.getenv('ENCRYPTION_PASSWORD', 'default-password-change-me').encode()
    salt = os.getenv('ENCRYPTION_SALT', 'default-salt-change-me').encode()
    
    # Use PBKDF2 to derive a key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Recommended minimum
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    
    # Log warning about using derived key
    logger.warning("Using derived encryption key. Set ENCRYPTION_KEY environment variable for production.")
    
    return key

# Initialize cipher suite with secure key
try:
    fernet_key = get_fernet_key()
    cipher_suite = Fernet(fernet_key)
    logger.info("Encryption service initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize encryption service: {e}")
    cipher_suite = None

@encryption_blueprint.route('/encrypt', methods=['POST'])
@jwt_required()
def encrypt():
    try:
        if not cipher_suite:
            return jsonify({'error': 'Encryption service unavailable'}), 503
        
        # Validate request
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        schema = EncryptionSchema()
        data = schema.load(request.json)
        
        # Get current user for logging
        current_user = get_jwt_identity()
        
        # Encrypt the data
        plaintext = data['data']
        encrypted_data = cipher_suite.encrypt(plaintext.encode('utf-8'))
        
        # Log the operation (without sensitive data)
        logger.info(f"Data encrypted by user: {current_user}")
        
        return jsonify({
            'encrypted': encrypted_data.decode('utf-8'),
            'message': 'Data encrypted successfully'
        }), 200
        
    except ValidationError as e:
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return jsonify({'error': 'Encryption failed'}), 500

@encryption_blueprint.route('/decrypt', methods=['POST'])
@jwt_required()
def decrypt():
    try:
        if not cipher_suite:
            return jsonify({'error': 'Encryption service unavailable'}), 503
        
        # Validate request
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        schema = DecryptionSchema()
        data = schema.load(request.json)
        
        # Get current user for logging
        current_user = get_jwt_identity()
        
        # Decrypt the data
        encrypted_data = data['encrypted']
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data.encode('utf-8'))
            plaintext = decrypted_data.decode('utf-8')
            
            # Log the operation (without sensitive data)
            logger.info(f"Data decrypted by user: {current_user}")
            
            return jsonify({
                'decrypted': plaintext,
                'message': 'Data decrypted successfully'
            }), 200
            
        except InvalidToken:
            return jsonify({'error': 'Invalid encrypted data or key'}), 400
        except UnicodeDecodeError:
            return jsonify({'error': 'Decrypted data contains invalid characters'}), 400
        
    except ValidationError as e:
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 500

@encryption_blueprint.route('/key-info', methods=['GET'])
@jwt_required()
def key_info():
    """Get information about the current encryption key (for admin purposes)."""
    try:
        current_user = get_jwt_identity()
        
        if not cipher_suite:
            return jsonify({'error': 'Encryption service unavailable'}), 503
        
        # Only provide non-sensitive key information
        key_source = "environment" if os.getenv('ENCRYPTION_KEY') else "derived"
        
        return jsonify({
            'key_source': key_source,
            'algorithm': 'Fernet (AES 128)',
            'key_length': '256 bits',
            'user': current_user
        }), 200
        
    except Exception as e:
        logger.error(f"Key info error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve key information'}), 500
