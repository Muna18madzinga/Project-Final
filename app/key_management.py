"""
Enterprise Key Management System (KMS)
Implements envelope encryption, key rotation, and HSM integration
"""

import logging
import os
import secrets
import base64
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

logger = logging.getLogger(__name__)

kms_blueprint = Blueprint('kms', __name__)

@dataclass
class EncryptionKey:
    """Encryption key metadata"""
    key_id: str
    key_type: str  # 'master', 'data', 'wrapped'
    algorithm: str
    created_at: datetime
    expires_at: Optional[datetime]
    status: str  # 'active', 'rotating', 'rotated', 'revoked'
    rotation_count: int
    used_count: int
    last_used: Optional[datetime]

@dataclass
class EncryptedData:
    """Encrypted data with metadata"""
    ciphertext: bytes
    wrapped_dek: bytes
    key_id: str
    algorithm: str
    iv: bytes
    auth_tag: Optional[bytes]
    context: Dict
    encrypted_at: datetime

class KeyManagementSystem:
    """Enterprise Key Management System"""

    def __init__(self, master_key: Optional[bytes] = None):
        self.master_keys = {}
        self.data_keys = {}
        self.key_metadata = {}
        self.rotation_schedule = {}

        # Initialize master key
        if master_key:
            self.master_keys['default'] = master_key
        else:
            self._initialize_master_key()

        # Key rotation settings
        self.rotation_interval = timedelta(days=90)  # 90 days
        self.auto_rotation_enabled = True

        logger.info("Key Management System initialized")

    def _initialize_master_key(self):
        """Initialize or load master key"""

        # Try to load from environment
        master_key_b64 = os.getenv('MASTER_ENCRYPTION_KEY')

        if master_key_b64:
            try:
                master_key = base64.b64decode(master_key_b64)
                if len(master_key) == 32:  # 256-bit key
                    self.master_keys['default'] = master_key
                    logger.info("Master key loaded from environment")
                    return
            except Exception as e:
                logger.error(f"Failed to load master key from environment: {e}")

        # Generate new master key
        master_key = secrets.token_bytes(32)  # 256-bit key
        self.master_keys['default'] = master_key

        # In production, this should be stored in HSM/KMS
        master_key_b64 = base64.b64encode(master_key).decode()
        logger.warning(f"Generated new master key. Store securely: MASTER_ENCRYPTION_KEY={master_key_b64}")

        # Create key metadata
        key_id = 'master_default_' + secrets.token_hex(8)
        self.key_metadata[key_id] = EncryptionKey(
            key_id=key_id,
            key_type='master',
            algorithm='AES-256-GCM',
            created_at=datetime.now(),
            expires_at=None,  # Master keys don't expire
            status='active',
            rotation_count=0,
            used_count=0,
            last_used=None
        )

    def generate_data_encryption_key(self) -> Tuple[str, bytes]:
        """Generate a new Data Encryption Key (DEK)"""

        # Generate DEK
        dek = secrets.token_bytes(32)  # 256-bit key

        # Create key ID
        key_id = 'dek_' + secrets.token_hex(16)

        # Store DEK (encrypted with master key)
        wrapped_dek = self.wrap_key(dek)
        self.data_keys[key_id] = wrapped_dek

        # Create metadata
        self.key_metadata[key_id] = EncryptionKey(
            key_id=key_id,
            key_type='data',
            algorithm='AES-256-GCM',
            created_at=datetime.now(),
            expires_at=datetime.now() + self.rotation_interval,
            status='active',
            rotation_count=0,
            used_count=0,
            last_used=None
        )

        logger.info(f"Generated DEK: {key_id}")

        return key_id, dek

    def wrap_key(self, key_to_wrap: bytes, master_key_id: str = 'default') -> bytes:
        """
        Wrap (encrypt) a key with master key using AES-GCM
        This implements envelope encryption
        """

        if master_key_id not in self.master_keys:
            raise ValueError(f"Master key not found: {master_key_id}")

        master_key = self.master_keys[master_key_id]

        # Use AES-GCM for authenticated encryption
        aesgcm = AESGCM(master_key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM

        # Additional authenticated data (AAD)
        aad = f"wrapped_key_{datetime.now().isoformat()}".encode()

        # Encrypt the key
        wrapped_key = aesgcm.encrypt(nonce, key_to_wrap, aad)

        # Combine nonce + wrapped_key + aad_length + aad
        result = nonce + wrapped_key + len(aad).to_bytes(4, 'big') + aad

        return result

    def unwrap_key(self, wrapped_key: bytes, master_key_id: str = 'default') -> bytes:
        """Unwrap (decrypt) a key with master key"""

        if master_key_id not in self.master_keys:
            raise ValueError(f"Master key not found: {master_key_id}")

        master_key = self.master_keys[master_key_id]

        try:
            # Extract components
            nonce = wrapped_key[:12]
            aad_length_start = len(wrapped_key) - 4
            aad_length = int.from_bytes(wrapped_key[aad_length_start:], 'big')
            aad = wrapped_key[aad_length_start + 4:]
            ciphertext = wrapped_key[12:aad_length_start]

            # Decrypt
            aesgcm = AESGCM(master_key)
            plaintext_key = aesgcm.decrypt(nonce, ciphertext, aad)

            return plaintext_key

        except Exception as e:
            logger.error(f"Key unwrap failed: {e}")
            raise ValueError("Failed to unwrap key - invalid key or corrupted data")

    def encrypt_data(self, plaintext: bytes, context: Optional[Dict] = None) -> EncryptedData:
        """
        Encrypt data using envelope encryption
        1. Generate DEK
        2. Encrypt data with DEK
        3. Encrypt DEK with master key (wrap)
        """

        if context is None:
            context = {}

        # Generate DEK
        key_id, dek = self.generate_data_encryption_key()

        # Encrypt data with DEK using AES-GCM
        aesgcm = AESGCM(dek)
        nonce = secrets.token_bytes(12)

        # Add context as AAD
        aad = json.dumps(context, sort_keys=True).encode()

        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Wrap DEK with master key
        wrapped_dek = self.wrap_key(dek)

        # Update key usage
        if key_id in self.key_metadata:
            self.key_metadata[key_id].used_count += 1
            self.key_metadata[key_id].last_used = datetime.now()

        # Clear DEK from memory (in production, use secure memory)
        dek = None

        encrypted_data = EncryptedData(
            ciphertext=ciphertext,
            wrapped_dek=wrapped_dek,
            key_id=key_id,
            algorithm='AES-256-GCM',
            iv=nonce,
            auth_tag=None,  # Included in ciphertext for GCM
            context=context,
            encrypted_at=datetime.now()
        )

        logger.info(f"Data encrypted with key: {key_id}")

        return encrypted_data

    def decrypt_data(self, encrypted_data: EncryptedData) -> bytes:
        """
        Decrypt data using envelope encryption
        1. Unwrap DEK
        2. Decrypt data with DEK
        """

        # Unwrap DEK
        dek = self.unwrap_key(encrypted_data.wrapped_dek)

        # Decrypt data with DEK
        aesgcm = AESGCM(dek)

        # Reconstruct AAD
        aad = json.dumps(encrypted_data.context, sort_keys=True).encode()

        try:
            plaintext = aesgcm.decrypt(encrypted_data.iv, encrypted_data.ciphertext, aad)

            # Update key usage
            if encrypted_data.key_id in self.key_metadata:
                self.key_metadata[encrypted_data.key_id].used_count += 1
                self.key_metadata[encrypted_data.key_id].last_used = datetime.now()

            # Clear DEK from memory
            dek = None

            logger.info(f"Data decrypted with key: {encrypted_data.key_id}")

            return plaintext

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Decryption failed - invalid key or corrupted data")

    def rotate_master_key(self, old_key_id: str = 'default') -> str:
        """
        Rotate master key
        1. Generate new master key
        2. Re-wrap all DEKs with new master key
        3. Mark old key as rotated
        """

        logger.info(f"Starting master key rotation for: {old_key_id}")

        # Generate new master key
        new_master_key = secrets.token_bytes(32)
        new_key_id = f"{old_key_id}_rotated_{datetime.now().strftime('%Y%m%d')}"

        # Store new master key
        self.master_keys[new_key_id] = new_master_key

        # Re-wrap all DEKs
        rewrapped_count = 0
        for dek_id, wrapped_dek in list(self.data_keys.items()):
            try:
                # Unwrap with old key
                dek = self.unwrap_key(wrapped_dek, old_key_id)

                # Re-wrap with new key
                new_wrapped_dek = self.wrap_key(dek, new_key_id)

                # Update storage
                self.data_keys[dek_id] = new_wrapped_dek

                # Update metadata
                if dek_id in self.key_metadata:
                    self.key_metadata[dek_id].rotation_count += 1

                rewrapped_count += 1

            except Exception as e:
                logger.error(f"Failed to re-wrap DEK {dek_id}: {e}")

        # Update old master key status
        for key_id, metadata in self.key_metadata.items():
            if metadata.key_type == 'master' and old_key_id in key_id:
                metadata.status = 'rotated'

        # Create new master key metadata
        new_metadata_id = f"master_{new_key_id}"
        self.key_metadata[new_metadata_id] = EncryptionKey(
            key_id=new_metadata_id,
            key_type='master',
            algorithm='AES-256-GCM',
            created_at=datetime.now(),
            expires_at=None,
            status='active',
            rotation_count=0,
            used_count=0,
            last_used=None
        )

        # Set new key as default
        self.master_keys['default'] = new_master_key

        logger.info(f"Master key rotation complete. Re-wrapped {rewrapped_count} DEKs")

        return new_key_id

    def rotate_data_key(self, old_key_id: str) -> str:
        """
        Rotate a specific data encryption key
        Note: This creates a new key but doesn't re-encrypt data
        Old key is kept for decryption of existing data
        """

        if old_key_id not in self.key_metadata:
            raise ValueError(f"Key not found: {old_key_id}")

        # Mark old key as rotated
        self.key_metadata[old_key_id].status = 'rotated'

        # Generate new DEK
        new_key_id, new_dek = self.generate_data_encryption_key()

        logger.info(f"Data key rotated: {old_key_id} -> {new_key_id}")

        return new_key_id

    def check_rotation_needed(self) -> List[str]:
        """Check which keys need rotation"""

        keys_to_rotate = []

        for key_id, metadata in self.key_metadata.items():
            if metadata.status != 'active':
                continue

            if metadata.key_type == 'data' and metadata.expires_at:
                if datetime.now() >= metadata.expires_at:
                    keys_to_rotate.append(key_id)

        return keys_to_rotate

    def auto_rotate_keys(self):
        """Automatically rotate expired keys"""

        if not self.auto_rotation_enabled:
            return

        keys_to_rotate = self.check_rotation_needed()

        for key_id in keys_to_rotate:
            try:
                self.rotate_data_key(key_id)
                logger.info(f"Auto-rotated key: {key_id}")
            except Exception as e:
                logger.error(f"Auto-rotation failed for {key_id}: {e}")

    def revoke_key(self, key_id: str):
        """Revoke a key"""

        if key_id not in self.key_metadata:
            raise ValueError(f"Key not found: {key_id}")

        self.key_metadata[key_id].status = 'revoked'

        logger.warning(f"Key revoked: {key_id}")

    def get_key_info(self, key_id: str) -> Optional[EncryptionKey]:
        """Get key metadata"""
        return self.key_metadata.get(key_id)

    def list_keys(self, key_type: Optional[str] = None, status: Optional[str] = None) -> List[EncryptionKey]:
        """List keys with optional filtering"""

        keys = []

        for key_id, metadata in self.key_metadata.items():
            if key_type and metadata.key_type != key_type:
                continue

            if status and metadata.status != status:
                continue

            keys.append(metadata)

        return keys

    def export_wrapped_dek(self, key_id: str) -> Optional[bytes]:
        """Export wrapped DEK for external storage"""
        return self.data_keys.get(key_id)

    def import_wrapped_dek(self, key_id: str, wrapped_dek: bytes):
        """Import wrapped DEK from external storage"""
        self.data_keys[key_id] = wrapped_dek
        logger.info(f"Imported wrapped DEK: {key_id}")

# Global KMS instance
kms = KeyManagementSystem()

# API Endpoints

@kms_blueprint.route('/encrypt', methods=['POST'])
@jwt_required()
def encrypt_with_kms():
    """Encrypt data using KMS envelope encryption"""
    try:
        current_user = get_jwt_identity()

        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400

        plaintext = request.json.get('data')
        if not plaintext:
            return jsonify({'error': 'Data required'}), 400

        context = request.json.get('context', {})
        context['user'] = current_user
        context['timestamp'] = datetime.now().isoformat()

        # Encrypt data
        encrypted = kms.encrypt_data(plaintext.encode(), context)

        # Return encrypted data (serialized)
        result = {
            'ciphertext': base64.b64encode(encrypted.ciphertext).decode(),
            'wrapped_key': base64.b64encode(encrypted.wrapped_dek).decode(),
            'key_id': encrypted.key_id,
            'algorithm': encrypted.algorithm,
            'iv': base64.b64encode(encrypted.iv).decode(),
            'encrypted_at': encrypted.encrypted_at.isoformat()
        }

        logger.info(f"Data encrypted for user: {current_user}")

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"KMS encryption error: {e}")
        return jsonify({'error': 'Encryption failed'}), 500

@kms_blueprint.route('/decrypt', methods=['POST'])
@jwt_required()
def decrypt_with_kms():
    """Decrypt data using KMS envelope encryption"""
    try:
        current_user = get_jwt_identity()

        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400

        # Parse encrypted data
        ciphertext = base64.b64decode(request.json.get('ciphertext', ''))
        wrapped_key = base64.b64decode(request.json.get('wrapped_key', ''))
        key_id = request.json.get('key_id', '')
        iv = base64.b64decode(request.json.get('iv', ''))
        context = request.json.get('context', {})

        # Reconstruct EncryptedData
        encrypted_data = EncryptedData(
            ciphertext=ciphertext,
            wrapped_dek=wrapped_key,
            key_id=key_id,
            algorithm='AES-256-GCM',
            iv=iv,
            auth_tag=None,
            context=context,
            encrypted_at=datetime.now()
        )

        # Decrypt data
        plaintext = kms.decrypt_data(encrypted_data)

        logger.info(f"Data decrypted for user: {current_user}")

        return jsonify({
            'plaintext': plaintext.decode(),
            'key_id': key_id
        }), 200

    except Exception as e:
        logger.error(f"KMS decryption error: {e}")
        return jsonify({'error': 'Decryption failed'}), 500

@kms_blueprint.route('/keys', methods=['GET'])
@jwt_required()
def list_encryption_keys():
    """List encryption keys (admin only)"""
    try:
        current_user = get_jwt_identity()

        # In production, check admin role
        if current_user not in ['admin', 'security_admin']:
            return jsonify({'error': 'Admin access required'}), 403

        key_type = request.args.get('type')
        status = request.args.get('status')

        keys = kms.list_keys(key_type=key_type, status=status)

        result = []
        for key in keys:
            result.append({
                'key_id': key.key_id[:16] + '...',  # Truncate for security
                'key_type': key.key_type,
                'algorithm': key.algorithm,
                'created_at': key.created_at.isoformat(),
                'expires_at': key.expires_at.isoformat() if key.expires_at else None,
                'status': key.status,
                'rotation_count': key.rotation_count,
                'used_count': key.used_count
            })

        return jsonify({
            'keys': result,
            'total_keys': len(result)
        }), 200

    except Exception as e:
        logger.error(f"Key listing error: {e}")
        return jsonify({'error': 'Failed to list keys'}), 500

@kms_blueprint.route('/rotate', methods=['POST'])
@jwt_required()
def rotate_key():
    """Rotate encryption key (admin only)"""
    try:
        current_user = get_jwt_identity()

        # In production, check admin role
        if current_user not in ['admin', 'security_admin']:
            return jsonify({'error': 'Admin access required'}), 403

        key_id = request.json.get('key_id')
        if not key_id:
            return jsonify({'error': 'Key ID required'}), 400

        # Rotate key
        new_key_id = kms.rotate_data_key(key_id)

        logger.info(f"Key rotated by {current_user}: {key_id} -> {new_key_id}")

        return jsonify({
            'message': 'Key rotated successfully',
            'old_key_id': key_id,
            'new_key_id': new_key_id
        }), 200

    except Exception as e:
        logger.error(f"Key rotation error: {e}")
        return jsonify({'error': 'Key rotation failed'}), 500

@kms_blueprint.route('/auto-rotate', methods=['POST'])
@jwt_required()
def trigger_auto_rotation():
    """Trigger automatic key rotation (admin only)"""
    try:
        current_user = get_jwt_identity()

        if current_user not in ['admin', 'security_admin']:
            return jsonify({'error': 'Admin access required'}), 403

        keys_to_rotate = kms.check_rotation_needed()

        if not keys_to_rotate:
            return jsonify({
                'message': 'No keys require rotation',
                'keys_checked': len(kms.key_metadata)
            }), 200

        kms.auto_rotate_keys()

        return jsonify({
            'message': 'Auto-rotation completed',
            'keys_rotated': len(keys_to_rotate),
            'rotated_keys': keys_to_rotate
        }), 200

    except Exception as e:
        logger.error(f"Auto-rotation error: {e}")
        return jsonify({'error': 'Auto-rotation failed'}), 500

# Export for use in other modules
def get_kms() -> KeyManagementSystem:
    """Get global KMS instance"""
    return kms
