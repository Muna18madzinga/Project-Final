"""
Multi-Factor Authentication (MFA) Module
Supports TOTP, SMS, Email verification, and backup codes
"""

import logging
import secrets
import base64
import io
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import pyotp
import qrcode
from marshmallow import Schema, fields, ValidationError

logger = logging.getLogger(__name__)

mfa_blueprint = Blueprint('mfa', __name__)

# In-memory storage (replace with database in production)
mfa_secrets = {}
backup_codes = {}
mfa_sessions = {}  # Temporary MFA challenges

class MFAEnrollSchema(Schema):
    """Schema for MFA enrollment request"""
    method = fields.Str(required=True, validate=lambda x: x in ['totp', 'sms', 'email'])
    phone_number = fields.Str(required=False)
    email = fields.Email(required=False)

class MFAVerifySchema(Schema):
    """Schema for MFA verification"""
    code = fields.Str(required=True, validate=lambda x: len(x) == 6 and x.isdigit())
    session_id = fields.Str(required=False)

class TOTPManager:
    """Time-based One-Time Password manager"""

    def __init__(self):
        self.issuer_name = "Adaptive Security Suite"

    def generate_secret(self, username: str) -> Dict[str, Any]:
        """Generate TOTP secret for user"""
        secret = pyotp.random_base32()

        # Store secret (in production, store in database)
        if username not in mfa_secrets:
            mfa_secrets[username] = {}
        mfa_secrets[username]['totp_secret'] = secret
        mfa_secrets[username]['totp_enabled'] = False  # Not enabled until verified
        mfa_secrets[username]['created_at'] = datetime.now()

        # Generate provisioning URI for QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

        logger.info(f"Generated TOTP secret for user: {username}")

        return {
            'secret': secret,
            'qr_code': f'data:image/png;base64,{qr_code_base64}',
            'provisioning_uri': provisioning_uri,
            'manual_entry_key': secret
        }

    def verify_totp(self, username: str, token: str, enable_on_success: bool = False) -> bool:
        """Verify TOTP token"""
        if username not in mfa_secrets or 'totp_secret' not in mfa_secrets[username]:
            logger.warning(f"No TOTP secret found for user: {username}")
            return False

        secret = mfa_secrets[username]['totp_secret']
        totp = pyotp.TOTP(secret)

        # Verify with a window of 1 (allows for time drift)
        is_valid = totp.verify(token, valid_window=1)

        if is_valid:
            if enable_on_success:
                mfa_secrets[username]['totp_enabled'] = True
                mfa_secrets[username]['enabled_at'] = datetime.now()

            logger.info(f"TOTP verification successful for user: {username}")
        else:
            logger.warning(f"TOTP verification failed for user: {username}")

        return is_valid

    def is_totp_enabled(self, username: str) -> bool:
        """Check if TOTP is enabled for user"""
        return (username in mfa_secrets and
                mfa_secrets[username].get('totp_enabled', False))

class BackupCodesManager:
    """Backup codes manager for account recovery"""

    def generate_backup_codes(self, username: str, count: int = 10) -> List[str]:
        """Generate backup codes for user"""
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            codes.append(code)

        # Store hashed codes (in production, hash with bcrypt)
        backup_codes[username] = {
            'codes': set(codes),
            'used': set(),
            'generated_at': datetime.now()
        }

        logger.info(f"Generated {count} backup codes for user: {username}")

        return codes

    def verify_backup_code(self, username: str, code: str) -> bool:
        """Verify and consume a backup code"""
        if username not in backup_codes:
            return False

        code = code.upper().strip()
        user_codes = backup_codes[username]

        if code in user_codes['codes'] and code not in user_codes['used']:
            # Mark code as used
            user_codes['used'].add(code)
            logger.info(f"Backup code used for user: {username}")
            return True

        logger.warning(f"Invalid or used backup code for user: {username}")
        return False

    def get_remaining_codes_count(self, username: str) -> int:
        """Get count of remaining backup codes"""
        if username not in backup_codes:
            return 0

        user_codes = backup_codes[username]
        return len(user_codes['codes'] - user_codes['used'])

class SMSVerificationManager:
    """SMS-based verification (stub - integrate with Twilio/AWS SNS)"""

    def __init__(self):
        # In production, initialize Twilio client
        self.pending_verifications = {}

    def send_sms_code(self, phone_number: str, username: str) -> str:
        """Send SMS verification code"""
        # Generate 6-digit code
        code = str(secrets.randbelow(1000000)).zfill(6)

        # Store temporarily
        session_id = secrets.token_urlsafe(32)
        self.pending_verifications[session_id] = {
            'code': code,
            'phone_number': phone_number,
            'username': username,
            'created_at': datetime.now(),
            'attempts': 0
        }

        # In production, send via Twilio
        logger.info(f"SMS code generated for {phone_number}: {code}")

        # For development, return code (remove in production)
        return session_id

    def verify_sms_code(self, session_id: str, code: str) -> bool:
        """Verify SMS code"""
        if session_id not in self.pending_verifications:
            return False

        verification = self.pending_verifications[session_id]

        # Check expiration (5 minutes)
        if datetime.now() - verification['created_at'] > timedelta(minutes=5):
            del self.pending_verifications[session_id]
            return False

        # Check attempts
        verification['attempts'] += 1
        if verification['attempts'] > 3:
            del self.pending_verifications[session_id]
            return False

        # Verify code
        if verification['code'] == code:
            del self.pending_verifications[session_id]
            return True

        return False

class EmailVerificationManager:
    """Email-based verification"""

    def __init__(self):
        self.pending_verifications = {}

    def send_email_code(self, email: str, username: str) -> str:
        """Send email verification code"""
        code = str(secrets.randbelow(1000000)).zfill(6)

        session_id = secrets.token_urlsafe(32)
        self.pending_verifications[session_id] = {
            'code': code,
            'email': email,
            'username': username,
            'created_at': datetime.now(),
            'attempts': 0
        }

        # In production, send via SendGrid/AWS SES
        logger.info(f"Email code generated for {email}: {code}")

        return session_id

    def verify_email_code(self, session_id: str, code: str) -> bool:
        """Verify email code"""
        if session_id not in self.pending_verifications:
            return False

        verification = self.pending_verifications[session_id]

        # Check expiration (10 minutes)
        if datetime.now() - verification['created_at'] > timedelta(minutes=10):
            del self.pending_verifications[session_id]
            return False

        # Check attempts
        verification['attempts'] += 1
        if verification['attempts'] > 3:
            del self.pending_verifications[session_id]
            return False

        # Verify code
        if verification['code'] == code:
            del self.pending_verifications[session_id]
            return True

        return False

# Initialize managers
totp_manager = TOTPManager()
backup_codes_manager = BackupCodesManager()
sms_manager = SMSVerificationManager()
email_manager = EmailVerificationManager()

# API Endpoints

@mfa_blueprint.route('/enroll', methods=['POST'])
@jwt_required()
def enroll_mfa():
    """Enroll in MFA"""
    try:
        current_user = get_jwt_identity()

        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400

        schema = MFAEnrollSchema()
        data = schema.load(request.json)

        method = data['method']

        if method == 'totp':
            # Generate TOTP secret and QR code
            result = totp_manager.generate_secret(current_user)

            # Generate backup codes
            backup_code_list = backup_codes_manager.generate_backup_codes(current_user)

            return jsonify({
                'method': 'totp',
                'secret': result['secret'],
                'qr_code': result['qr_code'],
                'manual_entry_key': result['manual_entry_key'],
                'backup_codes': backup_code_list,
                'message': 'Scan QR code with authenticator app and verify with a code'
            }), 200

        elif method == 'sms':
            phone_number = data.get('phone_number')
            if not phone_number:
                return jsonify({'error': 'Phone number required for SMS MFA'}), 400

            session_id = sms_manager.send_sms_code(phone_number, current_user)

            return jsonify({
                'method': 'sms',
                'session_id': session_id,
                'message': 'Verification code sent to your phone'
            }), 200

        elif method == 'email':
            email = data.get('email')
            if not email:
                return jsonify({'error': 'Email required for email MFA'}), 400

            session_id = email_manager.send_email_code(email, current_user)

            return jsonify({
                'method': 'email',
                'session_id': session_id,
                'message': 'Verification code sent to your email'
            }), 200

    except ValidationError as e:
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        logger.error(f"MFA enrollment error: {e}")
        return jsonify({'error': 'MFA enrollment failed'}), 500

@mfa_blueprint.route('/verify', methods=['POST'])
@jwt_required()
def verify_mfa():
    """Verify MFA code during enrollment"""
    try:
        current_user = get_jwt_identity()

        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400

        schema = MFAVerifySchema()
        data = schema.load(request.json)

        code = data['code']
        method = request.json.get('method', 'totp')

        if method == 'totp':
            # Verify TOTP and enable it
            is_valid = totp_manager.verify_totp(current_user, code, enable_on_success=True)

            if is_valid:
                return jsonify({
                    'message': 'TOTP MFA enabled successfully',
                    'mfa_enabled': True
                }), 200
            else:
                return jsonify({'error': 'Invalid verification code'}), 401

        elif method == 'sms':
            session_id = data.get('session_id')
            if not session_id:
                return jsonify({'error': 'Session ID required'}), 400

            is_valid = sms_manager.verify_sms_code(session_id, code)

            if is_valid:
                return jsonify({
                    'message': 'SMS MFA verified successfully',
                    'mfa_enabled': True
                }), 200
            else:
                return jsonify({'error': 'Invalid or expired code'}), 401

        elif method == 'email':
            session_id = data.get('session_id')
            if not session_id:
                return jsonify({'error': 'Session ID required'}), 400

            is_valid = email_manager.verify_email_code(session_id, code)

            if is_valid:
                return jsonify({
                    'message': 'Email MFA verified successfully',
                    'mfa_enabled': True
                }), 200
            else:
                return jsonify({'error': 'Invalid or expired code'}), 401

    except ValidationError as e:
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        return jsonify({'error': 'MFA verification failed'}), 500

@mfa_blueprint.route('/verify-login', methods=['POST'])
def verify_mfa_login():
    """Verify MFA during login (no JWT required)"""
    try:
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400

        username = request.json.get('username')
        code = request.json.get('code')

        if not username or not code:
            return jsonify({'error': 'Username and code required'}), 400

        # Try TOTP verification
        if totp_manager.is_totp_enabled(username):
            is_valid = totp_manager.verify_totp(username, code)
            if is_valid:
                return jsonify({
                    'mfa_verified': True,
                    'message': 'MFA verification successful'
                }), 200

        # Try backup code
        is_backup_code = backup_codes_manager.verify_backup_code(username, code)
        if is_backup_code:
            remaining = backup_codes_manager.get_remaining_codes_count(username)
            return jsonify({
                'mfa_verified': True,
                'message': 'Backup code accepted',
                'remaining_backup_codes': remaining,
                'warning': 'Backup code used. Generate new codes if running low.'
            }), 200

        return jsonify({'error': 'Invalid MFA code'}), 401

    except Exception as e:
        logger.error(f"MFA login verification error: {e}")
        return jsonify({'error': 'MFA verification failed'}), 500

@mfa_blueprint.route('/status', methods=['GET'])
@jwt_required()
def mfa_status():
    """Get MFA status for current user"""
    try:
        current_user = get_jwt_identity()

        totp_enabled = totp_manager.is_totp_enabled(current_user)
        remaining_backups = backup_codes_manager.get_remaining_codes_count(current_user)

        return jsonify({
            'mfa_enabled': totp_enabled,
            'methods': {
                'totp': totp_enabled,
                'backup_codes': remaining_backups > 0
            },
            'remaining_backup_codes': remaining_backups
        }), 200

    except Exception as e:
        logger.error(f"MFA status error: {e}")
        return jsonify({'error': 'Failed to retrieve MFA status'}), 500

@mfa_blueprint.route('/disable', methods=['POST'])
@jwt_required()
def disable_mfa():
    """Disable MFA (requires password confirmation)"""
    try:
        current_user = get_jwt_identity()

        # In production, require password confirmation
        password = request.json.get('password')
        if not password:
            return jsonify({'error': 'Password confirmation required'}), 400

        # Remove MFA secrets
        if current_user in mfa_secrets:
            del mfa_secrets[current_user]

        if current_user in backup_codes:
            del backup_codes[current_user]

        logger.info(f"MFA disabled for user: {current_user}")

        return jsonify({
            'message': 'MFA disabled successfully',
            'warning': 'Your account is now less secure'
        }), 200

    except Exception as e:
        logger.error(f"MFA disable error: {e}")
        return jsonify({'error': 'Failed to disable MFA'}), 500

@mfa_blueprint.route('/regenerate-backup-codes', methods=['POST'])
@jwt_required()
def regenerate_backup_codes():
    """Regenerate backup codes"""
    try:
        current_user = get_jwt_identity()

        # Check if TOTP is enabled
        if not totp_manager.is_totp_enabled(current_user):
            return jsonify({'error': 'MFA must be enabled first'}), 400

        # Generate new backup codes
        new_codes = backup_codes_manager.generate_backup_codes(current_user)

        return jsonify({
            'backup_codes': new_codes,
            'message': 'New backup codes generated. Save them securely.',
            'warning': 'Old backup codes are now invalid'
        }), 200

    except Exception as e:
        logger.error(f"Backup codes regeneration error: {e}")
        return jsonify({'error': 'Failed to regenerate backup codes'}), 500

# Helper functions for integration with auth module

def is_mfa_enabled(username: str) -> bool:
    """Check if MFA is enabled for user"""
    return totp_manager.is_totp_enabled(username)

def verify_mfa_code(username: str, code: str) -> bool:
    """Verify MFA code (TOTP or backup code)"""
    # Try TOTP
    if totp_manager.verify_totp(username, code):
        return True

    # Try backup code
    if backup_codes_manager.verify_backup_code(username, code):
        return True

    return False
