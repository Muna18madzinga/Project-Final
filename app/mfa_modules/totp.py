"""
Time-based One-Time Password (TOTP) implementation for MFA.
"""
import os
import pyotp
import qrcode
from io import BytesIO
import base64

class TOTPManager:
    """Manages Time-based One-Time Password generation and verification."""
    
    @staticmethod
    def generate_secret():
        """Generate a new TOTP secret key."""
        return pyotp.random_base32()
    
    @staticmethod
    def verify_totp(secret, token):
        """Verify a TOTP token against the user's secret."""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    
    @staticmethod
    def generate_qr_code(email, secret, issuer="Adaptive Security Suite"):
        """Generate a QR code for TOTP setup."""
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=email, issuer_name=issuer)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered)
        return base64.b64encode(buffered.getvalue()).decode('utf-8')
