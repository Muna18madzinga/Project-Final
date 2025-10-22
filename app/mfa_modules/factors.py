"""
Authentication factors implementation for multi-factor authentication.
"""
from enum import Enum
from abc import ABC, abstractmethod
from .totp import TOTPManager

class FactorType(Enum):
    """Enumeration of supported authentication factor types."""
    PASSWORD = "password"
    TOTP = "totp"
    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    BIOMETRIC = "biometric"

class AuthenticationFactor(ABC):
    """Abstract base class for authentication factors."""
    
    @abstractmethod
    def verify(self, user_id, credential):
        """Verify the provided credential for this factor."""
        pass
    
    @abstractmethod
    def setup(self, user_id, **kwargs):
        """Set up this factor for a user."""
        pass

class PasswordFactor(AuthenticationFactor):
    """Password-based authentication factor."""
    
    def __init__(self, password_service):
        self.password_service = password_service
    
    def verify(self, user_id, credential):
        return self.password_service.verify_password(user_id, credential)
    
    def setup(self, user_id, **kwargs):
        password = kwargs.get('password')
        if not password:
            raise ValueError("Password is required")
        return self.password_service.set_password(user_id, password)

class TOTPFactor(AuthenticationFactor):
    """Time-based One-Time Password authentication factor."""
    
    def __init__(self, totp_store):
        self.totp_store = totp_store
        self.totp_manager = TOTPManager()
    
    def verify(self, user_id, credential):
        secret = self.totp_store.get_secret(user_id)
        if not secret:
            return False
        return self.totp_manager.verify_totp(secret, credential)
    
    def setup(self, user_id, **kwargs):
        secret = self.totp_manager.generate_secret()
        self.totp_store.save_secret(user_id, secret)
        email = kwargs.get('email', user_id)
        qr_code = self.totp_manager.generate_qr_code(email, secret)
        return {
            'secret': secret,
            'qr_code': qr_code
        }

# Factory pattern for creating authentication factors
class FactorFactory:
    """Factory for creating authentication factor instances."""
    
    @staticmethod
    def create_factor(factor_type, **services):
        """Create an authentication factor of the specified type."""
        if factor_type == FactorType.PASSWORD:
            return PasswordFactor(services.get('password_service'))
        elif factor_type == FactorType.TOTP:
            return TOTPFactor(services.get('totp_store'))
        else:
            raise ValueError(f"Unsupported factor type: {factor_type}")
