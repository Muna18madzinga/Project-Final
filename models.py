"""
Database models for the Adaptive Security Suite
"""
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and user management."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(30), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=True, index=True)
    password_hash = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class SecurityLog(db.Model):
    """Security activity logging."""
    __tablename__ = 'security_logs'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    activity_type = Column(String(50), nullable=False, index=True)
    user_id = Column(String(50), index=True)
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    details = Column(JSON)
    risk_score = Column(String(10))
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'activity_type': self.activity_type,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'details': self.details,
            'risk_score': self.risk_score
        }

class ThreatIntelligence(db.Model):
    """Store threat intelligence and adaptive security updates."""
    __tablename__ = 'threat_intelligence'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    threat_type = Column(String(50), nullable=False, index=True)
    threat_data = Column(JSON, nullable=False)
    severity = Column(String(20), default='medium')  # low, medium, high, critical
    source = Column(String(100))  # Source of threat intelligence
    applied = Column(Boolean, default=False)
    applied_at = Column(DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'threat_type': self.threat_type,
            'threat_data': self.threat_data,
            'severity': self.severity,
            'source': self.source,
            'applied': self.applied,
            'applied_at': self.applied_at.isoformat() if self.applied_at else None
        }

class RiskAssessment(db.Model):
    """Store user risk assessments."""
    __tablename__ = 'risk_assessments'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(50), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    risk_score = Column(String(10), nullable=False)
    risk_level = Column(String(20), nullable=False)  # low, medium, high
    context_data = Column(JSON)
    required_factors = Column(JSON)  # List of required auth factors
    assessed_by = Column(String(50))
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat(),
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'context_data': self.context_data,
            'required_factors': self.required_factors,
            'assessed_by': self.assessed_by
        }

class BlacklistedToken(db.Model):
    """Store blacklisted JWT tokens."""
    __tablename__ = 'blacklisted_tokens'
    
    id = Column(Integer, primary_key=True)
    jti = Column(String(36), unique=True, nullable=False, index=True)
    token_type = Column(String(20), nullable=False)  # access or refresh
    user_id = Column(String(50), nullable=False)
    revoked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'jti': self.jti,
            'token_type': self.token_type,
            'user_id': self.user_id,
            'revoked_at': self.revoked_at.isoformat(),
            'expires_at': self.expires_at.isoformat()
        }

def init_database(app):
    """Initialize database with Flask app."""
    with app.app_context():
        db.create_all()
        
        # Create default admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            from werkzeug.security import generate_password_hash
            admin_user = User(
                username='admin',
                email='admin@security.local',
                password_hash=generate_password_hash('ChangeMe123!@#'),
                is_admin=True,
                is_active=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created: admin / ChangeMe123!@#")
            print("IMPORTANT: Change the admin password immediately!")