"""
Test configuration and fixtures for the Adaptive Security Suite
"""
import os
import tempfile
import pytest
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token

# Set test environment variables before importing the app
os.environ['FLASK_ENV'] = 'testing'
os.environ['SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['JWT_SECRET_KEY'] = 'test-jwt-secret-key-for-testing-only'
os.environ['ENCRYPTION_PASSWORD'] = 'test-encryption-password'
os.environ['ENCRYPTION_SALT'] = 'test-encryption-salt'

from main import app
from models import db, User, SecurityLog, RiskAssessment, BlacklistedToken
import bcrypt

@pytest.fixture
def client():
    """Create a test client."""
    # Create a temporary database
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
        
    os.close(db_fd)
    os.unlink(app.config['DATABASE'])

@pytest.fixture
def app_context():
    """Create an application context."""
    with app.app_context():
        yield app

@pytest.fixture
def sample_user():
    """Create a sample user for testing."""
    return {
        'username': 'testuser',
        'password': 'TestPassword123!@#',
        'email': 'test@example.com'
    }

@pytest.fixture
def admin_user():
    """Create an admin user for testing."""
    return {
        'username': 'admin',
        'password': 'AdminPassword123!@#',
        'email': 'admin@example.com'
    }

@pytest.fixture
def create_test_user(client, app_context):
    """Create a test user in the database."""
    def _create_user(username='testuser', password='TestPassword123!@#', email='test@example.com', is_admin=False):
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=4))  # Lower rounds for testing
        user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            is_active=True,
            is_admin=is_admin,
            created_at=datetime.utcnow()
        )
        db.session.add(user)
        db.session.commit()
        return user
    return _create_user

@pytest.fixture
def auth_headers(client, create_test_user, app_context):
    """Get authentication headers for testing protected endpoints."""
    def _get_headers(username='testuser', is_admin=False):
        # Create user
        create_test_user(username=username, is_admin=is_admin)
        
        # Create access token
        with app.app_context():
            token = create_access_token(identity=username)
        
        return {'Authorization': f'Bearer {token}'}
    return _get_headers

@pytest.fixture
def sample_encryption_data():
    """Sample data for encryption tests."""
    return {
        'short_text': 'Hello World',
        'long_text': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.' * 10,
        'special_chars': 'Test with special chars: !@#$%^&*()_+-=[]{}|;:,.<>?',
        'unicode': 'Test unicode: 你好世界 🌍🔒',
        'json_data': '{"key": "value", "number": 42, "boolean": true}',
        'empty': '',
        'whitespace': '   \n\t   '
    }

@pytest.fixture
def sample_risk_context():
    """Sample risk assessment context data."""
    return {
        'normal_context': {
            'time_of_day': 0.5,  # Noon
            'failed_attempts': 0,
            'location_change': False,
            'device_change': False,
            'unusual_activity': 0,
            'request_frequency': 10
        },
        'high_risk_context': {
            'time_of_day': 0.1,  # Late night
            'failed_attempts': 5,
            'location_change': True,
            'device_change': True,
            'unusual_activity': 0.8,
            'request_frequency': 100
        },
        'medium_risk_context': {
            'time_of_day': 0.4,  # Morning
            'failed_attempts': 2,
            'location_change': False,
            'device_change': True,
            'unusual_activity': 0.3,
            'request_frequency': 30
        }
    }

@pytest.fixture
def sample_threat_data():
    """Sample threat intelligence data."""
    return {
        'failed_login_patterns': True,
        'password_attacks': True,
        'rate_limit_exceeded': True,
        'new_patterns': ['sql_injection_attempt', 'xss_attempt', 'brute_force']
    }

@pytest.fixture
def mock_openai_response():
    """Mock OpenAI API response for testing."""
    return {
        'is_threat': True,
        'confidence': 0.85
    }

# Custom assertions
def assert_valid_jwt_response(response_data):
    """Assert that response contains valid JWT tokens."""
    assert 'access_token' in response_data
    assert 'refresh_token' in response_data
    assert 'expires_in' in response_data
    assert isinstance(response_data['access_token'], str)
    assert len(response_data['access_token']) > 20

def assert_error_response(response, status_code, error_message=None):
    """Assert that response is an error with expected status code."""
    assert response.status_code == status_code
    data = response.get_json()
    assert 'error' in data
    if error_message:
        assert error_message in data['error']

def assert_security_headers(response):
    """Assert that response has proper security headers."""
    headers = response.headers
    assert headers.get('X-Content-Type-Options') == 'nosniff'
    assert headers.get('X-Frame-Options') == 'DENY'
    assert headers.get('X-XSS-Protection') == '1; mode=block'
    assert 'Strict-Transport-Security' in headers
    assert 'Content-Security-Policy' in headers

# Performance test helpers
class PerformanceTimer:
    """Context manager for timing operations."""
    def __init__(self, name):
        self.name = name
        self.start_time = None
        
    def __enter__(self):
        self.start_time = datetime.now()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        print(f"{self.name}: {duration:.3f} seconds")

@pytest.fixture
def perf_timer():
    """Performance timing fixture."""
    return PerformanceTimer