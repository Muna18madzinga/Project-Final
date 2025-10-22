"""
Unit tests for authentication module
"""
import pytest
import json
from datetime import datetime, timedelta
from models import User, db
from tests.conftest import assert_valid_jwt_response, assert_error_response, assert_security_headers

class TestAuthRegistration:
    """Test user registration functionality."""
    
    def test_successful_registration(self, client, sample_user):
        """Test successful user registration."""
        response = client.post('/auth/register', 
                             json=sample_user,
                             content_type='application/json')
        
        assert response.status_code == 201
        data = response.get_json()
        assert data['message'] == 'User registered successfully'
        assert_security_headers(response)
        
        # Verify user was created in database
        user = User.query.filter_by(username=sample_user['username']).first()
        assert user is not None
        assert user.email == sample_user['email']
        assert user.is_active == True

    def test_duplicate_username_registration(self, client, sample_user):
        """Test registration with duplicate username."""
        # Register user first time
        client.post('/auth/register', json=sample_user, content_type='application/json')
        
        # Try to register again
        response = client.post('/auth/register', json=sample_user, content_type='application/json')
        assert_error_response(response, 409, "Username already exists")

    def test_weak_password_registration(self, client):
        """Test registration with weak password."""
        weak_user = {
            'username': 'testuser',
            'password': 'weak',  # Too short, no complexity
            'email': 'test@example.com'
        }
        response = client.post('/auth/register', json=weak_user, content_type='application/json')
        assert_error_response(response, 400, "Password validation failed")

    def test_invalid_email_registration(self, client):
        """Test registration with invalid email."""
        invalid_email_user = {
            'username': 'testuser',
            'password': 'ValidPassword123!@#',
            'email': 'invalid-email'
        }
        response = client.post('/auth/register', json=invalid_email_user, content_type='application/json')
        assert_error_response(response, 400)

    def test_missing_fields_registration(self, client):
        """Test registration with missing required fields."""
        incomplete_user = {'username': 'testuser'}
        response = client.post('/auth/register', json=incomplete_user, content_type='application/json')
        assert_error_response(response, 400)

    def test_invalid_username_characters(self, client):
        """Test registration with invalid username characters."""
        invalid_user = {
            'username': 'test@user!',  # Invalid characters
            'password': 'ValidPassword123!@#',
            'email': 'test@example.com'
        }
        response = client.post('/auth/register', json=invalid_user, content_type='application/json')
        assert_error_response(response, 400)

class TestAuthLogin:
    """Test user login functionality."""
    
    def test_successful_login(self, client, create_test_user):
        """Test successful user login."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        login_data = {'username': username, 'password': password}
        response = client.post('/auth/login', json=login_data, content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Login successful'
        assert_valid_jwt_response(data)

    def test_invalid_credentials_login(self, client, create_test_user):
        """Test login with invalid credentials."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        # Wrong password
        login_data = {'username': username, 'password': 'WrongPassword'}
        response = client.post('/auth/login', json=login_data, content_type='application/json')
        assert_error_response(response, 401, "Invalid credentials")

    def test_nonexistent_user_login(self, client):
        """Test login with non-existent user."""
        login_data = {'username': 'nonexistent', 'password': 'AnyPassword123!'}
        response = client.post('/auth/login', json=login_data, content_type='application/json')
        assert_error_response(response, 401, "Invalid credentials")

    def test_account_lockout(self, client, create_test_user):
        """Test account lockout after multiple failed attempts."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        # Make multiple failed login attempts
        login_data = {'username': username, 'password': 'WrongPassword'}
        for _ in range(6):  # More than max allowed (5)
            client.post('/auth/login', json=login_data, content_type='application/json')
        
        # Account should be locked now
        response = client.post('/auth/login', json=login_data, content_type='application/json')
        assert_error_response(response, 423, "Account temporarily locked")

    def test_missing_login_fields(self, client):
        """Test login with missing fields."""
        # Missing password
        response = client.post('/auth/login', json={'username': 'test'}, content_type='application/json')
        assert_error_response(response, 400, "Username and password required")

    def test_inactive_user_login(self, client, create_test_user, app_context):
        """Test login with inactive user account."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        user = create_test_user(username=username, password=password)
        
        # Deactivate user
        user.is_active = False
        db.session.commit()
        
        login_data = {'username': username, 'password': password}
        response = client.post('/auth/login', json=login_data, content_type='application/json')
        assert_error_response(response, 403, "Account is disabled")

class TestAuthTokens:
    """Test JWT token functionality."""
    
    def test_token_refresh(self, client, create_test_user):
        """Test JWT token refresh."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        # Login to get tokens
        login_data = {'username': username, 'password': password}
        login_response = client.post('/auth/login', json=login_data, content_type='application/json')
        tokens = login_response.get_json()
        
        # Use refresh token to get new access token
        headers = {'Authorization': f'Bearer {tokens["refresh_token"]}'}
        response = client.post('/auth/refresh', headers=headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data

    def test_logout(self, client, auth_headers):
        """Test user logout."""
        headers = auth_headers()
        response = client.post('/auth/logout', headers=headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Successfully logged out'

    def test_protected_profile_access(self, client, auth_headers, create_test_user):
        """Test access to protected profile endpoint."""
        username = 'testuser'
        email = 'test@example.com'
        create_test_user(username=username, email=email)
        headers = auth_headers(username=username)
        
        response = client.get('/auth/profile', headers=headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['username'] == username
        assert data['email'] == email

    def test_unauthorized_profile_access(self, client):
        """Test unauthorized access to profile endpoint."""
        response = client.get('/auth/profile')
        assert_error_response(response, 401, "Authorization token is required")

    def test_invalid_token_access(self, client):
        """Test access with invalid token."""
        headers = {'Authorization': 'Bearer invalid_token_here'}
        response = client.get('/auth/profile', headers=headers)
        assert_error_response(response, 401, "Invalid token")

class TestPasswordValidation:
    """Test password validation functionality."""
    
    @pytest.mark.parametrize("password,expected_valid", [
        ("ValidPassword123!@#", True),      # Valid password
        ("short", False),                   # Too short
        ("nouppercase123!", False),         # No uppercase
        ("NOLOWERCASE123!", False),         # No lowercase
        ("NoNumbers!@#", False),            # No numbers
        ("NoSpecialChars123", False),       # No special chars
        ("ValidButTooShort1!", False),      # Less than 12 chars
        ("AnotherValidPassword456$", True), # Valid password
    ])
    def test_password_strength_validation(self, client, password, expected_valid):
        """Test password strength validation with various passwords."""
        user_data = {
            'username': 'testuser',
            'password': password,
            'email': 'test@example.com'
        }
        response = client.post('/auth/register', json=user_data, content_type='application/json')
        
        if expected_valid:
            assert response.status_code == 201
        else:
            assert response.status_code == 400

class TestSecurityHeaders:
    """Test security headers in authentication responses."""
    
    def test_registration_security_headers(self, client, sample_user):
        """Test security headers in registration response."""
        response = client.post('/auth/register', json=sample_user, content_type='application/json')
        assert_security_headers(response)

    def test_login_security_headers(self, client, create_test_user):
        """Test security headers in login response."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        login_data = {'username': username, 'password': password}
        response = client.post('/auth/login', json=login_data, content_type='application/json')
        assert_security_headers(response)

class TestPerformance:
    """Test authentication performance."""
    
    def test_registration_performance(self, client, sample_user, perf_timer):
        """Test registration performance."""
        with perf_timer("Registration"):
            response = client.post('/auth/register', json=sample_user, content_type='application/json')
        assert response.status_code == 201

    def test_login_performance(self, client, create_test_user, perf_timer):
        """Test login performance."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        login_data = {'username': username, 'password': password}
        with perf_timer("Login"):
            response = client.post('/auth/login', json=login_data, content_type='application/json')
        assert response.status_code == 200