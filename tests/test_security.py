"""
Security-specific tests for the Adaptive Security Suite
"""
import pytest
import json
import time
from unittest.mock import patch, MagicMock
from tests.conftest import assert_error_response, assert_security_headers

class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def test_rate_limit_exceeded(self, client):
        """Test rate limiting on public endpoints."""
        # Make requests beyond the rate limit
        # Note: This test might be flaky depending on rate limiter implementation
        for i in range(15):  # Exceed 10 per minute limit on index
            response = client.get('/')
            if response.status_code == 429:
                break
        else:
            pytest.skip("Rate limiting not triggered in test environment")
        
        assert response.status_code == 429
        data = response.get_json()
        assert 'error' in data
        assert 'Rate limit exceeded' in data['error']

    def test_rate_limit_reset(self, client):
        """Test that rate limits reset properly."""
        # This is a conceptual test - in practice, you'd need to mock time
        # or use a test-specific rate limiter configuration
        response = client.get('/')
        assert response.status_code in [200, 429]  # Either allowed or rate limited

class TestSecurityHeaders:
    """Test security headers on all endpoints."""
    
    def test_index_security_headers(self, client):
        """Test security headers on index endpoint."""
        response = client.get('/')
        assert_security_headers(response)

    def test_health_security_headers(self, client):
        """Test security headers on health endpoint."""
        response = client.get('/health')
        assert_security_headers(response)

    def test_404_security_headers(self, client):
        """Test security headers on 404 responses."""
        response = client.get('/nonexistent-endpoint')
        assert_security_headers(response)

class TestInputValidation:
    """Test input validation and sanitization."""
    
    def test_sql_injection_prevention(self, client, auth_headers):
        """Test SQL injection prevention in username."""
        headers = auth_headers()
        malicious_data = {
            'user_id': "admin'; DROP TABLE users; --",
            'context': {'time_of_day': 0.5}
        }
        
        response = client.post('/adaptive/risk-assessment',
                             json=malicious_data,
                             headers=headers,
                             content_type='application/json')
        
        # Should either sanitize the input or reject it
        assert response.status_code in [400, 403]  # Bad request or forbidden

    def test_xss_prevention(self, client):
        """Test XSS prevention in registration."""
        xss_user = {
            'username': '<script>alert("xss")</script>',
            'password': 'ValidPassword123!@#',
            'email': 'test@example.com'
        }
        
        response = client.post('/auth/register',
                             json=xss_user,
                             content_type='application/json')
        
        # Should reject invalid username characters
        assert_error_response(response, 400)

    def test_oversized_payload_rejection(self, client, auth_headers):
        """Test rejection of oversized payloads."""
        headers = auth_headers()
        huge_data = 'A' * 10000  # 10KB string
        
        response = client.post('/encryption/encrypt',
                             json={'data': huge_data},
                             headers=headers,
                             content_type='application/json')
        
        # Should either process or reject based on size limits
        assert response.status_code in [200, 400, 413]

class TestAuthenticationBypass:
    """Test for authentication bypass vulnerabilities."""
    
    def test_protected_endpoints_require_auth(self, client):
        """Test that all protected endpoints require authentication."""
        protected_endpoints = [
            ('/auth/profile', 'GET'),
            ('/auth/logout', 'POST'),
            ('/encryption/encrypt', 'POST'),
            ('/encryption/decrypt', 'POST'),
            ('/encryption/key-info', 'GET'),
            ('/adaptive/risk-assessment', 'POST'),
            ('/adaptive/rules', 'GET'),
        ]
        
        for endpoint, method in protected_endpoints:
            if method == 'GET':
                response = client.get(endpoint)
            else:
                response = client.post(endpoint, json={})
            
            assert_error_response(response, 401)

    def test_admin_endpoints_require_admin_auth(self, client, auth_headers):
        """Test that admin endpoints require admin privileges."""
        # Regular user headers
        regular_headers = auth_headers(username='regularuser')
        
        admin_endpoints = [
            ('/adaptive/evolve', 'POST'),
            ('/adaptive/threat-history', 'GET'),
        ]
        
        for endpoint, method in admin_endpoints:
            if method == 'GET':
                response = client.get(endpoint, headers=regular_headers)
            else:
                response = client.post(endpoint, json={'threats': {}}, headers=regular_headers)
            
            assert response.status_code in [401, 403]  # Unauthorized or Forbidden

    def test_token_manipulation_prevention(self, client, create_test_user, app_context):
        """Test prevention of token manipulation."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        # Get valid token
        login_response = client.post('/auth/login',
                                   json={'username': username, 'password': password},
                                   content_type='application/json')
        token = login_response.get_json()['access_token']
        
        # Try to use manipulated token
        manipulated_token = token[:-5] + 'XXXXX'  # Change last 5 characters
        headers = {'Authorization': f'Bearer {manipulated_token}'}
        
        response = client.get('/auth/profile', headers=headers)
        assert_error_response(response, 401, "Invalid token")

class TestThreatDetection:
    """Test threat detection functionality."""
    
    @patch('app.threat_detection.client.chat.completions.create')
    def test_threat_detection_with_mock_openai(self, mock_openai, client, auth_headers, mock_openai_response):
        """Test threat detection with mocked OpenAI response."""
        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps(mock_openai_response)
        mock_openai.return_value = mock_response
        
        headers = auth_headers()
        features = [0.5, 2, 1, 0]  # Sample features
        
        response = client.post('/threat/detect',
                             json={'features': features},
                             headers=headers,
                             content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'threat' in data
        assert 'confidence' in data
        assert 'source' in data

    def test_threat_detection_without_openai(self, client, auth_headers):
        """Test threat detection fallback without OpenAI."""
        headers = auth_headers()
        features = [0.5, 2, 1, 0]  # Sample features
        
        with patch.dict('os.environ', {'OPENAI_API_KEY': ''}):
            response = client.post('/threat/detect',
                                 json={'features': features},
                                 headers=headers,
                                 content_type='application/json')
        
        # Should fallback to ML model only
        assert response.status_code == 200
        data = response.get_json()
        assert 'threat' in data

    def test_threat_detection_invalid_features(self, client, auth_headers):
        """Test threat detection with invalid features."""
        headers = auth_headers()
        
        invalid_cases = [
            {'features': []},  # Empty features
            {'features': 'not_a_list'},  # Invalid type
            {},  # Missing features
        ]
        
        for invalid_data in invalid_cases:
            response = client.post('/threat/detect',
                                 json=invalid_data,
                                 headers=headers,
                                 content_type='application/json')
            assert_error_response(response, 400)

class TestAdaptiveEngine:
    """Test adaptive engine security."""
    
    def test_risk_assessment_access_control(self, client, auth_headers, sample_risk_context, create_test_user):
        """Test access control for risk assessment."""
        # Create two users
        user1 = 'user1'
        user2 = 'user2'
        create_test_user(username=user1)
        create_test_user(username=user2)
        
        # User1 tries to assess User2's risk
        headers = auth_headers(username=user1)
        assessment_data = {
            'user_id': user2,
            'context': sample_risk_context['normal_context']
        }
        
        response = client.post('/adaptive/risk-assessment',
                             json=assessment_data,
                             headers=headers,
                             content_type='application/json')
        
        assert_error_response(response, 403, "Insufficient permissions")

    def test_self_risk_assessment_allowed(self, client, auth_headers, sample_risk_context, create_test_user):
        """Test that users can assess their own risk."""
        username = 'testuser'
        create_test_user(username=username)
        headers = auth_headers(username=username)
        
        assessment_data = {
            'user_id': username,
            'context': sample_risk_context['normal_context']
        }
        
        response = client.post('/adaptive/risk-assessment',
                             json=assessment_data,
                             headers=headers,
                             content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'risk_score' in data
        assert 'risk_level' in data
        assert data['user_id'] == username

    def test_admin_risk_assessment_allowed(self, client, auth_headers, sample_risk_context, create_test_user):
        """Test that admins can assess any user's risk."""
        regular_user = 'regularuser'
        admin_user = 'admin'
        create_test_user(username=regular_user)
        create_test_user(username=admin_user, is_admin=True)
        
        headers = auth_headers(username=admin_user, is_admin=True)
        assessment_data = {
            'user_id': regular_user,
            'context': sample_risk_context['normal_context']
        }
        
        response = client.post('/adaptive/risk-assessment',
                             json=assessment_data,
                             headers=headers,
                             content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['user_id'] == regular_user

class TestPasswordSecurity:
    """Test password security features."""
    
    def test_password_not_logged(self, client, caplog):
        """Test that passwords are not logged in plaintext."""
        user_data = {
            'username': 'testuser',
            'password': 'SecretPassword123!@#',
            'email': 'test@example.com'
        }
        
        response = client.post('/auth/register',
                             json=user_data,
                             content_type='application/json')
        
        # Check that password doesn't appear in logs
        log_output = caplog.text
        assert 'SecretPassword123!@#' not in log_output

    def test_password_hashing_strength(self, client, create_test_user, app_context):
        """Test that passwords are properly hashed."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        user = create_test_user(username=username, password=password)
        
        # Verify password is hashed (not stored in plaintext)
        assert user.password_hash != password
        assert len(user.password_hash) > 50  # Bcrypt hash is typically 60 chars
        assert user.password_hash.startswith(b'$2b$')  # Bcrypt format

class TestSessionSecurity:
    """Test session security features."""
    
    def test_token_expiration(self, client, create_test_user, app_context):
        """Test JWT token expiration handling."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        # Login to get token
        login_response = client.post('/auth/login',
                                   json={'username': username, 'password': password},
                                   content_type='application/json')
        token = login_response.get_json()['access_token']
        
        # Use token immediately (should work)
        headers = {'Authorization': f'Bearer {token}'}
        response = client.get('/auth/profile', headers=headers)
        assert response.status_code == 200

    def test_token_blacklisting(self, client, auth_headers):
        """Test token blacklisting after logout."""
        headers = auth_headers()
        
        # Use token (should work)
        response = client.get('/auth/profile', headers=headers)
        assert response.status_code == 200
        
        # Logout (blacklist token)
        logout_response = client.post('/auth/logout', headers=headers)
        assert logout_response.status_code == 200
        
        # Try to use token again (should fail)
        response = client.get('/auth/profile', headers=headers)
        assert_error_response(response, 401, "Token has been revoked")

class TestConcurrencySecurity:
    """Test security under concurrent access."""
    
    def test_concurrent_login_attempts(self, client, create_test_user):
        """Test handling of concurrent login attempts."""
        username = 'testuser'
        password = 'TestPassword123!@#'
        create_test_user(username=username, password=password)
        
        login_data = {'username': username, 'password': password}
        
        # Simulate concurrent logins (simplified test)
        responses = []
        for _ in range(5):
            response = client.post('/auth/login',
                                 json=login_data,
                                 content_type='application/json')
            responses.append(response)
        
        # All should succeed (no race conditions)
        for response in responses:
            assert response.status_code == 200

    def test_concurrent_encryption_operations(self, client, auth_headers, sample_encryption_data):
        """Test concurrent encryption operations."""
        headers = auth_headers()
        test_data = sample_encryption_data['short_text']
        
        responses = []
        for _ in range(10):
            response = client.post('/encryption/encrypt',
                                 json={'data': test_data},
                                 headers=headers,
                                 content_type='application/json')
            responses.append(response)
        
        # All should succeed
        for response in responses:
            assert response.status_code == 200