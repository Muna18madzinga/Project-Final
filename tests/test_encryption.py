"""
Integration tests for encryption module
"""
import pytest
import json
import base64
from cryptography.fernet import Fernet
from tests.conftest import assert_error_response, assert_security_headers

class TestEncryptionEndpoints:
    """Test encryption API endpoints."""
    
    def test_encrypt_success(self, client, auth_headers, sample_encryption_data):
        """Test successful data encryption."""
        headers = auth_headers()
        data = {'data': sample_encryption_data['short_text']}
        
        response = client.post('/encryption/encrypt', 
                             json=data, 
                             headers=headers, 
                             content_type='application/json')
        
        assert response.status_code == 200
        response_data = response.get_json()
        assert 'encrypted' in response_data
        assert 'message' in response_data
        assert response_data['message'] == 'Data encrypted successfully'
        
        # Verify encrypted data is base64 encoded Fernet token
        encrypted = response_data['encrypted']
        assert len(encrypted) > 20
        assert encrypted.startswith('gAAAAA')  # Fernet token prefix

    def test_decrypt_success(self, client, auth_headers, sample_encryption_data):
        """Test successful data decryption."""
        headers = auth_headers()
        original_data = sample_encryption_data['short_text']
        
        # First encrypt the data
        encrypt_response = client.post('/encryption/encrypt', 
                                     json={'data': original_data}, 
                                     headers=headers, 
                                     content_type='application/json')
        encrypted_data = encrypt_response.get_json()['encrypted']
        
        # Then decrypt it
        decrypt_response = client.post('/encryption/decrypt',
                                     json={'encrypted': encrypted_data},
                                     headers=headers,
                                     content_type='application/json')
        
        assert decrypt_response.status_code == 200
        decrypted_data = decrypt_response.get_json()
        assert decrypted_data['decrypted'] == original_data
        assert decrypted_data['message'] == 'Data decrypted successfully'

    def test_encrypt_various_data_types(self, client, auth_headers, sample_encryption_data):
        """Test encryption with various data types."""
        headers = auth_headers()
        
        test_cases = [
            sample_encryption_data['short_text'],
            sample_encryption_data['long_text'],
            sample_encryption_data['special_chars'],
            sample_encryption_data['unicode'],
            sample_encryption_data['json_data']
        ]
        
        for test_data in test_cases:
            response = client.post('/encryption/encrypt',
                                 json={'data': test_data},
                                 headers=headers,
                                 content_type='application/json')
            
            assert response.status_code == 200
            encrypted = response.get_json()['encrypted']
            assert len(encrypted) > 0

    def test_round_trip_encryption(self, client, auth_headers, sample_encryption_data):
        """Test complete encrypt-decrypt round trip for various data."""
        headers = auth_headers()
        
        test_cases = [
            sample_encryption_data['short_text'],
            sample_encryption_data['long_text'], 
            sample_encryption_data['special_chars'],
            sample_encryption_data['unicode'],
            sample_encryption_data['json_data']
        ]
        
        for original_data in test_cases:
            # Encrypt
            encrypt_response = client.post('/encryption/encrypt',
                                         json={'data': original_data},
                                         headers=headers,
                                         content_type='application/json')
            encrypted_data = encrypt_response.get_json()['encrypted']
            
            # Decrypt
            decrypt_response = client.post('/encryption/decrypt',
                                         json={'encrypted': encrypted_data},
                                         headers=headers,
                                         content_type='application/json')
            
            decrypted_data = decrypt_response.get_json()['decrypted']
            assert decrypted_data == original_data

class TestEncryptionSecurity:
    """Test encryption security features."""
    
    def test_encrypt_requires_authentication(self, client, sample_encryption_data):
        """Test that encryption requires authentication."""
        data = {'data': sample_encryption_data['short_text']}
        response = client.post('/encryption/encrypt', 
                             json=data, 
                             content_type='application/json')
        assert_error_response(response, 401, "Authorization token is required")

    def test_decrypt_requires_authentication(self, client):
        """Test that decryption requires authentication."""
        data = {'encrypted': 'fake_encrypted_data'}
        response = client.post('/encryption/decrypt', 
                             json=data, 
                             content_type='application/json')
        assert_error_response(response, 401, "Authorization token is required")

    def test_decrypt_invalid_token(self, client, auth_headers):
        """Test decryption with invalid encrypted token."""
        headers = auth_headers()
        data = {'encrypted': 'invalid_encrypted_token'}
        
        response = client.post('/encryption/decrypt',
                             json=data,
                             headers=headers,
                             content_type='application/json')
        
        assert_error_response(response, 400, "Invalid encrypted data")

    def test_encrypt_empty_data(self, client, auth_headers):
        """Test encryption of empty data."""
        headers = auth_headers()
        data = {'data': ''}
        
        response = client.post('/encryption/encrypt',
                             json=data,
                             headers=headers,
                             content_type='application/json')
        
        assert_error_response(response, 400, "Validation failed")

    def test_encrypt_missing_data_field(self, client, auth_headers):
        """Test encryption with missing data field."""
        headers = auth_headers()
        response = client.post('/encryption/encrypt',
                             json={},
                             headers=headers,
                             content_type='application/json')
        
        assert_error_response(response, 400, "Validation failed")

    def test_decrypt_missing_encrypted_field(self, client, auth_headers):
        """Test decryption with missing encrypted field."""
        headers = auth_headers()
        response = client.post('/encryption/decrypt',
                             json={},
                             headers=headers,
                             content_type='application/json')
        
        assert_error_response(response, 400, "Validation failed")

class TestEncryptionKeyInfo:
    """Test encryption key information endpoint."""
    
    def test_key_info_success(self, client, auth_headers):
        """Test successful key info retrieval."""
        headers = auth_headers()
        response = client.get('/encryption/key-info', headers=headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'key_source' in data
        assert 'algorithm' in data
        assert 'key_length' in data
        assert 'user' in data
        assert data['algorithm'] == 'Fernet (AES 128)'
        assert data['key_length'] == '256 bits'

    def test_key_info_requires_authentication(self, client):
        """Test that key info requires authentication."""
        response = client.get('/encryption/key-info')
        assert_error_response(response, 401, "Authorization token is required")

class TestEncryptionValidation:
    """Test input validation for encryption endpoints."""
    
    def test_encrypt_non_json_request(self, client, auth_headers):
        """Test encryption with non-JSON request."""
        headers = auth_headers()
        response = client.post('/encryption/encrypt',
                             data='not json data',
                             headers=headers,
                             content_type='text/plain')
        
        assert_error_response(response, 400, "Request must be JSON")

    def test_decrypt_non_json_request(self, client, auth_headers):
        """Test decryption with non-JSON request."""
        headers = auth_headers()
        response = client.post('/encryption/decrypt',
                             data='not json data',
                             headers=headers,
                             content_type='text/plain')
        
        assert_error_response(response, 400, "Request must be JSON")

    def test_encrypt_whitespace_only_data(self, client, auth_headers, sample_encryption_data):
        """Test encryption with whitespace-only data."""
        headers = auth_headers()
        data = {'data': sample_encryption_data['whitespace']}
        
        response = client.post('/encryption/encrypt',
                             json=data,
                             headers=headers,
                             content_type='application/json')
        
        assert_error_response(response, 400, "Validation failed")

class TestEncryptionPerformance:
    """Test encryption performance."""
    
    def test_encrypt_performance(self, client, auth_headers, sample_encryption_data, perf_timer):
        """Test encryption performance."""
        headers = auth_headers()
        data = {'data': sample_encryption_data['long_text']}
        
        with perf_timer("Encryption"):
            response = client.post('/encryption/encrypt',
                                 json=data,
                                 headers=headers,
                                 content_type='application/json')
        
        assert response.status_code == 200

    def test_decrypt_performance(self, client, auth_headers, sample_encryption_data, perf_timer):
        """Test decryption performance."""
        headers = auth_headers()
        original_data = sample_encryption_data['long_text']
        
        # First encrypt
        encrypt_response = client.post('/encryption/encrypt',
                                     json={'data': original_data},
                                     headers=headers,
                                     content_type='application/json')
        encrypted_data = encrypt_response.get_json()['encrypted']
        
        # Then time the decryption
        with perf_timer("Decryption"):
            response = client.post('/encryption/decrypt',
                                 json={'encrypted': encrypted_data},
                                 headers=headers,
                                 content_type='application/json')
        
        assert response.status_code == 200

    def test_multiple_operations_performance(self, client, auth_headers, sample_encryption_data, perf_timer):
        """Test performance of multiple encryption operations."""
        headers = auth_headers()
        test_data = sample_encryption_data['short_text']
        
        with perf_timer("100 Encryption Operations"):
            for _ in range(100):
                response = client.post('/encryption/encrypt',
                                     json={'data': test_data},
                                     headers=headers,
                                     content_type='application/json')
                assert response.status_code == 200

class TestEncryptionSecurityHeaders:
    """Test security headers in encryption responses."""
    
    def test_encrypt_security_headers(self, client, auth_headers, sample_encryption_data):
        """Test security headers in encryption response."""
        headers = auth_headers()
        data = {'data': sample_encryption_data['short_text']}
        
        response = client.post('/encryption/encrypt',
                             json=data,
                             headers=headers,
                             content_type='application/json')
        
        assert_security_headers(response)

    def test_decrypt_security_headers(self, client, auth_headers, sample_encryption_data):
        """Test security headers in decryption response."""
        headers = auth_headers()
        original_data = sample_encryption_data['short_text']
        
        # Encrypt first
        encrypt_response = client.post('/encryption/encrypt',
                                     json={'data': original_data},
                                     headers=headers,
                                     content_type='application/json')
        encrypted_data = encrypt_response.get_json()['encrypted']
        
        # Decrypt and check headers
        decrypt_response = client.post('/encryption/decrypt',
                                     json={'encrypted': encrypted_data},
                                     headers=headers,
                                     content_type='application/json')
        
        assert_security_headers(decrypt_response)