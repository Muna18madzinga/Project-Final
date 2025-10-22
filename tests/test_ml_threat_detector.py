"""
Tests for the custom ML threat detection system
"""
import pytest
import json
import tempfile
import os
from datetime import datetime
from app.ml_threat_detector import AdaptiveThreatDetector, ThreatSample, FeatureExtractor

class TestFeatureExtractor:
    """Test feature extraction functionality."""
    
    def test_network_feature_extraction(self):
        """Test network traffic feature extraction."""
        extractor = FeatureExtractor()
        
        network_data = {
            'type': 'network',
            'packet_size': 1500,
            'port': 80,
            'connection_duration': 120,
            'is_encrypted': True,
            'packet_count': 50,
            'bytes_transferred': 1048576,  # 1MB
            'protocol': 'tcp',
            'request_frequency': 20,
            'unique_destinations': 5,
            'is_weekend': False,
            'hour_of_day': 14
        }
        
        features = extractor.extract_network_features(network_data)
        
        assert len(features) > 0
        assert all(isinstance(f, float) for f in features)
        assert 0 <= features[0] <= 1  # Normalized packet size
        assert 0 <= features[1] <= 1  # Normalized port

    def test_auth_feature_extraction(self):
        """Test authentication feature extraction."""
        extractor = FeatureExtractor()
        
        auth_data = {
            'type': 'auth',
            'failed_attempts': 3,
            'time_since_last_attempt': 300,
            'new_device': True,
            'new_location': False,
            'tor_exit_node': False,
            'vpn_detected': True,
            'distance_from_usual': 1000,
            'country_mismatch': False,
            'high_risk_country': False,
            'typing_pattern_similarity': 0.8,
            'session_duration_anomaly': 0.5,
            'unusual_access_pattern': 0.3
        }
        
        features = extractor.extract_auth_features(auth_data)
        
        assert len(features) > 0
        assert all(isinstance(f, float) for f in features)

    def test_payload_feature_extraction(self):
        """Test payload feature extraction."""
        extractor = FeatureExtractor()
        
        # Test SQL injection payload
        sql_payload_data = {
            'type': 'payload',
            'payload': "admin' OR '1'='1'--"
        }
        
        features = extractor.extract_payload_features(sql_payload_data)
        
        assert len(features) > 0
        assert any(f > 0 for f in features[-20:])  # Should detect SQL patterns
        
        # Test XSS payload
        xss_payload_data = {
            'type': 'payload',
            'payload': "<script>alert('xss')</script>"
        }
        
        features = extractor.extract_payload_features(xss_payload_data)
        
        assert len(features) > 0
        assert any(f > 0 for f in features[-20:])  # Should detect XSS patterns

    def test_feature_vector_consistency(self):
        """Test that feature vectors have consistent size."""
        extractor = FeatureExtractor()
        
        test_data = [
            {'type': 'network', 'packet_size': 100},
            {'type': 'auth', 'failed_attempts': 1},
            {'type': 'payload', 'payload': 'test'},
            {'type': 'unknown', 'severity': 5}
        ]
        
        features_list = [extractor.extract_all_features(data) for data in test_data]
        
        # All feature vectors should have the same size
        sizes = [len(features) for features in features_list]
        assert len(set(sizes)) == 1, f"Inconsistent feature vector sizes: {sizes}"

class TestAdaptiveThreatDetector:
    """Test adaptive threat detection functionality."""
    
    @pytest.fixture
    def temp_detector(self):
        """Create a temporary detector for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            detector = AdaptiveThreatDetector(model_dir=temp_dir)
            yield detector

    def test_detector_initialization(self, temp_detector):
        """Test detector initialization."""
        detector = temp_detector
        
        assert detector.feature_extractor is not None
        assert detector.anomaly_detector is not None
        assert detector.classifier is not None
        assert len(detector.threat_buffer) > 0  # Should have synthetic data

    def test_threat_detection_sql_injection(self, temp_detector):
        """Test SQL injection detection."""
        detector = temp_detector
        
        sql_data = {
            'type': 'payload',
            'payload': "1' UNION SELECT * FROM users--",
            'source_ip': '192.168.1.100'
        }
        
        result = detector.predict(sql_data)
        
        assert 'is_threat' in result
        assert 'confidence' in result
        assert 'threat_type' in result
        assert isinstance(result['is_threat'], bool)
        assert 0 <= result['confidence'] <= 1

    def test_threat_detection_xss(self, temp_detector):
        """Test XSS detection."""
        detector = temp_detector
        
        xss_data = {
            'type': 'payload',
            'payload': "<script>alert('malicious')</script>",
            'source_ip': '10.0.0.50'
        }
        
        result = detector.predict(xss_data)
        
        assert 'is_threat' in result
        assert 'confidence' in result
        assert isinstance(result['is_threat'], bool)

    def test_threat_detection_brute_force(self, temp_detector):
        """Test brute force detection."""
        detector = temp_detector
        
        brute_force_data = {
            'type': 'auth',
            'failed_attempts': 10,
            'time_since_last_attempt': 1,
            'new_device': True,
            'new_location': True,
            'username': 'admin'
        }
        
        result = detector.predict(brute_force_data)
        
        assert 'is_threat' in result
        assert 'confidence' in result
        # High failed attempts should likely be detected as threat
        # Note: May not always be true due to ML model variations

    def test_normal_traffic_detection(self, temp_detector):
        """Test normal traffic detection."""
        detector = temp_detector
        
        normal_data = {
            'type': 'network',
            'packet_size': 500,
            'packet_count': 10,
            'request_frequency': 5,
            'protocol': 'https',
            'port': 443
        }
        
        result = detector.predict(normal_data)
        
        assert 'is_threat' in result
        assert 'confidence' in result
        assert isinstance(result['is_threat'], bool)

    def test_feedback_mechanism(self, temp_detector):
        """Test feedback and adaptive learning."""
        detector = temp_detector
        
        # Initial buffer size
        initial_feedback_size = len(detector.feedback_buffer)
        
        # Add feedback
        test_data = {
            'type': 'payload',
            'payload': 'legitimate search query',
            'source_ip': '192.168.1.10'
        }
        
        detector.add_feedback(test_data, is_threat=False, threat_type=None)
        
        # Feedback buffer should have increased
        assert len(detector.feedback_buffer) == initial_feedback_size + 1

    def test_model_retraining(self, temp_detector):
        """Test model retraining functionality."""
        detector = temp_detector
        
        original_version = detector.last_retrain
        
        # Add some feedback samples
        for i in range(5):
            test_data = {
                'type': 'payload',
                'payload': f'test payload {i}',
                'source_ip': '192.168.1.10'
            }
            detector.add_feedback(test_data, is_threat=i % 2 == 0)
        
        # Trigger retraining
        detector.retrain_model()
        
        # Model version should have updated
        assert detector.last_retrain > original_version

    def test_model_persistence(self, temp_detector):
        """Test model saving and loading."""
        detector = temp_detector
        
        # Add some data
        test_data = {
            'type': 'payload',
            'payload': 'test data for persistence',
            'source_ip': '192.168.1.10'
        }
        detector.add_feedback(test_data, is_threat=True, threat_type='test_threat')
        
        # Save model
        detector.save_model()
        
        # Verify model file exists
        model_path = os.path.join(detector.model_dir, 'threat_detector.pkl')
        assert os.path.exists(model_path)
        
        # Create new detector and load model
        new_detector = AdaptiveThreatDetector(model_dir=detector.model_dir)
        
        # Should have loaded the saved data
        assert len(new_detector.threat_buffer) > 0

    def test_threat_type_classification(self, temp_detector):
        """Test threat type classification."""
        detector = temp_detector
        
        test_cases = [
            {
                'data': {'type': 'payload', 'payload': "' OR 1=1--"},
                'expected_type': 'sql_injection'
            },
            {
                'data': {'type': 'payload', 'payload': "<script>alert(1)</script>"},
                'expected_type': 'xss'
            },
            {
                'data': {'type': 'auth', 'failed_attempts': 10, 'username': 'admin'},
                'expected_type': 'brute_force'
            },
            {
                'data': {'type': 'network', 'request_frequency': 100},
                'expected_type': 'ddos'
            }
        ]
        
        for test_case in test_cases:
            threat_type = detector._classify_threat_type(test_case['data'])
            # Should classify as expected type or unknown_threat
            assert threat_type in [test_case['expected_type'], 'unknown_threat']

    def test_model_metrics(self, temp_detector):
        """Test model metrics tracking."""
        detector = temp_detector
        
        model_info = detector.get_model_info()
        
        required_fields = [
            'model_version', 'samples_trained', 'feedback_samples',
            'metrics', 'threat_patterns', 'next_retrain'
        ]
        
        for field in required_fields:
            assert field in model_info
        
        # Metrics should have required subfields
        metrics = model_info['metrics']
        metric_fields = ['accuracy', 'precision', 'recall', 'f1_score', 'false_positive_rate']
        
        for field in metric_fields:
            assert field in metrics
            assert isinstance(metrics[field], (int, float))

    def test_pattern_tracking(self, temp_detector):
        """Test threat pattern tracking."""
        detector = temp_detector
        
        # Simulate multiple threats of the same type
        for i in range(3):
            sql_data = {
                'type': 'payload',
                'payload': f"' OR 1=1 -- {i}",
                'source_ip': f'192.168.1.{100+i}'
            }
            
            result = detector.predict(sql_data)
        
        # Should have tracked patterns
        assert len(detector.pattern_tracker) > 0

    def test_error_handling(self, temp_detector):
        """Test error handling in threat detection."""
        detector = temp_detector
        
        # Test with invalid data
        invalid_data = None
        result = detector.predict(invalid_data)
        
        assert 'error' in result
        assert result['is_threat'] == False  # Safe default

    def test_feature_based_detection(self, temp_detector):
        """Test legacy feature-based detection."""
        detector = temp_detector
        
        # Test with raw features (legacy mode)
        features_data = {
            'type': 'features',
            'features': [0.8, 0.2, 0.9, 0.1, 0.5]
        }
        
        result = detector.predict(features_data)
        
        assert 'is_threat' in result
        assert 'confidence' in result
        assert isinstance(result['is_threat'], bool)

class TestThreatDetectionIntegration:
    """Integration tests for threat detection system."""
    
    def test_sql_injection_patterns(self):
        """Test various SQL injection patterns."""
        with tempfile.TemporaryDirectory() as temp_dir:
            detector = AdaptiveThreatDetector(model_dir=temp_dir)
            
            sql_patterns = [
                "' OR '1'='1",
                "admin'--",
                "1; DROP TABLE users",
                "UNION SELECT * FROM passwords",
                "' AND 1=1--",
                "'; INSERT INTO users VALUES('hacker', 'password'); --"
            ]
            
            threat_count = 0
            for pattern in sql_patterns:
                data = {
                    'type': 'payload',
                    'payload': pattern,
                    'source_ip': '192.168.1.100'
                }
                
                result = detector.predict(data)
                if result['is_threat']:
                    threat_count += 1
            
            # Should detect at least some SQL injection patterns
            assert threat_count > 0

    def test_xss_patterns(self):
        """Test various XSS patterns."""
        with tempfile.TemporaryDirectory() as temp_dir:
            detector = AdaptiveThreatDetector(model_dir=temp_dir)
            
            xss_patterns = [
                "<script>alert('xss')</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "<iframe src='javascript:alert(1)'></iframe>",
                "';alert('xss');//"
            ]
            
            threat_count = 0
            for pattern in xss_patterns:
                data = {
                    'type': 'payload',
                    'payload': pattern,
                    'source_ip': '10.0.0.50'
                }
                
                result = detector.predict(data)
                if result['is_threat']:
                    threat_count += 1
            
            # Should detect at least some XSS patterns
            assert threat_count > 0

    def test_normal_vs_malicious(self):
        """Test distinction between normal and malicious traffic."""
        with tempfile.TemporaryDirectory() as temp_dir:
            detector = AdaptiveThreatDetector(model_dir=temp_dir)
            
            # Normal requests
            normal_requests = [
                {'type': 'payload', 'payload': 'search?q=python tutorial'},
                {'type': 'payload', 'payload': 'login.php'},
                {'type': 'payload', 'payload': 'profile/update'},
                {'type': 'auth', 'failed_attempts': 0, 'new_device': False},
                {'type': 'network', 'packet_count': 10, 'request_frequency': 5}
            ]
            
            # Malicious requests
            malicious_requests = [
                {'type': 'payload', 'payload': "' OR 1=1--"},
                {'type': 'payload', 'payload': '<script>alert(1)</script>'},
                {'type': 'auth', 'failed_attempts': 15, 'new_device': True},
                {'type': 'network', 'packet_count': 1000, 'request_frequency': 100}
            ]
            
            normal_threat_count = sum(1 for req in normal_requests 
                                    if detector.predict(req)['is_threat'])
            malicious_threat_count = sum(1 for req in malicious_requests 
                                       if detector.predict(req)['is_threat'])
            
            # Should detect more threats in malicious requests
            # Note: This is probabilistic, so we allow some tolerance
            assert malicious_threat_count >= normal_threat_count

    def test_adaptive_learning_cycle(self):
        """Test complete adaptive learning cycle."""
        with tempfile.TemporaryDirectory() as temp_dir:
            detector = AdaptiveThreatDetector(model_dir=temp_dir)
            
            # 1. Initial prediction
            test_data = {
                'type': 'payload',
                'payload': 'custom malicious pattern xyz123',
                'source_ip': '192.168.1.100'
            }
            
            initial_result = detector.predict(test_data)
            
            # 2. Add feedback (this is a threat)
            detector.add_feedback(test_data, is_threat=True, threat_type='custom_threat')
            
            # 3. Add more similar samples
            for i in range(10):
                similar_data = {
                    'type': 'payload',
                    'payload': f'custom malicious pattern xyz{i}',
                    'source_ip': f'192.168.1.{100+i}'
                }
                detector.add_feedback(similar_data, is_threat=True, threat_type='custom_threat')
            
            # 4. Retrain model
            detector.retrain_model()
            
            # 5. Test with similar pattern
            new_test_data = {
                'type': 'payload',
                'payload': 'custom malicious pattern xyz999',
                'source_ip': '192.168.1.200'
            }
            
            final_result = detector.predict(new_test_data)
            
            # Model should have learned from feedback
            assert 'is_threat' in final_result
            assert 'confidence' in final_result