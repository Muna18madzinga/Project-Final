"""
Risk assessment engine for adaptive multi-factor authentication.
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime

import hashlib
import requests
import re
import logging
from typing import Optional, Dict, List, Set, Tuple

# Import Google Drive scanner
from ..utils.google_drive import check_password_in_drive

class RiskFactor:
    """Represents different risk factors for authentication."""
    IP_CHANGE = "ip_change"
    UNUSUAL_TIME = "unusual_time" 
    UNUSUAL_LOCATION = "unusual_location"
    UNUSUAL_DEVICE = "unusual_device"
    FAILED_ATTEMPTS = "failed_attempts"
    SENSITIVE_ACTION = "sensitive_action"
    COMPROMISED_PASSWORD = "compromised_password"

class RiskLevel:
    """Risk level classifications."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RiskAssessmentEngine:
    """Engine for assessing authentication risk and determining MFA requirements."""
    
    def __init__(self):
        # Initialize anomaly detection model
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.training_data = []
        self.is_trained = False
        
        # Risk thresholds
        self.thresholds = {
            RiskLevel.LOW: 0.3,
            RiskLevel.MEDIUM: 0.6,
            RiskLevel.HIGH: 0.8
        }
        
        # Known compromised password hashes (in a real app, this would be a database)
        self.known_compromised_hashes = set()
        
        # Known platform domains to check against
        self.platform_domains = {
            'linkedin.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'google.com', 'microsoft.com', 'github.com', 'amazon.com',
            'netflix.com', 'spotify.com', 'dropbox.com', 'slack.com'
        }
        
        # Common password variations to check
        self.common_variations = [
            lambda p: p + '123',
            lambda p: p + '!@#',
            lambda p: p + '123!@#',
            lambda p: p.capitalize(),
            lambda p: p + '1',
            lambda p: p + '!',
            lambda p: p + '1234',
            lambda p: p + '2023',
            lambda p: p + '2024',
            lambda p: p.upper()
        ]
        
    def _check_common_platform_patterns(self, password: str, email: Optional[str] = None) -> Tuple[bool, List[str]]:
        """
        Check for common password patterns and platform-specific reuse.
        Returns a tuple of (is_reused, reasons)
        """
        reasons = []
        
        # Check for username in password
        if email:
            username = email.split('@')[0]
            if username and username.lower() in password.lower():
                reasons.append(f"Password contains username or email")
        
        # Check for common platform names in password
        for domain in self.platform_domains:
            name = domain.split('.')[0]
            if name.lower() in password.lower():
                reasons.append(f"Password contains platform name: {name}")
        
        # Check for common patterns (e.g., 'linkedin123')
        for domain in self.platform_domains:
            name = domain.split('.')[0]
            for variation in self.common_variations:
                if variation(name.lower()) in password.lower():
                    reasons.append(f"Password follows common pattern for {name}")
                    break
        
        return len(reasons) > 0, reasons

    def _check_password_breach(self, password: str) -> bool:
        """
        Check if password has been compromised using Have I Been Pwned API.
        Uses k-anonymity to protect the password.
        """
        try:
            # Hash the password using SHA-1
            sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_password[:5]
            suffix = sha1_password[5:]
            
            # Check local cache first
            if sha1_password in self.known_compromised_hashes:
                return True
                
            # Check Have I Been Pwned API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                # Check if suffix exists in the response
                for line in response.text.splitlines():
                    if line.split(':')[0] == suffix:
                        self.known_compromised_hashes.add(sha1_password)
                        return True
            return False
            
        except Exception as e:
            # Log the error but don't block the user
            print(f"Error checking password breach: {e}")
            return False
        
    def check_password_strength(self, password: str, email: Optional[str] = None, check_google_drive: bool = True) -> dict:
        """
        Check password strength, if it's been compromised, and if it's reused from other platforms.
        
        Args:
            password: The password to check
            email: Optional email to check for username patterns
            check_google_drive: Whether to check for the password in Google Drive
            
        Returns:
            Dictionary with results of the password check
        """
        result = {
            'is_compromised': False,
            'is_reused': False,
            'in_google_drive': False,
            'google_drive_matches': [],
            'strength': 'weak',
            'suggestions': [],
            'reuse_warnings': []
        }
        
        # Check if password exists in Google Drive
        if check_google_drive and len(password) >= 4:  # Skip very short passwords
            try:
                drive_matches = check_password_in_drive(password)
                if drive_matches:
                    result['in_google_drive'] = True
                    result['google_drive_matches'] = drive_matches
                    result['suggestions'].append('This password was found in your Google Drive. For security, please choose a password you haven\'t used before.')
            except Exception as e:
                logging.warning(f"Error checking Google Drive for password: {e}")
                # Continue with other checks even if Google Drive check fails
        
        # Check if password is in known breaches
        if self._check_password_breach(password):
            result['is_compromised'] = True
            result['suggestions'].append('This password has been exposed in data breaches. Please choose a different one.')
        
        # Check for platform-specific patterns and reuse
        is_platform_reuse, reuse_reasons = self._check_common_platform_patterns(password, email)
        if is_platform_reuse:
            result['is_reused'] = True
            result['reuse_warnings'].extend(reuse_reasons)
            result['suggestions'].append('This password follows patterns commonly used on other platforms. Please choose a more unique password.')
        
        # Basic password strength checks
        if len(password) < 8:
            result['suggestions'].append('Use at least 8 characters')
        if not any(c.isupper() for c in password):
            result['suggestions'].append('Include uppercase letters')
        if not any(c.islower() for c in password):
            result['suggestions'].append('Include lowercase letters')
        if not any(c.isdigit() for c in password):
            result['suggestions'].append('Include numbers')
        if not any(not c.isalnum() for c in password):
            result['suggestions'].append('Include special characters')
            
        # Determine strength based on suggestions
        if not result['suggestions']:
            result['strength'] = 'strong'
        elif len(result['suggestions']) <= 2:
            result['strength'] = 'moderate'
            
        return result
        self.user_history = {}
    
    def train_model(self):
        """Train the anomaly detection model with collected data."""
        if len(self.training_data) > 10:  # Need minimum data points
            self.model.fit(np.array(self.training_data))
            self.is_trained = True
    
    def record_login(self, user_id, context):
        """Record a login attempt for future risk assessment."""
        if user_id not in self.user_history:
            self.user_history[user_id] = []
        
        # Add timestamp to context
        context['timestamp'] = datetime.now().timestamp()
        
        # Store the login context
        self.user_history[user_id].append(context)
        
        # Convert login data to feature vector for model training
        features = self._extract_features(user_id, context)
        self.training_data.append(features)
        
        # Periodically retrain the model
        if len(self.training_data) % 20 == 0:  # Retrain every 20 new data points
            self.train_model()
    
    def assess_risk(self, user_id, login_context, password: Optional[str] = None, email: Optional[str] = None, check_google_drive: bool = True):
        """
        Assess the risk level of a login attempt or password change.
        
        Args:
            user_id: Identifier for the user
            login_context: Dictionary containing login details 
                         (ip, device, location, time, etc.)
            password: Optional password to check for breaches/reuse
            email: Optional email for additional password checks
            check_google_drive: Whether to check for the password in Google Drive
            
        Returns:
            Dictionary containing risk assessment details
        """
        risk_score = 0.0
        risk_factors = []
        password_issues = {}
        
        # Check password if provided
        if password is not None:
            password_check = self.check_password_strength(password, email, check_google_drive)
            
            # Block compromised passwords
            if password_check.get('is_compromised', False):
                return {
                    'risk_score': 1.0,
                    'risk_level': RiskLevel.CRITICAL,
                    'risk_factors': [RiskFactor.COMPROMISED_PASSWORD],
                    'requires_mfa': True,
                    'password_issues': password_check,
                    'allowed': False,
                    'message': 'This password has been compromised in data breaches. Please choose a different one.'
                }
                
            # Block or flag reused passwords
            if password_check.get('is_reused', False):
                return {
                    'risk_score': 0.8,
                    'risk_level': RiskLevel.HIGH,
                    'risk_factors': [RiskFactor.COMPROMISED_PASSWORD],
                    'requires_mfa': True,
                    'password_issues': password_check,
                    'allowed': False,
                    'message': 'This password appears to be reused from other platforms. Please choose a unique password for this service.'
                }
                
            # Block passwords found in Google Drive
            if check_google_drive and password_check.get('in_google_drive', False):
                matches = password_check.get('google_drive_matches', [])
                match_info = "\n".join([f"- {m['name']} ({m['type']})" for m in matches[:3]])
                if len(matches) > 3:
                    match_info += "\n... and more"
                    
                return {
                    'risk_score': 0.9,
                    'risk_level': RiskLevel.CRITICAL,
                    'risk_factors': [RiskFactor.COMPROMISED_PASSWORD],
                    'requires_mfa': True,
                    'password_issues': password_check,
                    'allowed': False,
                    'message': f"This password was found in your Google Drive. For security, please choose a password you haven't used before.\n\nFound in:\n{match_info}"
                }
            
            password_issues = password_check
        
        # Check if user has history for login context assessment
        if not login_context:
            login_context = {}
            
        if user_id not in self.user_history or not self.user_history[user_id]:
            # New user or no history - medium risk by default
            return {
                'risk_score': 0.5,
                'risk_level': RiskLevel.MEDIUM,
                'risk_factors': [],
                'requires_mfa': True,
                'password_issues': password_issues,
                'allowed': True,
                'message': 'New user or no login history. Additional verification required.'
            }
        
        # Calculate risk based on various factors
        
        # IP change detection
        last_ip = self.user_history[user_id][-1].get('ip')
        current_ip = login_context.get('ip')
        if last_ip and current_ip and last_ip != current_ip:
            risk_factors.append(RiskFactor.IP_CHANGE)
            risk_score += 0.2
        
        # Unusual time detection
        current_hour = datetime.now().hour
        usual_hours = self._get_usual_hours(user_id)
        if current_hour not in usual_hours:
            risk_factors.append(RiskFactor.UNUSUAL_TIME)
            risk_score += 0.15
        
        # Device fingerprint check
        last_device = self.user_history[user_id][-1].get('device')
        current_device = login_context.get('device')
        if last_device and current_device and last_device != current_device:
            risk_factors[RiskFactor.UNUSUAL_DEVICE] = self.weights[RiskFactor.UNUSUAL_DEVICE]
            risk_score += risk_factors[RiskFactor.UNUSUAL_DEVICE]
        
        # Failed attempts check
        failed_attempts = login_context.get('failed_attempts', 0)
        if failed_attempts > 0:
            factor_weight = min(failed_attempts * 0.05, self.weights[RiskFactor.FAILED_ATTEMPTS])
            risk_factors[RiskFactor.FAILED_ATTEMPTS] = factor_weight
            risk_score += factor_weight
        
        # Check if accessing sensitive actions
        if login_context.get('sensitive_action', False):
            risk_factors[RiskFactor.SENSITIVE_ACTION] = self.weights[RiskFactor.SENSITIVE_ACTION]
            risk_score += risk_factors[RiskFactor.SENSITIVE_ACTION]
        
        # Use anomaly detection for additional risk assessment
        if self.is_trained:
            features = self._extract_features(user_id, login_context)
            anomaly_score = self._get_anomaly_score(features)
            # Combine with rule-based score (giving each 50% weight)
            risk_score = 0.5 * risk_score + 0.5 * anomaly_score
        
        # Determine risk level
        risk_level = self._get_risk_level(risk_score)
        
        # Determine required factors based on risk level
        required_factors = self._get_required_factors(risk_level)
        
        return risk_level, required_factors
    
    def _extract_features(self, user_id, context):
        """Extract feature vector from login context for anomaly detection."""
        # Example features (would be expanded in a real implementation)
        hour = datetime.fromtimestamp(context.get('timestamp', datetime.now().timestamp())).hour
        failed_attempts = context.get('failed_attempts', 0)
        
        # This is a simplified example - in a real system, you'd encode IP,
        # geolocation, device fingerprints, etc. in a meaningful way
        return [hour / 24.0, failed_attempts / 10.0]
    
    def _get_anomaly_score(self, features):
        """Get anomaly score from the model."""
        # Higher score means more anomalous
        features_array = np.array([features])
        raw_score = self.model.decision_function(features_array)[0]
        # Convert to a 0-1 scale where 1 is most anomalous
        return 1 - (1 / (1 + np.exp(-raw_score)))
    
    def _get_usual_hours(self, user_id):
        """Determine user's usual login hours based on history."""
        usual_hours = set()
        for login in self.user_history[user_id]:
            if 'timestamp' in login:
                hour = datetime.fromtimestamp(login['timestamp']).hour
                usual_hours.add(hour)
        
        # If no clear pattern, assume business hours
        if not usual_hours:
            usual_hours = set(range(8, 19))  # 8 AM to 6 PM
            
        return usual_hours
    
    def _get_risk_level(self, risk_score):
        """Determine risk level based on risk score."""
        if risk_score <= self.thresholds[RiskLevel.LOW]:
            return RiskLevel.LOW
        elif risk_score <= self.thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif risk_score <= self.thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _get_required_factors(self, risk_level):
        """Determine required authentication factors based on risk level."""
        if risk_level == RiskLevel.LOW:
            return [RiskFactor.PASSWORD]
        elif risk_level == RiskLevel.MEDIUM:
            return [RiskFactor.PASSWORD, RiskFactor.TOTP]
        elif risk_level == RiskLevel.HIGH:
            return [RiskFactor.PASSWORD, RiskFactor.TOTP, RiskFactor.EMAIL]
        else:  # CRITICAL
            return [RiskFactor.PASSWORD, RiskFactor.TOTP, RiskFactor.EMAIL, RiskFactor.PUSH]

    def train_model(self):
        """Train the anomaly detection model with collected data."""
        if len(self.training_data) > 10:  # Need minimum data points
            self.model.fit(np.array(self.training_data))
            self.is_trained = True
    
    def record_login(self, user_id, context):
        """Record a login attempt for future risk assessment."""
        if user_id not in self.user_history:
            self.user_history[user_id] = []
        
        # Add timestamp to context
        context['timestamp'] = datetime.now().timestamp()
        
        # Store the login context
        self.user_history[user_id].append(context)
        
        # Convert login data to feature vector for model training
        features = self._extract_features(user_id, context)
        self.training_data.append(features)
        
        # Periodically retrain the model
        if len(self.training_data) % 20 == 0:  # Retrain every 20 new data points
            self.train_model()
