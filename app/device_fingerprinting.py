"""
Device Fingerprinting and Risk-Based Authentication
Tracks devices, calculates authentication risk, and adapts security requirements
"""

import logging
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import geoip2.database
import geoip2.errors
from user_agents import parse
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

logger = logging.getLogger(__name__)

device_blueprint = Blueprint('device', __name__)

# In-memory storage (replace with database in production)
device_registry = {}
login_history = []
risk_assessments = {}

@dataclass
class DeviceFingerprint:
    """Device fingerprint data structure"""
    fingerprint_hash: str
    user_agent: str
    platform: str
    browser: str
    browser_version: str
    os: str
    os_version: str
    device_type: str
    screen_resolution: Optional[str]
    timezone: Optional[str]
    language: Optional[str]
    color_depth: Optional[int]
    pixel_ratio: Optional[float]
    created_at: datetime
    last_seen: datetime
    is_trusted: bool
    trust_score: float

@dataclass
class GeoLocation:
    """Geographic location data"""
    ip_address: str
    country: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    timezone: Optional[str]
    isp: Optional[str]
    is_vpn: bool
    is_tor: bool
    is_proxy: bool

@dataclass
class AuthenticationContext:
    """Complete authentication context"""
    username: str
    timestamp: datetime
    ip_address: str
    device_fingerprint: str
    geo_location: GeoLocation
    is_new_device: bool
    is_unusual_location: bool
    is_unusual_time: bool
    velocity_check_failed: bool
    failed_attempts_count: int
    time_since_last_login: Optional[timedelta]
    risk_score: float

class DeviceFingerprintGenerator:
    """Generate device fingerprints from browser/client data"""

    @staticmethod
    def generate_fingerprint(request_data: Dict) -> DeviceFingerprint:
        """Generate device fingerprint from request data"""

        # Parse User-Agent
        user_agent_string = request_data.get('user_agent', '')
        ua = parse(user_agent_string)

        # Collect fingerprint components
        components = [
            user_agent_string,
            request_data.get('accept_language', ''),
            request_data.get('screen_resolution', ''),
            request_data.get('timezone', ''),
            request_data.get('platform', ''),
            str(request_data.get('color_depth', '')),
            str(request_data.get('pixel_ratio', '')),
            request_data.get('canvas_hash', ''),  # Canvas fingerprinting
            request_data.get('webgl_hash', ''),   # WebGL fingerprinting
            ','.join(sorted(request_data.get('plugins', []))),
            ','.join(sorted(request_data.get('fonts', [])))
        ]

        # Generate hash
        fingerprint_str = '|'.join(components)
        fingerprint_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()

        return DeviceFingerprint(
            fingerprint_hash=fingerprint_hash,
            user_agent=user_agent_string,
            platform=request_data.get('platform', ua.os.family),
            browser=ua.browser.family,
            browser_version=ua.browser.version_string,
            os=ua.os.family,
            os_version=ua.os.version_string,
            device_type=ua.device.family,
            screen_resolution=request_data.get('screen_resolution'),
            timezone=request_data.get('timezone'),
            language=request_data.get('accept_language'),
            color_depth=request_data.get('color_depth'),
            pixel_ratio=request_data.get('pixel_ratio'),
            created_at=datetime.now(),
            last_seen=datetime.now(),
            is_trusted=False,
            trust_score=0.5
        )

    @staticmethod
    def generate_simple_fingerprint(request_headers: Dict) -> str:
        """Generate simple fingerprint from request headers only"""
        components = [
            request_headers.get('User-Agent', ''),
            request_headers.get('Accept-Language', ''),
            request_headers.get('Accept-Encoding', ''),
        ]

        fingerprint_str = '|'.join(components)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()

class GeoLocationAnalyzer:
    """Analyze geographic location and detect anomalies"""

    def __init__(self):
        # In production, use GeoIP2 database
        self.geoip_reader = None
        try:
            # Requires MaxMind GeoLite2 database
            # Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
            pass
            # self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except Exception as e:
            logger.warning(f"GeoIP database not available: {e}")

    def analyze_ip(self, ip_address: str) -> GeoLocation:
        """Analyze IP address and extract location data"""

        # Skip private/local IPs
        if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.'):
            return GeoLocation(
                ip_address=ip_address,
                country='LOCAL',
                city='LOCAL',
                latitude=None,
                longitude=None,
                timezone=None,
                isp='LOCAL',
                is_vpn=False,
                is_tor=False,
                is_proxy=False
            )

        # Use GeoIP database if available
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip_address)
                return GeoLocation(
                    ip_address=ip_address,
                    country=response.country.name,
                    city=response.city.name,
                    latitude=response.location.latitude,
                    longitude=response.location.longitude,
                    timezone=response.location.time_zone,
                    isp=None,  # Requires ISP database
                    is_vpn=False,  # Requires VPN detection service
                    is_tor=False,
                    is_proxy=False
                )
            except geoip2.errors.AddressNotFoundError:
                logger.warning(f"IP address not found in GeoIP database: {ip_address}")
            except Exception as e:
                logger.error(f"GeoIP lookup error: {e}")

        # Fallback: return minimal data
        return GeoLocation(
            ip_address=ip_address,
            country=None,
            city=None,
            latitude=None,
            longitude=None,
            timezone=None,
            isp=None,
            is_vpn=False,
            is_tor=False,
            is_proxy=False
        )

    def calculate_distance(self, loc1: GeoLocation, loc2: GeoLocation) -> float:
        """Calculate distance between two locations (in km)"""
        if not all([loc1.latitude, loc1.longitude, loc2.latitude, loc2.longitude]):
            return 0.0

        # Haversine formula
        from math import radians, sin, cos, sqrt, atan2

        lat1, lon1 = radians(loc1.latitude), radians(loc1.longitude)
        lat2, lon2 = radians(loc2.latitude), radians(loc2.longitude)

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))

        # Earth radius in km
        radius = 6371
        return radius * c

class RiskCalculator:
    """Calculate authentication risk score"""

    def __init__(self):
        self.geo_analyzer = GeoLocationAnalyzer()
        self.risk_thresholds = {
            'new_device': 0.3,
            'unusual_location': 0.4,
            'unusual_time': 0.2,
            'velocity_anomaly': 0.5,
            'vpn_tor': 0.3,
            'high_failed_attempts': 0.4,
            'impossible_travel': 0.6
        }

    def calculate_risk(self, username: str, context: Dict) -> Tuple[float, AuthenticationContext]:
        """Calculate comprehensive risk score"""

        # Parse current request
        ip_address = context.get('ip_address', '127.0.0.1')
        device_fingerprint = context.get('device_fingerprint', '')
        timestamp = datetime.now()

        # Analyze location
        current_location = self.geo_analyzer.analyze_ip(ip_address)

        # Check if new device
        is_new_device = self._is_new_device(username, device_fingerprint)

        # Check unusual location
        is_unusual_location = self._is_unusual_location(username, current_location)

        # Check unusual time
        is_unusual_time = self._is_unusual_time(username, timestamp)

        # Velocity check (impossible travel)
        velocity_check_failed = self._check_velocity(username, current_location, timestamp)

        # Failed attempts count
        failed_attempts = self._get_failed_attempts_count(username)

        # Time since last login
        time_since_last = self._get_time_since_last_login(username)

        # Calculate base risk score
        risk_score = 0.0

        if is_new_device:
            risk_score += self.risk_thresholds['new_device']
            logger.info(f"New device detected for {username}")

        if is_unusual_location:
            risk_score += self.risk_thresholds['unusual_location']
            logger.info(f"Unusual location detected for {username}")

        if is_unusual_time:
            risk_score += self.risk_thresholds['unusual_time']

        if velocity_check_failed:
            risk_score += self.risk_thresholds['impossible_travel']
            logger.warning(f"Impossible travel detected for {username}")

        if current_location.is_vpn or current_location.is_tor:
            risk_score += self.risk_thresholds['vpn_tor']
            logger.warning(f"VPN/Tor detected for {username}")

        if failed_attempts > 2:
            risk_score += self.risk_thresholds['high_failed_attempts']
            logger.warning(f"High failed attempts for {username}: {failed_attempts}")

        # Normalize to 0-1 range
        risk_score = min(risk_score, 1.0)

        # Create authentication context
        auth_context = AuthenticationContext(
            username=username,
            timestamp=timestamp,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            geo_location=current_location,
            is_new_device=is_new_device,
            is_unusual_location=is_unusual_location,
            is_unusual_time=is_unusual_time,
            velocity_check_failed=velocity_check_failed,
            failed_attempts_count=failed_attempts,
            time_since_last_login=time_since_last,
            risk_score=risk_score
        )

        # Store risk assessment
        risk_assessments[f"{username}_{timestamp.isoformat()}"] = auth_context

        return risk_score, auth_context

    def _is_new_device(self, username: str, fingerprint: str) -> bool:
        """Check if device is new for user"""
        user_devices = device_registry.get(username, {})
        return fingerprint not in user_devices

    def _is_unusual_location(self, username: str, location: GeoLocation) -> bool:
        """Check if location is unusual for user"""
        # Get user's typical locations from history
        user_history = [h for h in login_history if h.get('username') == username]

        if not user_history:
            return False  # First login, not unusual

        # Check if country is different from usual
        typical_countries = set(h.get('country') for h in user_history[-20:] if h.get('country'))

        if location.country and location.country not in typical_countries and len(typical_countries) > 0:
            return True

        return False

    def _is_unusual_time(self, username: str, timestamp: datetime) -> bool:
        """Check if login time is unusual"""
        hour = timestamp.hour

        # Unusual hours: 2 AM - 5 AM
        if 2 <= hour <= 5:
            return True

        # Check user's typical login hours
        user_history = [h for h in login_history if h.get('username') == username]
        typical_hours = [h.get('timestamp').hour for h in user_history[-50:] if h.get('timestamp')]

        if typical_hours:
            # If user never logs in at this hour, it's unusual
            hour_counts = defaultdict(int)
            for h in typical_hours:
                hour_counts[h] += 1

            if hour not in hour_counts:
                return True

        return False

    def _check_velocity(self, username: str, current_location: GeoLocation, timestamp: datetime) -> bool:
        """Check for impossible travel (velocity anomaly)"""
        user_history = [h for h in login_history if h.get('username') == username]

        if not user_history:
            return False

        # Get last login location and time
        last_login = user_history[-1]
        last_location = last_login.get('geo_location')
        last_timestamp = last_login.get('timestamp')

        if not last_location or not last_timestamp:
            return False

        # Calculate distance and time difference
        distance_km = self.geo_analyzer.calculate_distance(last_location, current_location)
        time_diff_hours = (timestamp - last_timestamp).total_seconds() / 3600

        if time_diff_hours <= 0:
            return False

        # Calculate required speed (km/h)
        required_speed = distance_km / time_diff_hours

        # Impossible travel: >800 km/h (faster than commercial flight)
        if required_speed > 800:
            logger.warning(f"Impossible travel detected: {distance_km:.1f} km in {time_diff_hours:.1f} hours ({required_speed:.1f} km/h)")
            return True

        return False

    def _get_failed_attempts_count(self, username: str) -> int:
        """Get recent failed login attempts count"""
        recent_failures = [
            h for h in login_history
            if h.get('username') == username
            and not h.get('success')
            and datetime.now() - h.get('timestamp', datetime.now()) < timedelta(hours=1)
        ]
        return len(recent_failures)

    def _get_time_since_last_login(self, username: str) -> Optional[timedelta]:
        """Get time since last successful login"""
        user_history = [
            h for h in login_history
            if h.get('username') == username and h.get('success')
        ]

        if user_history:
            return datetime.now() - user_history[-1]['timestamp']

        return None

    def get_required_auth_factors(self, risk_score: float) -> List[str]:
        """Determine required authentication factors based on risk"""
        factors = ['password']

        if risk_score >= 0.8:
            # Critical risk
            factors.extend(['totp', 'email_verification', 'security_questions'])
        elif risk_score >= 0.6:
            # High risk
            factors.extend(['totp', 'email_verification'])
        elif risk_score >= 0.4:
            # Medium risk
            factors.append('totp')
        # Low risk: password only

        return factors

# Global instance
risk_calculator = RiskCalculator()

# API Endpoints

@device_blueprint.route('/fingerprint', methods=['POST'])
@jwt_required()
def register_device():
    """Register device fingerprint"""
    try:
        current_user = get_jwt_identity()

        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400

        # Generate fingerprint
        fingerprint = DeviceFingerprintGenerator.generate_fingerprint(request.json)

        # Store device
        if current_user not in device_registry:
            device_registry[current_user] = {}

        device_registry[current_user][fingerprint.fingerprint_hash] = fingerprint

        logger.info(f"Device registered for user {current_user}: {fingerprint.fingerprint_hash[:8]}...")

        return jsonify({
            'fingerprint': fingerprint.fingerprint_hash,
            'device_type': fingerprint.device_type,
            'browser': f"{fingerprint.browser} {fingerprint.browser_version}",
            'os': f"{fingerprint.os} {fingerprint.os_version}",
            'is_trusted': fingerprint.is_trusted,
            'message': 'Device registered successfully'
        }), 200

    except Exception as e:
        logger.error(f"Device registration error: {e}")
        return jsonify({'error': 'Device registration failed'}), 500

@device_blueprint.route('/list', methods=['GET'])
@jwt_required()
def list_devices():
    """List all registered devices for current user"""
    try:
        current_user = get_jwt_identity()

        user_devices = device_registry.get(current_user, {})

        devices = []
        for fingerprint_hash, device in user_devices.items():
            devices.append({
                'fingerprint': fingerprint_hash[:16] + '...',
                'device_type': device.device_type,
                'browser': f"{device.browser} {device.browser_version}",
                'os': f"{device.os} {device.os_version}",
                'first_seen': device.created_at.isoformat(),
                'last_seen': device.last_seen.isoformat(),
                'is_trusted': device.is_trusted,
                'trust_score': device.trust_score
            })

        return jsonify({
            'devices': devices,
            'total_devices': len(devices)
        }), 200

    except Exception as e:
        logger.error(f"Device list error: {e}")
        return jsonify({'error': 'Failed to list devices'}), 500

@device_blueprint.route('/trust/<fingerprint>', methods=['POST'])
@jwt_required()
def trust_device(fingerprint):
    """Mark device as trusted"""
    try:
        current_user = get_jwt_identity()

        user_devices = device_registry.get(current_user, {})

        if fingerprint not in user_devices:
            return jsonify({'error': 'Device not found'}), 404

        user_devices[fingerprint].is_trusted = True
        user_devices[fingerprint].trust_score = 1.0

        logger.info(f"Device trusted: {fingerprint[:8]}... for user {current_user}")

        return jsonify({
            'message': 'Device marked as trusted',
            'fingerprint': fingerprint
        }), 200

    except Exception as e:
        logger.error(f"Trust device error: {e}")
        return jsonify({'error': 'Failed to trust device'}), 500

@device_blueprint.route('/revoke/<fingerprint>', methods=['DELETE'])
@jwt_required()
def revoke_device(fingerprint):
    """Revoke device access"""
    try:
        current_user = get_jwt_identity()

        user_devices = device_registry.get(current_user, {})

        if fingerprint not in user_devices:
            return jsonify({'error': 'Device not found'}), 404

        del user_devices[fingerprint]

        logger.info(f"Device revoked: {fingerprint[:8]}... for user {current_user}")

        return jsonify({
            'message': 'Device access revoked',
            'fingerprint': fingerprint
        }), 200

    except Exception as e:
        logger.error(f"Revoke device error: {e}")
        return jsonify({'error': 'Failed to revoke device'}), 500

@device_blueprint.route('/risk-assessment', methods=['POST'])
def assess_authentication_risk():
    """Assess risk for authentication attempt"""
    try:
        if not request.json:
            return jsonify({'error': 'Request must be JSON'}), 400

        username = request.json.get('username')
        if not username:
            return jsonify({'error': 'Username required'}), 400

        # Get client IP
        ip_address = request.remote_addr

        # Generate device fingerprint
        device_fingerprint = DeviceFingerprintGenerator.generate_simple_fingerprint(dict(request.headers))

        context = {
            'ip_address': ip_address,
            'device_fingerprint': device_fingerprint
        }

        # Calculate risk
        risk_score, auth_context = risk_calculator.calculate_risk(username, context)

        # Get required factors
        required_factors = risk_calculator.get_required_auth_factors(risk_score)

        return jsonify({
            'risk_score': risk_score,
            'risk_level': 'critical' if risk_score >= 0.8 else 'high' if risk_score >= 0.6 else 'medium' if risk_score >= 0.4 else 'low',
            'required_factors': required_factors,
            'is_new_device': auth_context.is_new_device,
            'is_unusual_location': auth_context.is_unusual_location,
            'is_unusual_time': auth_context.is_unusual_time,
            'velocity_check_failed': auth_context.velocity_check_failed,
            'location': {
                'country': auth_context.geo_location.country,
                'city': auth_context.geo_location.city
            } if auth_context.geo_location else None
        }), 200

    except Exception as e:
        logger.error(f"Risk assessment error: {e}")
        return jsonify({'error': 'Risk assessment failed'}), 500

# Helper functions for integration

def record_login_attempt(username: str, ip_address: str, device_fingerprint: str,
                        success: bool, geo_location: Optional[GeoLocation] = None):
    """Record login attempt for history tracking"""
    login_history.append({
        'username': username,
        'timestamp': datetime.now(),
        'ip_address': ip_address,
        'device_fingerprint': device_fingerprint,
        'success': success,
        'geo_location': geo_location,
        'country': geo_location.country if geo_location else None
    })

    # Keep only last 10000 records
    if len(login_history) > 10000:
        login_history.pop(0)

def update_device_last_seen(username: str, fingerprint: str):
    """Update device last seen timestamp"""
    if username in device_registry and fingerprint in device_registry[username]:
        device_registry[username][fingerprint].last_seen = datetime.now()
