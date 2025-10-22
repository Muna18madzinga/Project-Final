#!/usr/bin/env python3
"""
Simple Flask App for Testing UI Integration
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import random

app = Flask(__name__, static_folder='frontend/dist', static_url_path='')

# Configuration
app.config['SECRET_KEY'] = 'dev-secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key' 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
CORS(app, origins=['http://localhost:3000', 'http://localhost:5173'])
jwt = JWTManager(app)

# Simple in-memory user store
users = {
    'admin': {
        'password_hash': generate_password_hash('admin123'),
        'role': 'admin'
    },
    'demo': {
        'password_hash': generate_password_hash('demo123'), 
        'role': 'user'
    }
}

# Routes
@app.route('/')
def index():
    """Serve React frontend."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User authentication endpoint."""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        user = users.get(username)
        if user and check_password_hash(user['password_hash'], password):
            access_token = create_access_token(identity=username)
            return jsonify({
                'access_token': access_token,
                'user': {
                    'username': username,
                    'role': user['role']
                }
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user information."""
    current_user = get_jwt_identity()
    user = users.get(current_user)
    
    if user:
        return jsonify({
            'username': current_user,
            'role': user['role']
        })
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """Get dashboard statistics."""
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'real_data_available': False,
        'network': {
            'packets_captured': random.randint(10000, 50000),
            'active_flows': random.randint(10, 100),
            'interface': 'eth0',
            'packets_per_second': random.uniform(50, 200)
        },
        'threats': {
            'total_indicators': random.randint(15000, 25000),
            'threat_matches': random.randint(1, 10),
            'high_risk_events': random.randint(0, 5)
        },
        'telemetry': {
            'events_processed': random.randint(1000, 5000),
            'threat_events': random.randint(10, 50),
            'network_events': random.randint(500, 2000),
            'system_events': random.randint(100, 500)
        }
    })

@app.route('/api/system/metrics', methods=['GET'])
@jwt_required()
def get_system_metrics():
    """Get system metrics."""
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'cpu_percent': random.uniform(20, 80),
        'memory_percent': random.uniform(30, 70),
        'disk_io_read': random.randint(1000000, 10000000),
        'disk_io_write': random.randint(500000, 5000000),
        'network_bytes_sent': random.randint(10000000, 100000000),
        'network_bytes_recv': random.randint(20000000, 200000000),
        'active_connections': random.randint(50, 300),
        'processes_count': random.randint(100, 400)
    })

@app.route('/api/threats/recent', methods=['GET'])
@jwt_required()
def get_recent_threats():
    """Get recent threats."""
    limit = request.args.get('limit', 20, type=int)
    
    threat_types = ['network_intrusion', 'malware_detection', 'suspicious_activity', 'port_scan', 'data_exfiltration']
    sources = ['network', 'system', 'endpoint']
    severities = ['low', 'medium', 'high', 'critical']
    statuses = ['active', 'investigating', 'resolved']
    
    threats = []
    for i in range(min(limit, 25)):
        threats.append({
            'id': f'threat_{i}_{int(datetime.now().timestamp())}',
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
            'type': random.choice(threat_types),
            'source': random.choice(sources),
            'severity': random.choice(severities),
            'status': random.choice(statuses),
            'threat_score': random.uniform(0.3, 1.0),
            'indicators': [f'indicator_{j}' for j in range(random.randint(1, 4))],
            'summary': {'description': f'Demo threat event {i}'}
        })
    
    return jsonify({'threats': threats})

@app.route('/api/network/events', methods=['GET'])
@jwt_required()
def get_network_events():
    """Get network events."""
    limit = request.args.get('limit', 50, type=int)
    
    events = []
    for i in range(min(limit, 30)):
        events.append({
            'id': f'event_{i}',
            'timestamp': (datetime.now() - timedelta(seconds=random.randint(1, 3600))).isoformat(),
            'source_ip': f"192.168.1.{random.randint(1, 254)}",
            'dest_ip': f"10.0.0.{random.randint(1, 254)}",
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice([80, 443, 22, 3389, 445, 53, 25]),
            'protocol': random.choice(['tcp', 'udp']),
            'packet_size': random.randint(64, 1500),
            'threat_score': random.uniform(0.0, 1.0)
        })
    
    return jsonify({'events': events})

@app.route('/api/devices', methods=['GET'])
@jwt_required()
def get_devices():
    """Get network devices."""
    device_types = ['desktop', 'laptop', 'server', 'router', 'switch', 'printer', 'mobile']
    statuses = ['online', 'offline', 'warning']
    risk_levels = ['low', 'medium', 'high']
    
    devices = []
    for i in range(random.randint(8, 15)):
        devices.append({
            'id': f'device_{i}',
            'name': f'Device-{i+1}',
            'ip': f'192.168.1.{random.randint(10, 200)}',
            'mac': ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)]),
            'type': random.choice(device_types),
            'status': random.choice(statuses),
            'risk_level': random.choice(risk_levels),
            'os': random.choice(['Windows 11', 'macOS', 'Linux', 'Android', 'iOS', 'Unknown']),
            'last_seen': (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat()
        })
    
    return jsonify({'devices': devices})

@app.route('/api/threat-intel/status', methods=['GET'])
@jwt_required()
def get_threat_intel_status():
    """Get threat intelligence status."""
    return jsonify({
        'total_indicators': random.randint(15000, 25000),
        'sources_enabled': random.randint(6, 8),
        'sources_total': 8,
        'indicators_by_type': {
            'ip': random.randint(8000, 12000),
            'domain': random.randint(5000, 8000),
            'url': random.randint(2000, 5000),
            'hash': random.randint(1000, 3000)
        },
        'last_update': datetime.now().isoformat(),
        'status': 'demo_mode'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors by serving React app."""
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization token required'}), 401

if __name__ == '__main__':
    print("Starting Simple Flask App")
    print("Backend: http://localhost:5000")
    print("Default credentials: admin/admin123 or demo/demo123")
    app.run(host='0.0.0.0', port=5000, debug=True)