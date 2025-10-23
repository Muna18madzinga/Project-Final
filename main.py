#!/usr/bin/env python3
"""
Adaptive Security Suite - Flask Application (Fixed & Updated)
Complete backend with real data integration and consistent API endpoints
"""

import os
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Dict, List, Any, Optional
import sqlite3
from dataclasses import asdict

# Import real data integrator
try:
    from app.real_data_sources.real_data_integration import get_real_data_integrator
    from app.architecture.real_telemetry_collection import get_enhanced_telemetry_processor
    REAL_DATA_AVAILABLE = True
except ImportError as e:
    REAL_DATA_AVAILABLE = False
    print(f"⚠️  Real data sources not available: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__, static_folder='static/dist', static_url_path='')

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Initialize extensions
CORS(app, origins=['http://localhost:3000', 'http://localhost:5173', 'http://localhost:3002'])
jwt = JWTManager(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize real data components
real_data_integrator = None
telemetry_processor = None

def init_real_data():
    """Initialize real data collection system."""
    global real_data_integrator, telemetry_processor
    
    if not REAL_DATA_AVAILABLE:
        logger.warning("Real data integration not available")
        return False
    
    try:
        real_data_integrator = get_real_data_integrator()
        telemetry_processor = get_enhanced_telemetry_processor()
        
        # Start real data collection
        config = {
            'api_keys': {
                # Add API keys from environment if available
            }
        }
        
        real_data_integrator.start_real_data_collection(config)
        telemetry_processor.start_stream_processing(config)
        
        logger.info("Real data integration started successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize real data: {e}")
        return False

# Database setup
def init_database():
    """Initialize SQLite database for user management."""
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create default admin user
    admin_hash = generate_password_hash('admin123')
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('admin', admin_hash, 'admin'))
    
    conn.commit()
    conn.close()

# API Routes

@app.route('/')
def index():
    """Serve React frontend."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """User authentication endpoint."""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = sqlite3.connect('security.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, password_hash, role FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user[1], password):
            # Update last login
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            conn.commit()
            
            # Create access token
            access_token = create_access_token(
                identity=username,
                additional_claims={'role': user[2], 'user_id': user[0]}
            )
            
            conn.close()
            
            return jsonify({
                'access_token': access_token,
                'user': {
                    'id': user[0],
                    'username': username,
                    'role': user[2]
                }
            })
        
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user information."""
    try:
        current_user = get_jwt_identity()
        conn = sqlite3.connect('security.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, role, last_login FROM users WHERE username = ?', (current_user,))
        user = cursor.fetchone()
        
        conn.close()
        
        if user:
            return jsonify({
                'id': user[0],
                'username': user[1],
                'role': user[2],
                'last_login': user[3]
            })
        
        return jsonify({'error': 'User not found'}), 404
        
    except Exception as e:
        logger.error(f"Get user error: {e}")
        return jsonify({'error': 'Failed to get user'}), 500

@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """Get real-time dashboard statistics."""
    try:
        stats = {
            'timestamp': datetime.now().isoformat(),
            'system_status': 'operational',
            'real_data_available': REAL_DATA_AVAILABLE
        }
        
        if REAL_DATA_AVAILABLE and real_data_integrator and telemetry_processor:
            # Get real-time stats
            real_stats = real_data_integrator.get_real_time_stats()
            telemetry_stats = telemetry_processor.get_stream_stats()
            
            stats.update({
                'network': {
                    'packets_captured': real_stats['network_collection']['packets_captured'],
                    'active_flows': real_stats['network_collection']['active_flows'],
                    'interface': real_stats['network_collection']['interface'],
                    'packets_per_second': real_stats['network_collection']['packets_per_second']
                },
                'threats': {
                    'total_indicators': real_stats['threat_intelligence']['total_indicators'],
                    'threat_matches': real_stats['integrator']['threat_matches'],
                    'high_risk_events': real_stats['integrator']['high_risk_events']
                },
                'telemetry': {
                    'events_processed': telemetry_stats['event_analytics']['total_processed'],
                    'threat_events': telemetry_stats['event_analytics']['threat_events'],
                    'network_events': telemetry_stats['event_analytics']['network_events'],
                    'system_events': telemetry_stats['event_analytics']['system_events']
                }
            })
        else:
            # Fallback simulated stats
            import random
            stats.update({
                'network': {
                    'packets_captured': random.randint(1000, 10000),
                    'active_flows': random.randint(10, 100),
                    'interface': 'simulated',
                    'packets_per_second': random.uniform(10, 100)
                },
                'threats': {
                    'total_indicators': random.randint(5000, 15000),
                    'threat_matches': random.randint(1, 20),
                    'high_risk_events': random.randint(0, 5)
                },
                'telemetry': {
                    'events_processed': random.randint(100, 1000),
                    'threat_events': random.randint(5, 50),
                    'network_events': random.randint(50, 500),
                    'system_events': random.randint(20, 200)
                }
            })
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'error': 'Failed to get dashboard stats'}), 500

@app.route('/api/threats/recent', methods=['GET'])
@jwt_required()
def get_recent_threats():
    """Get recent threat events."""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        threats = []
        
        if REAL_DATA_AVAILABLE and telemetry_processor:
            # Get real threat events
            real_threats = telemetry_processor.telemetry_collector.get_threat_events(limit)
            for threat in real_threats:
                threats.append({
                    'id': threat['correlation_id'],
                    'timestamp': threat['timestamp'],
                    'source': threat['source'],
                    'type': threat['data_type'],
                    'severity': 'high' if threat['threat_score'] > 0.8 else 'medium' if threat['threat_score'] > 0.5 else 'low',
                    'threat_score': threat['threat_score'],
                    'indicators': threat['risk_indicators'],
                    'summary': threat.get('payload_summary', {}),
                    'status': 'active'
                })
        else:
            # Generate simulated threat events
            import random
            from uuid import uuid4
            
            threat_types = ['network_intrusion', 'malware_detection', 'suspicious_activity', 'port_scan', 'ddos_attempt']
            sources = ['network', 'system', 'endpoint']
            severities = ['low', 'medium', 'high', 'critical']
            
            for i in range(min(limit, 20)):
                threats.append({
                    'id': str(uuid4()),
                    'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
                    'source': random.choice(sources),
                    'type': random.choice(threat_types),
                    'severity': random.choice(severities),
                    'threat_score': random.uniform(0.3, 1.0),
                    'indicators': [f'indicator_{i}'],
                    'summary': {'description': f'Simulated threat event {i}'},
                    'status': random.choice(['active', 'investigating', 'resolved'])
                })
        
        return jsonify({
            'threats': threats,
            'total': len(threats),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Get threats error: {e}")
        return jsonify({'error': 'Failed to get threats'}), 500

@app.route('/api/network/events', methods=['GET'])
@jwt_required()
def get_network_events():
    """Get recent network events."""
    try:
        limit = request.args.get('limit', 100, type=int)
        
        events = []
        
        if REAL_DATA_AVAILABLE and real_data_integrator:
            # Get real network events
            real_events = real_data_integrator.get_recent_events(limit, 'network_traffic')
            for event in real_events:
                events.append({
                    'id': event['event_id'],
                    'timestamp': event['timestamp'],
                    'source_ip': event['data']['source_ip'],
                    'dest_ip': event['data']['dest_ip'],
                    'source_port': event['data'].get('source_port'),
                    'dest_port': event['data'].get('dest_port'),
                    'protocol': event['data']['protocol'],
                    'packet_size': event['data']['packet_size'],
                    'threat_score': event['threat_score'],
                    'threat_indicators': event['threat_indicators']
                })
        else:
            # Generate simulated network events
            import random
            from uuid import uuid4
            
            for i in range(min(limit, 50)):
                events.append({
                    'id': str(uuid4()),
                    'timestamp': (datetime.now() - timedelta(seconds=random.randint(1, 3600))).isoformat(),
                    'source_ip': f"192.168.1.{random.randint(1, 254)}",
                    'dest_ip': f"10.0.0.{random.randint(1, 254)}",
                    'source_port': random.randint(1024, 65535),
                    'dest_port': random.choice([80, 443, 22, 3389, 445]),
                    'protocol': random.choice(['tcp', 'udp']),
                    'packet_size': random.randint(64, 1500),
                    'threat_score': random.uniform(0.0, 1.0),
                    'threat_indicators': []
                })
        
        return jsonify({
            'events': events,
            'total': len(events),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Get network events error: {e}")
        return jsonify({'error': 'Failed to get network events'}), 500

@app.route('/api/system/metrics', methods=['GET'])
@jwt_required()
def get_system_metrics():
    """Get system metrics."""
    try:
        if REAL_DATA_AVAILABLE and real_data_integrator:
            # Get real system metrics
            real_events = real_data_integrator.get_recent_events(10, 'system_metrics')
            if real_events:
                latest_event = real_events[0]
                metrics = {
                    'timestamp': latest_event['timestamp'],
                    'cpu_percent': latest_event['data']['cpu_percent'],
                    'memory_percent': latest_event['data']['memory_percent'],
                    'disk_io_read': latest_event['data']['disk_io_read'],
                    'disk_io_write': latest_event['data']['disk_io_write'],
                    'network_bytes_sent': latest_event['data']['network_bytes_sent'],
                    'network_bytes_recv': latest_event['data']['network_bytes_recv'],
                    'active_connections': latest_event['data']['active_connections'],
                    'processes_count': latest_event['data']['processes_count']
                }
            else:
                # Fallback to psutil directly
                import psutil
                metrics = {
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_io_read': psutil.disk_io_counters().read_bytes if psutil.disk_io_counters() else 0,
                    'disk_io_write': psutil.disk_io_counters().write_bytes if psutil.disk_io_counters() else 0,
                    'network_bytes_sent': psutil.net_io_counters().bytes_sent if psutil.net_io_counters() else 0,
                    'network_bytes_recv': psutil.net_io_counters().bytes_recv if psutil.net_io_counters() else 0,
                    'active_connections': len(psutil.net_connections()),
                    'processes_count': len(psutil.pids())
                }
        else:
            # Simulated metrics
            import random
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': random.uniform(10, 90),
                'memory_percent': random.uniform(20, 80),
                'disk_io_read': random.randint(1000000, 10000000),
                'disk_io_write': random.randint(500000, 5000000),
                'network_bytes_sent': random.randint(1000000, 100000000),
                'network_bytes_recv': random.randint(2000000, 200000000),
                'active_connections': random.randint(50, 300),
                'processes_count': random.randint(100, 400)
            }
        
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Get system metrics error: {e}")
        return jsonify({'error': 'Failed to get system metrics'}), 500

@app.route('/api/devices', methods=['GET'])
@jwt_required()
def get_devices():
    """Get network devices using multi-method discovery with full network scanning."""
    try:
        from app.utils.network_device_discovery import get_device_discovery

        # Get query parameters
        scan = request.args.get('scan', 'true').lower() == 'true'  # Default to TRUE for full scan
        methods_param = request.args.get('methods', 'arp,ping')  # Default: ARP + Ping for full discovery
        methods = methods_param.split(',')

        device_discovery = get_device_discovery()

        if scan:
            # Perform full network scan with ARP + Ping to discover ALL devices
            logger.info(f"Performing FULL network scan with methods: {methods}")
            devices = device_discovery.discover_devices(methods=methods)
        else:
            # Return cached devices
            devices = device_discovery.get_cached_devices()

            # If no cached devices, perform a full scan
            if not devices:
                logger.info("No cached devices, performing full network scan with ARP + Ping")
                devices = device_discovery.discover_devices(methods=['arp', 'ping'])
        
        return jsonify({
            'devices': devices,
            'total': len(devices),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Get devices error: {e}")
        return jsonify({'error': 'Failed to get devices'}), 500

@app.route('/api/threat-intel/status', methods=['GET'])
@jwt_required()
def get_threat_intel_status():
    """Get threat intelligence feed status."""
    try:
        if REAL_DATA_AVAILABLE and real_data_integrator:
            real_stats = real_data_integrator.get_real_time_stats()
            threat_stats = real_stats['threat_intelligence']
            
            status = {
                'total_indicators': threat_stats['total_indicators'],
                'sources_enabled': threat_stats['sources_enabled'],
                'sources_total': threat_stats['sources_total'],
                'indicators_by_type': threat_stats.get('indicators_by_type', {}),
                'last_update': datetime.now().isoformat(),
                'status': 'active' if threat_stats['is_running'] else 'inactive'
            }
        else:
            # Simulated threat intel status
            import random
            status = {
                'total_indicators': random.randint(10000, 50000),
                'sources_enabled': random.randint(5, 8),
                'sources_total': 8,
                'indicators_by_type': {
                    'ip': random.randint(5000, 15000),
                    'domain': random.randint(3000, 10000),
                    'url': random.randint(2000, 8000),
                    'hash': random.randint(1000, 5000)
                },
                'last_update': datetime.now().isoformat(),
                'status': 'simulated'
            }
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Get threat intel status error: {e}")
        return jsonify({'error': 'Failed to get threat intel status'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors by serving React app."""
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal error: {error}")
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

def main():
    """Main entry point."""
    logger.info("Starting Adaptive Security Suite Flask Application")
    
    # Initialize database
    init_database()
    logger.info("Database initialized")
    
    # Initialize real data collection
    if init_real_data():
        logger.info("Real data integration started")
    else:
        logger.warning("Running with simulated data")
    
    # Start Flask app
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logger.info(f"Starting Flask app on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)

if __name__ == '__main__':
    main()
