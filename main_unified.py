#!/usr/bin/env python3
"""
Adaptive Security Suite - Unified Flask Application with Real Data
Complete backend with real data integration - NO SIMULATED DATA
"""

import os
import json
import logging
import time
import sys
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Dict, List, Any, Optional
import sqlite3

# Add project root to path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

# Import real data components
try:
    from app.real_data_sources.real_data_integration import get_real_data_integrator
    from app.architecture.real_telemetry_collection import get_enhanced_telemetry_processor
    REAL_DATA_AVAILABLE = True
except ImportError as e:
    REAL_DATA_AVAILABLE = False
    print(f"⚠️  Real data sources not available: {e}")
    print("❌ This system REQUIRES real data components. Exiting.")
    sys.exit(1)

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

jwt = JWTManager(app)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Custom CORS implementation
ALLOWED_ORIGINS = ['http://localhost:3002', 'http://127.0.0.1:3002']

@app.after_request
def after_request(response):
    """Add CORS headers to all responses."""
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
        response.headers['Access-Control-Max-Age'] = '600'
    return response

@app.before_request
def handle_preflight():
    """Handle preflight OPTIONS requests."""
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            response = make_response('', 200)
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
            response.headers['Access-Control-Max-Age'] = '600'
            return response
        return make_response('Forbidden', 403)

# Global system components
real_data_integrator = None
telemetry_processor = None

def init_real_data():
    """Initialize real data collection system."""
    global real_data_integrator, telemetry_processor

    if not REAL_DATA_AVAILABLE:
        logger.error("Real data integration not available")
        return False

    try:
        real_data_integrator = get_real_data_integrator()
        telemetry_processor = get_enhanced_telemetry_processor()

        # Start real data collection
        config = {'api_keys': {}}
        real_data_integrator.start_real_data_collection(config)
        telemetry_processor.start_stream_processing(config)

        logger.info("✅ Real data integration started successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to initialize real data: {e}")
        return False

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
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            conn.commit()

            access_token = create_access_token(
                identity=username,
                additional_claims={'role': user[2], 'user_id': user[0]}
            )

            conn.close()

            return jsonify({
                'access_token': access_token,
                'user': {'id': user[0], 'username': username, 'role': user[2]}
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
    """Get real-time dashboard statistics - REAL DATA ONLY."""
    try:
        if not real_data_integrator or not telemetry_processor:
            return jsonify({'error': 'Real data collection not available'}), 503

        real_stats = real_data_integrator.get_real_time_stats()
        telemetry_stats = telemetry_processor.get_stream_stats()

        stats = {
            'timestamp': datetime.now().isoformat(),
            'system_status': 'operational',
            'real_data_available': True,
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
        }

        return jsonify(stats)

    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'error': f'Failed to get dashboard stats: {str(e)}'}), 500

@app.route('/api/threats/recent', methods=['GET'])
@jwt_required()
def get_recent_threats():
    """Get recent threat events - REAL DATA ONLY."""
    try:
        limit = request.args.get('limit', 50, type=int)

        if not telemetry_processor:
            return jsonify({'error': 'Real data collection not available'}), 503

        threats = []
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

        return jsonify({
            'threats': threats,
            'total': len(threats),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Get threats error: {e}")
        return jsonify({'error': f'Failed to get threats: {str(e)}'}), 500

@app.route('/api/network/events', methods=['GET'])
@jwt_required()
def get_network_events():
    """Get recent network events - REAL DATA ONLY."""
    try:
        limit = request.args.get('limit', 100, type=int)

        if not real_data_integrator:
            return jsonify({'error': 'Real data collection not available'}), 503

        events = []
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

        return jsonify({
            'events': events,
            'total': len(events),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Get network events error: {e}")
        return jsonify({'error': f'Failed to get network events: {str(e)}'}), 500

@app.route('/api/system/metrics', methods=['GET'])
@jwt_required()
def get_system_metrics():
    """Get system metrics - REAL DATA ONLY."""
    try:
        if not real_data_integrator:
            # Fallback to direct psutil
            import psutil
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_io_read': psutil.disk_io_counters().read_bytes if psutil.disk_io_counters() else 0,
                'disk_io_write': psutil.disk_io_counters().write_bytes if psutil.disk_io_counters() else 0,
                'network_bytes_sent': psutil.net_io_counters().bytes_sent if psutil.net_io_counters() else 0,
                'network_bytes_recv': psutil.net_io_counters().bytes_recv if psutil.net_io_counters() else 0,
                'active_connections': len(psutil.net_connections()),
                'processes_count': len(psutil.pids())
            }
            return jsonify(metrics)

        # Get from real data integrator
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
            import psutil
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_io_read': psutil.disk_io_counters().read_bytes if psutil.disk_io_counters() else 0,
                'disk_io_write': psutil.disk_io_counters().write_bytes if psutil.disk_io_counters() else 0,
                'network_bytes_sent': psutil.net_io_counters().bytes_sent if psutil.net_io_counters() else 0,
                'network_bytes_recv': psutil.net_io_counters().bytes_recv if psutil.net_io_counters() else 0,
                'active_connections': len(psutil.net_connections()),
                'processes_count': len(psutil.pids())
            }

        return jsonify(metrics)

    except Exception as e:
        logger.error(f"Get system metrics error: {e}")
        return jsonify({'error': f'Failed to get system metrics: {str(e)}'}), 500

@app.route('/api/devices', methods=['GET'])
@jwt_required()
def get_devices():
    """Get network devices."""
    try:
        # Return empty for now - device discovery not implemented yet
        return jsonify({
            'devices': [],
            'total': 0,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Get devices error: {e}")
        return jsonify({'error': 'Failed to get devices'}), 500

@app.route('/api/threat-intel/status', methods=['GET'])
@jwt_required()
def get_threat_intel_status():
    """Get threat intelligence feed status - REAL DATA ONLY."""
    try:
        if not real_data_integrator:
            return jsonify({'error': 'Real data collection not available'}), 503

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
    logger.info("=" * 60)
    logger.info("🛡️  ADAPTIVE SECURITY SUITE - UNIFIED REAL DATA SYSTEM")
    logger.info("=" * 60)

    # Initialize database
    init_database()
    logger.info("✅ Database initialized")

    # Initialize real data collection - REQUIRED
    if not init_real_data():
        logger.error("❌ Failed to initialize real data collection")
        logger.error("System cannot run without real data components")
        sys.exit(1)

    # Start Flask app
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('FLASK_DEBUG') == '1'

    logger.info(f"🚀 Starting Flask app on port {port}")
    logger.info("🌐 Web dashboard available with real data integration")
    logger.info("=" * 60)

    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)

if __name__ == '__main__':
    main()
