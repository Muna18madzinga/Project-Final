""
Test Script for Security Features

This script tests the core security components of the application.
"""
import os
import sys
from flask import Flask, request, jsonify
from app.security.security_manager import SecurityManager
from config.security_config import SECURITY_CONFIG

app = Flask(__name__)

# Initialize security manager
security = SecurityManager(SECURITY_CONFIG)
security.start()

@app.route('/')
def home():
    return "Security Test Server Running"

@app.route('/test/network', methods=['GET'])
def test_network():
    """Test network security features."""
    ip = request.remote_addr
    return jsonify({
        'status': 'success',
        'ip': ip,
        'is_blocked': ip in [b[0] for b in security.list_blocked_ips()]
    })

@app.route('/test/firewall/block/<ip>', methods=['POST'])
def block_ip(ip):
    """Test IP blocking."""
    security.firewall.block_ip(ip, "Test block", 60)  # Block for 1 minute
    return jsonify({
        'status': 'success',
        'message': f'Blocked {ip} for 1 minute'
    })

@app.route('/test/firewall/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Test IP unblocking."""
    security.firewall.unblock_ip(ip)
    return jsonify({
        'status': 'success',
        'message': f'Unblocked {ip}'
    })

@app.route('/test/analyze', methods=['POST'])
def analyze_payload():
    """Test payload analysis."""
    data = request.get_data()
    result = security.analyze_traffic(
        packet=data,
        src_ip=request.remote_addr,
        dst_ip=request.host,
        dst_port=request.environ.get('REMOTE_PORT'),
        protocol='tcp'
    )
    return jsonify(result)

if __name__ == '__main__':
    try:
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
        print(f"Starting security test server on port {port}...")
        print(f"Access the server at: http://localhost:{port}")
        app.run(host='0.0.0.0', port=port, debug=True)
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)
