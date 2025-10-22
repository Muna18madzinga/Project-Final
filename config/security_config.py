"""
Security Configuration

Configuration settings for the security components.
"""

# Security Manager Configuration
SECURITY_CONFIG = {
    # General Settings
    'monitoring_enabled': True,
    'block_malicious': True,
    'alert_threshold': 0.7,  # 0-1 threat score
    
    # Network Monitoring
    'network_interface': None,  # Auto-detect if None
    'port_scan_threshold': 10,  # Max ports scanned per minute
    'ddos_threshold': 100,      # Max connections per minute
    'syn_flood_threshold': 50,  # Max SYN packets per second
    
    # Logging
    'log_file': 'security.log',
    'log_level': 'INFO',  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    
    # Whitelisted IPs (never blocked)
    'whitelisted_ips': [
        '127.0.0.1',
        'http://localhost:3002'  # Localhost
        '::1',        # IPv6 localhost
    ],
    
    # Known malicious IPs (always blocked)
    'blacklisted_ips': [
        # Add known malicious IPs here
    ],
    
    # Email alerts configuration
    'email_alerts': {
        'enabled': False,
        'smtp_server': 'smtp.example.com',
        'smtp_port': 587,
        'use_tls': True,
        'username': 'alerts@example.com',
        'password': 'your_password',
        'from_addr': 'security@yourdomain.com',
        'to_addrs': ['admin@yourdomain.com'],
        'subject_prefix': '[Security Alert] '
    }
}

# Password Security Settings
PASSWORD_CONFIG = {
    'min_length': 12,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digits': True,
    'require_special_chars': True,
    'max_password_age_days': 90,
    'password_history': 5,  # Remember last N passwords
    'max_attempts': 5,     # Max failed attempts before lockout
    'lockout_minutes': 15  # Account lockout duration
}

# API Security
API_SECURITY = {
    'rate_limiting': {
        'enabled': True,
        'max_requests': 100,  # Max requests per window
        'window_minutes': 15  # Time window in minutes
    },
    'require_https': True,
    'cors_allowed_origins': [
        'https://yourdomain.com',
        'http://localhost:3000',
        'http://localhost:3002'  # For development
    ]
}

# Session Security
SESSION_CONFIG = {
    'cookie_secure': True,
    'cookie_httponly': True,
    'cookie_samesite': 'Lax',  # or 'Strict'
    'session_timeout_minutes': 30,
    'session_regeneration': True  # Regenerate session ID on login
}
