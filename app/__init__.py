"""
Application Factory

This module initializes the Flask application and configures all extensions.
"""
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config.security_config import SECURITY_CONFIG, API_SECURITY, SESSION_CONFIG

# Initialize extensions
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{API_SECURITY['rate_limiting']['max_requests']} per "
                   f"{API_SECURITY['rate_limiting']['window_minutes']} minutes"]
    if API_SECURITY['rate_limiting']['enabled'] else []
)

def create_app(config_name='default'):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('config.settings')
    
    # Configure CORS
    CORS(
        app,
        resources={
            r"/*": {"origins": API_SECURITY['cors_allowed_origins']}
        },
        supports_credentials=True
    )
    
    # Initialize rate limiting
    limiter.init_app(app)
    
    # Configure session security
    app.config.update(
        SESSION_COOKIE_SECURE=SESSION_CONFIG['cookie_secure'],
        SESSION_COOKIE_HTTPONLY=SESSION_CONFIG['cookie_httponly'],
        SESSION_COOKIE_SAMESITE=SESSION_CONFIG['cookie_samesite'],
        PERMANENT_SESSION_LIFETIME=SESSION_CONFIG['session_timeout_minutes'] * 60
    )
    
    # Register blueprints
    from .auth import auth_bp
    from .api import api_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Initialize security manager
    from .security.security_manager import SecurityManager
    app.security = SecurityManager(SECURITY_CONFIG)
    app.security.start()
    
    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self';"
        return response
    
    # Error handlers
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return {
            'error': 'Too many requests',
            'message': 'Rate limit exceeded. Please try again later.'
        }, 429
    
    @app.errorhandler(404)
    def not_found_handler(e):
        return {'error': 'Not found'}, 404
    
    @app.errorhandler(500)
    def internal_error_handler(e):
        # Log the error
        app.logger.error(f'Internal Server Error: {str(e)}')
        return {'error': 'Internal server error'}, 500
    
    return app
