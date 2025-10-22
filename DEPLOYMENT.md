# Deployment Guide - Adaptive Security Suite

## Security Fixes Implemented

### ✅ Critical Security Vulnerabilities Fixed

1. **Authentication & Session Management**
   - ❌ **FIXED**: Debug mode disabled by default
   - ❌ **FIXED**: JWT-based authentication with secure tokens
   - ❌ **FIXED**: Account lockout after failed login attempts
   - ❌ **FIXED**: Password strength validation (12+ chars, complexity)
   - ❌ **FIXED**: Secure session cookies with proper flags

2. **Input Validation & Sanitization**
   - ❌ **FIXED**: Marshmallow schema validation on all endpoints
   - ❌ **FIXED**: Input sanitization to prevent injection attacks
   - ❌ **FIXED**: Request size and rate limiting implemented

3. **API Security**
   - ❌ **FIXED**: CORS protection with whitelisted origins
   - ❌ **FIXED**: Security headers (CSP, X-Frame-Options, etc.)
   - ❌ **FIXED**: Rate limiting (100 req/hour default)
   - ❌ **FIXED**: Authentication required on sensitive endpoints

4. **Encryption & Key Management**
   - ❌ **FIXED**: Environment variable-based key storage
   - ❌ **FIXED**: PBKDF2 key derivation for fallback
   - ❌ **FIXED**: Secure Fernet encryption with proper error handling

5. **Database Integration**
   - ❌ **FIXED**: SQLAlchemy ORM with proper models
   - ❌ **FIXED**: Database-backed user storage (no more in-memory)
   - ❌ **FIXED**: Token blacklist stored in database

6. **Logging & Monitoring**
   - ❌ **FIXED**: Comprehensive security event logging
   - ❌ **FIXED**: Structured logging with timestamps and user tracking
   - ❌ **FIXED**: Error handling without information disclosure

## Quick Start

### 1. Environment Setup
```bash
# Copy environment template
cp .env.template .env

# Edit .env with your secure values
nano .env
```

### 2. Required Environment Variables
```bash
# Generate secure keys
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python main.py
# Default admin created: admin / ChangeMe123!@#
```

### 4. Production Deployment

#### Docker Deployment (Recommended)
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "main:app"]
```

#### Environment Variables for Production
```bash
# Required
SECRET_KEY=your-32-char-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
ENCRYPTION_KEY=your-fernet-key

# Database
DATABASE_URL=postgresql://user:pass@localhost/security_db

# Security
FLASK_DEBUG=False
HTTPS_ONLY=True
SECURE_COOKIES=True

# Optional
OPENAI_API_KEY=your-openai-key
RATE_LIMIT_STORAGE_URL=redis://localhost:6379
```

## API Documentation

### Authentication Endpoints
```bash
# Register user
POST /auth/register
{
  "username": "user123",
  "password": "SecurePass123!@#",
  "email": "user@example.com"
}

# Login
POST /auth/login
{
  "username": "user123", 
  "password": "SecurePass123!@#"
}

# Get profile (requires token)
GET /auth/profile
Headers: Authorization: Bearer <access_token>
```

### Encryption Endpoints
```bash
# Encrypt data (requires token)
POST /encryption/encrypt
Headers: Authorization: Bearer <access_token>
{
  "data": "sensitive information"
}

# Decrypt data (requires token)  
POST /encryption/decrypt
Headers: Authorization: Bearer <access_token>
{
  "encrypted": "gAAAAABh..."
}
```

### Risk Assessment
```bash
# Assess risk (requires token)
POST /adaptive/risk-assessment
Headers: Authorization: Bearer <access_token>
{
  "user_id": "user123",
  "context": {
    "time_of_day": 0.5,
    "failed_attempts": 0,
    "location_change": false,
    "device_change": false
  }
}
```

## Security Recommendations

### Immediate Actions Required
1. **Change Default Admin Password**
   ```bash
   # Login as admin and change password immediately
   curl -X POST http://localhost:5000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"ChangeMe123!@#"}'
   ```

2. **Set Strong Environment Variables**
   - Generate unique SECRET_KEY and JWT_SECRET_KEY
   - Use strong ENCRYPTION_KEY from Fernet.generate_key()
   - Set secure database credentials

3. **Enable HTTPS in Production**
   - Use reverse proxy (nginx/Apache) with SSL/TLS
   - Set HTTPS_ONLY=True and SECURE_COOKIES=True
   - Implement HSTS headers

### Ongoing Security Practices
- Regularly rotate encryption keys
- Monitor security logs for suspicious activity
- Keep dependencies updated
- Implement backup and recovery procedures
- Use database connection pooling for production

## Production Checklist
- [ ] Environment variables configured securely
- [ ] Default admin password changed
- [ ] HTTPS/TLS enabled
- [ ] Database properly secured
- [ ] Logging and monitoring in place
- [ ] Rate limiting configured
- [ ] Backup strategy implemented
- [ ] Security testing completed

## Monitoring & Alerts
Security events are logged to `security.log`:
- Authentication attempts (success/failure)
- Risk assessments performed
- Adaptive engine updates
- Encryption operations
- Admin actions

Set up log monitoring and alerting for production environments.