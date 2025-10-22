# Testing Guide - Adaptive Security Suite

## Overview

This guide covers comprehensive testing strategies for the Adaptive Security Suite, including unit tests, integration tests, security tests, and performance tests.

## Quick Start

### 1. Install Test Dependencies
```bash
pip install -r requirements-test.txt
```

### 2. Run All Tests
```bash
python run_tests.py
```

### 3. Run Specific Test Categories
```bash
# Unit tests only
python run_tests.py --unit

# Security tests only
python run_tests.py --security

# Performance tests only
python run_tests.py --performance

# Load tests only
python run_tests.py --load

# Code quality checks only
python run_tests.py --quality
```

## Test Structure

```
tests/
├── __init__.py
├── conftest.py           # Test configuration and fixtures
├── test_auth.py         # Authentication module tests
├── test_encryption.py   # Encryption module tests
└── test_security.py     # Security-specific tests
```

## Test Categories

### 1. Unit Tests (`test_auth.py`, `test_encryption.py`)
- **Authentication Tests**: Registration, login, token management
- **Encryption Tests**: Data encryption/decryption, key management
- **Input Validation**: Schema validation, sanitization
- **Error Handling**: Proper error responses and logging

### 2. Integration Tests
- **API Endpoint Tests**: Full request/response cycles
- **Database Integration**: User storage, token blacklisting
- **Cross-module Integration**: Auth + encryption workflows

### 3. Security Tests (`test_security.py`)
- **Authentication Security**: Token manipulation, session security
- **Authorization**: Access control, privilege escalation
- **Input Security**: SQL injection, XSS prevention
- **Rate Limiting**: Abuse prevention
- **Password Security**: Hashing, strength validation

### 4. Performance Tests
- **Response Time**: API endpoint performance
- **Load Testing**: Concurrent user simulation
- **Resource Usage**: Memory and CPU monitoring
- **Benchmark Tests**: Encryption/decryption performance

## Running Individual Tests

### Run Specific Test Files
```bash
# Authentication tests
pytest tests/test_auth.py -v

# Encryption tests  
pytest tests/test_encryption.py -v

# Security tests
pytest tests/test_security.py -v
```

### Run Specific Test Classes
```bash
# Test user registration only
pytest tests/test_auth.py::TestAuthRegistration -v

# Test encryption endpoints only
pytest tests/test_encryption.py::TestEncryptionEndpoints -v
```

### Run Tests by Markers
```bash
# Security-focused tests only
pytest -m security -v

# Performance tests only
pytest -m performance -v

# Skip slow tests
pytest -m "not slow" -v
```

## Test Configuration

### Environment Variables for Testing
```bash
# Set in .env or export directly
FLASK_ENV=testing
SECRET_KEY=test-secret-key
JWT_SECRET_KEY=test-jwt-secret
ENCRYPTION_PASSWORD=test-password
ENCRYPTION_SALT=test-salt
```

### Test Database
Tests use an in-memory SQLite database that's created and destroyed for each test session.

### Mock External Services
- OpenAI API calls are mocked in security tests
- Email services are mocked (if implemented)
- Network services use test doubles

## Coverage Reports

### Generate Coverage Report
```bash
pytest --cov=app --cov=main --cov-report=html:htmlcov --cov-report=term-missing
```

### View Coverage Report
Open `htmlcov/index.html` in your browser to see detailed coverage information.

### Coverage Targets
- **Minimum Coverage**: 80%
- **Critical Modules**: 90%+ (auth, encryption, security)
- **Line Coverage**: Focus on business logic
- **Branch Coverage**: Test all conditional paths

## Security Testing

### Automated Security Tests
```bash
# Run Bandit security linter
bandit -r app/ main.py -f json -o bandit-report.json

# Run Safety vulnerability check
safety check --json --output safety-report.json

# Run security-specific pytest tests
pytest tests/test_security.py -v
```

### Manual Security Testing Checklist

#### Authentication & Authorization
- [ ] SQL injection in login forms
- [ ] Brute force protection
- [ ] Session fixation attacks
- [ ] Privilege escalation attempts
- [ ] Token manipulation attacks

#### Input Validation
- [ ] XSS in all input fields
- [ ] Command injection attempts
- [ ] Path traversal attacks
- [ ] File upload vulnerabilities
- [ ] JSON injection attacks

#### API Security
- [ ] CORS policy verification
- [ ] Rate limiting effectiveness
- [ ] HTTP method tampering
- [ ] Content-Type validation
- [ ] Request size limits

#### Data Protection
- [ ] Encryption key exposure
- [ ] Data at rest encryption
- [ ] Data in transit encryption
- [ ] Key rotation procedures
- [ ] Backup security

### Security Testing Tools

#### Automated Tools
```bash
# OWASP ZAP (if available)
zap-baseline.py -t http://localhost:5000

# Nikto web scanner (if available)
nikto -h localhost:5000

# Custom security scanner
python tests/security_scanner.py
```

#### Manual Testing Tools
- **Burp Suite Community**: Web application security testing
- **OWASP ZAP**: Free security scanner
- **Postman**: API testing with security test cases
- **curl**: Command-line HTTP testing

## Performance Testing

### Load Testing with Locust
```python
# Create locustfile.py
from locust import HttpUser, task, between

class SecuritySuiteUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        # Register and login
        self.client.post("/auth/register", json={
            "username": f"user_{self.environment.runner.user_count}",
            "password": "TestPassword123!@#",
            "email": f"user_{self.environment.runner.user_count}@example.com"
        })
        
        response = self.client.post("/auth/login", json={
            "username": f"user_{self.environment.runner.user_count}",
            "password": "TestPassword123!@#"
        })
        
        if response.status_code == 200:
            self.token = response.json()["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
    
    @task(3)
    def health_check(self):
        self.client.get("/health")
    
    @task(2)  
    def encrypt_data(self):
        self.client.post("/encryption/encrypt", 
                        json={"data": "test data"},
                        headers=self.headers)
    
    @task(1)
    def risk_assessment(self):
        self.client.post("/adaptive/risk-assessment",
                        json={
                            "user_id": f"user_{self.environment.runner.user_count}",
                            "context": {"time_of_day": 0.5, "failed_attempts": 0}
                        },
                        headers=self.headers)
```

```bash
# Run load test
locust -f locustfile.py --host=http://localhost:5000
```

### Benchmark Testing
```bash
# Run benchmark tests
pytest tests/ --benchmark-only --benchmark-sort=mean
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Security Suite Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-test.txt
    
    - name: Run tests
      run: python run_tests.py --all
    
    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
    
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          bandit-report.json
          safety-report.json
```

## Test Data Management

### Test Fixtures
- **User Data**: Various user types (regular, admin, inactive)
- **Encryption Data**: Different data types and sizes
- **Risk Contexts**: Various risk scenarios
- **Threat Data**: Sample threat intelligence

### Database State
- Tests use isolated database instances
- Each test gets fresh database state
- Cleanup handled automatically

## Debugging Tests

### Run Tests with Debugging
```bash
# Run with verbose output
pytest -v -s tests/test_auth.py

# Run specific test with debugger
pytest --pdb tests/test_auth.py::TestAuthLogin::test_successful_login

# Run with coverage and debugging
pytest --cov=app --cov-report=term-missing -v -s tests/
```

### Common Issues
1. **Import Errors**: Check PYTHONPATH and module structure
2. **Database Errors**: Ensure test database is properly isolated
3. **Token Issues**: Check JWT configuration in test environment
4. **Mock Failures**: Verify mock configurations match actual implementations

## Test Maintenance

### Adding New Tests
1. Follow naming conventions (`test_*.py`, `Test*` classes)
2. Use appropriate fixtures from `conftest.py`
3. Add docstrings explaining test purpose
4. Include both positive and negative test cases
5. Add performance tests for critical operations

### Updating Tests
1. Update tests when changing functionality
2. Maintain test data relevance
3. Review and update security tests regularly
4. Keep performance benchmarks current

### Test Review Checklist
- [ ] Tests cover new functionality
- [ ] Security implications tested
- [ ] Performance impact assessed
- [ ] Error conditions handled
- [ ] Documentation updated

## Reporting Issues

When tests fail:
1. Check the test output and error messages
2. Review the generated reports (coverage, security)
3. Verify test environment configuration
4. Check for recent code changes that might affect tests
5. Report persistent failures with full context

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Clear Naming**: Test names should describe what they test
3. **Comprehensive Coverage**: Test both success and failure cases
4. **Security Focus**: Always include security considerations
5. **Performance Awareness**: Monitor test execution time
6. **Documentation**: Keep test documentation current