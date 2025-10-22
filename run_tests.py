#!/usr/bin/env python3
"""
Comprehensive test runner for Adaptive Security Suite
"""
import os
import sys
import subprocess
import argparse
from pathlib import Path

def run_command(cmd, description, ignore_errors=False):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"🔄 {description}")
    print(f"{'='*60}")
    print(f"Running: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.stdout:
        print("📤 STDOUT:")
        print(result.stdout)
    
    if result.stderr:
        print("⚠️  STDERR:")
        print(result.stderr)
    
    if result.returncode != 0 and not ignore_errors:
        print(f"❌ {description} failed with exit code {result.returncode}")
        return False
    elif result.returncode == 0:
        print(f"✅ {description} completed successfully")
    
    return True

def check_dependencies():
    """Check if test dependencies are installed."""
    print("🔍 Checking test dependencies...")
    
    required_packages = ['pytest', 'pytest-cov', 'bandit', 'safety']
    missing_packages = []
    
    for package in required_packages:
        result = subprocess.run([sys.executable, '-c', f'import {package.replace("-", "_")}'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("📦 Install with: pip install -r requirements-test.txt")
        return False
    
    print("✅ All test dependencies are installed")
    return True

def run_unit_tests():
    """Run unit and integration tests."""
    cmd = [
        sys.executable, '-m', 'pytest',
        'tests/',
        '-v',
        '--cov=app',
        '--cov=main',
        '--cov-report=html:htmlcov',
        '--cov-report=term-missing',
        '--cov-report=xml',
        '--tb=short'
    ]
    return run_command(cmd, "Unit and Integration Tests")

def run_security_tests():
    """Run security-focused tests."""
    success = True
    
    # Run security-specific pytest tests
    cmd = [sys.executable, '-m', 'pytest', 'tests/test_security.py', '-v', '-m', 'security']
    if not run_command(cmd, "Security Tests", ignore_errors=True):
        success = False
    
    # Run Bandit security linter
    cmd = ['bandit', '-r', 'app/', 'main.py', '-f', 'json', '-o', 'bandit-report.json']
    if not run_command(cmd, "Bandit Security Scan", ignore_errors=True):
        success = False
    
    # Run Safety vulnerability check
    cmd = ['safety', 'check', '--json', '--output', 'safety-report.json']
    if not run_command(cmd, "Safety Vulnerability Check", ignore_errors=True):
        success = False
    
    return success

def run_performance_tests():
    """Run performance tests."""
    cmd = [
        sys.executable, '-m', 'pytest',
        'tests/',
        '-v',
        '-m', 'performance',
        '--benchmark-only'
    ]
    return run_command(cmd, "Performance Tests", ignore_errors=True)

def run_load_tests():
    """Run load tests using simple requests."""
    print("\n🚀 Running basic load test...")
    
    load_test_script = '''
import requests
import time
import concurrent.futures
import statistics

def test_endpoint():
    try:
        start_time = time.time()
        response = requests.get("http://127.0.0.1:5000/health", timeout=5)
        end_time = time.time()
        return {
            "status_code": response.status_code,
            "response_time": end_time - start_time
        }
    except Exception as e:
        return {"error": str(e), "response_time": None}

def run_load_test(num_requests=50, concurrent_users=10):
    print(f"Running {num_requests} requests with {concurrent_users} concurrent users...")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_users) as executor:
        futures = [executor.submit(test_endpoint) for _ in range(num_requests)]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    
    # Calculate statistics
    successful_requests = [r for r in results if "error" not in r and r["status_code"] == 200]
    failed_requests = [r for r in results if "error" in r or r["status_code"] != 200]
    
    if successful_requests:
        response_times = [r["response_time"] for r in successful_requests]
        avg_response_time = statistics.mean(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)
        
        print(f"✅ Successful requests: {len(successful_requests)}/{num_requests}")
        print(f"📊 Average response time: {avg_response_time:.3f}s")
        print(f"⚡ Min response time: {min_response_time:.3f}s")
        print(f"⏱️  Max response time: {max_response_time:.3f}s")
    
    if failed_requests:
        print(f"❌ Failed requests: {len(failed_requests)}/{num_requests}")
        for i, failure in enumerate(failed_requests[:5]):  # Show first 5 failures
            print(f"   {i+1}. {failure}")
    
    return len(successful_requests) / num_requests > 0.95  # 95% success rate

if __name__ == "__main__":
    run_load_test()
'''
    
    # Write load test script
    with open('temp_load_test.py', 'w') as f:
        f.write(load_test_script)
    
    try:
        cmd = [sys.executable, 'temp_load_test.py']
        return run_command(cmd, "Load Tests", ignore_errors=True)
    finally:
        # Clean up
        if os.path.exists('temp_load_test.py'):
            os.remove('temp_load_test.py')

def run_code_quality_checks():
    """Run code quality checks."""
    success = True
    
    # Black formatting check
    cmd = ['black', '--check', '--diff', 'app/', 'main.py', 'tests/']
    if not run_command(cmd, "Black Code Formatting Check", ignore_errors=True):
        print("💡 Run 'black app/ main.py tests/' to fix formatting")
        success = False
    
    # Flake8 linting
    cmd = ['flake8', 'app/', 'main.py', '--max-line-length=100', '--extend-ignore=E203,W503']
    if not run_command(cmd, "Flake8 Linting", ignore_errors=True):
        success = False
    
    return success

def generate_test_report():
    """Generate a comprehensive test report."""
    print("\n📋 Generating Test Report...")
    
    report = f"""
# Test Report - Adaptive Security Suite
Generated: {os.popen('date').read().strip() if os.name != 'nt' else 'Windows'}

## Test Coverage
- HTML Coverage Report: file:///{Path.cwd()}/htmlcov/index.html
- XML Coverage Report: coverage.xml

## Security Reports
- Bandit Report: bandit-report.json
- Safety Report: safety-report.json

## Files Generated
- Test coverage: htmlcov/
- Security reports: bandit-report.json, safety-report.json

## Next Steps
1. Review coverage report and add tests for uncovered code
2. Address any security issues found in bandit/safety reports
3. Fix code quality issues if any were found
4. Consider running load tests against a staging environment

## Manual Security Testing Checklist
- [ ] SQL injection testing
- [ ] XSS prevention testing
- [ ] Authentication bypass testing
- [ ] Authorization testing
- [ ] Rate limiting verification
- [ ] Input validation testing
- [ ] Password security verification
- [ ] Session management testing
"""
    
    with open('test-report.md', 'w') as f:
        f.write(report)
    
    print("📄 Test report generated: test-report.md")

def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description='Comprehensive test runner for Adaptive Security Suite')
    parser.add_argument('--unit', action='store_true', help='Run unit tests only')
    parser.add_argument('--security', action='store_true', help='Run security tests only')
    parser.add_argument('--performance', action='store_true', help='Run performance tests only')
    parser.add_argument('--load', action='store_true', help='Run load tests only')
    parser.add_argument('--quality', action='store_true', help='Run code quality checks only')
    parser.add_argument('--all', action='store_true', help='Run all tests (default)')
    parser.add_argument('--skip-deps', action='store_true', help='Skip dependency check')
    
    args = parser.parse_args()
    
    # If no specific test type is specified, run all
    if not any([args.unit, args.security, args.performance, args.load, args.quality]):
        args.all = True
    
    print("🧪 Adaptive Security Suite - Test Runner")
    print("=" * 50)
    
    # Check dependencies
    if not args.skip_deps and not check_dependencies():
        return 1
    
    success = True
    
    # Run tests based on arguments
    if args.unit or args.all:
        success &= run_unit_tests()
    
    if args.security or args.all:
        success &= run_security_tests()
    
    if args.performance or args.all:
        success &= run_performance_tests()
    
    if args.load or args.all:
        success &= run_load_tests()
    
    if args.quality or args.all:
        success &= run_code_quality_checks()
    
    # Generate report
    generate_test_report()
    
    # Summary
    print(f"\n{'='*60}")
    if success:
        print("🎉 All tests completed successfully!")
        print("📊 Check htmlcov/index.html for detailed coverage report")
        return 0
    else:
        print("⚠️  Some tests failed or had issues")
        print("📋 Check test-report.md for details and next steps")
        return 1

if __name__ == '__main__':
    sys.exit(main())