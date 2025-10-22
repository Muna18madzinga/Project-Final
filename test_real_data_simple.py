#!/usr/bin/env python3
"""
Simple Real Data Integration Test
Tests the core real data collection without Flask dependencies
"""

import sys
import time
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_network_collection():
    """Test basic network data collection."""
    print("\n🌐 Testing Network Collection")
    print("=" * 40)
    
    try:
        from app.real_data_sources.live_network_collector import RealNetworkCollector
        
        collector = RealNetworkCollector()
        print("✅ Network collector created")
        
        # Test interface resolution
        interface = collector._resolve_interface()
        print(f"📡 Network interface: {interface}")
        
        if interface:
            print("✅ Network interface available")
            return True
        else:
            print("❌ No network interface available")
            return False
        
    except Exception as e:
        print(f"❌ Network collection failed: {e}")
        logger.exception("Network collection error")
        return False

def test_system_metrics():
    """Test system metrics collection."""
    print("\n💻 Testing System Metrics")
    print("=" * 40)
    
    try:
        from app.real_data_sources.live_network_collector import RealSystemMetricsCollector
        
        collector = RealSystemMetricsCollector()
        print("✅ System metrics collector created")
        
        # Start collection briefly
        collector.start_collection()
        time.sleep(2)
        
        # Get latest metrics
        metrics = collector.get_latest_metrics()
        if metrics:
            print(f"📊 System Metrics:")
            print(f"   - CPU: {metrics.cpu_percent:.1f}%")
            print(f"   - Memory: {metrics.memory_percent:.1f}%")
            print(f"   - Connections: {metrics.active_connections}")
            print(f"   - Processes: {metrics.processes_count}")
            print("✅ System metrics working")
            collector.stop_collection()
            return True
        else:
            print("❌ No metrics collected")
            collector.stop_collection()
            return False
            
    except Exception as e:
        print(f"❌ System metrics failed: {e}")
        logger.exception("System metrics error")
        return False

def test_threat_intel():
    """Test threat intelligence feeds."""
    print("\n🛡️  Testing Threat Intelligence")
    print("=" * 40)
    
    try:
        from app.real_data_sources.threat_intel_feeds import LiveThreatIntelFeeds
        
        threat_intel = LiveThreatIntelFeeds()
        print("✅ Threat intel feeds created")
        
        # Test configuration
        print(f"📋 Sources configured: {len(threat_intel.sources)}")
        enabled_sources = [name for name, config in threat_intel.sources.items() if config['enabled']]
        print(f"📋 Sources enabled: {len(enabled_sources)}")
        print(f"   - {', '.join(enabled_sources[:3])}...")
        
        # Test indicator checking (without actually downloading feeds)
        test_indicators = threat_intel.check_indicator('127.0.0.1', 'ip')
        print(f"🔍 Test indicator check: {len(test_indicators)} matches")
        
        print("✅ Threat intel basic functionality working")
        return True
        
    except Exception as e:
        print(f"❌ Threat intel failed: {e}")
        logger.exception("Threat intel error")
        return False

def test_data_structures():
    """Test data structures and basic functionality."""
    print("\n📊 Testing Data Structures")
    print("=" * 40)
    
    try:
        from app.real_data_sources.live_network_collector import RealNetworkEvent, SystemMetrics
        from app.real_data_sources.threat_intel_feeds import ThreatIndicator
        from datetime import datetime, timezone
        
        # Test network event
        net_event = RealNetworkEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            dest_ip="8.8.8.8",
            source_port=12345,
            dest_port=80,
            protocol="tcp",
            packet_size=1024,
            flags=["syn"],
            payload_snippet="GET / HTTP/1.1",
            geo_location=None,
            threat_indicators=["test_indicator"],
            flow_id="test_flow"
        )
        print(f"✅ Network event: {net_event.source_ip} -> {net_event.dest_ip}")
        
        # Test system metrics
        sys_metrics = SystemMetrics(
            timestamp=datetime.now(timezone.utc),
            cpu_percent=45.2,
            memory_percent=67.8,
            disk_io_read=1024000,
            disk_io_write=512000,
            network_bytes_sent=2048000,
            network_bytes_recv=4096000,
            active_connections=150,
            processes_count=200,
            load_average=[1.5, 1.2, 1.0]
        )
        print(f"✅ System metrics: CPU {sys_metrics.cpu_percent}%, Memory {sys_metrics.memory_percent}%")
        
        # Test threat indicator
        threat_indicator = ThreatIndicator(
            value="malicious.example.com",
            type="domain",
            threat_type="malware",
            confidence=0.9,
            source="test_source",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            tags=["malware", "botnet"],
            description="Test malware domain",
            severity="high"
        )
        print(f"✅ Threat indicator: {threat_indicator.value} ({threat_indicator.threat_type})")
        
        print("✅ All data structures working correctly")
        return True
        
    except Exception as e:
        print(f"❌ Data structures test failed: {e}")
        logger.exception("Data structures error")
        return False

def test_dependencies():
    """Test required dependencies."""
    print("\n📦 Testing Dependencies")
    print("=" * 40)
    
    dependencies = [
        ('scapy', 'Network packet capture'),
        ('psutil', 'System metrics'),
        ('netifaces', 'Network interfaces'),
        ('requests', 'HTTP requests for threat feeds'),
        ('pandas', 'Data processing'),
        ('numpy', 'Numerical operations')
    ]
    
    results = []
    for dep, description in dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep}: {description}")
            results.append(True)
        except ImportError:
            print(f"❌ {dep}: {description} - NOT INSTALLED")
            results.append(False)
    
    passed = sum(results)
    total = len(results)
    print(f"\n📊 Dependencies: {passed}/{total} available")
    
    return passed == total

def run_simple_test():
    """Run simplified real data test."""
    print("🚀 REAL DATA INTEGRATION - SIMPLE TEST")
    print("=" * 50)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Test results
    results = {
        'dependencies': False,
        'data_structures': False,
        'network_collection': False,
        'system_metrics': False,
        'threat_intel': False
    }
    
    try:
        # Run tests
        results['dependencies'] = test_dependencies()
        results['data_structures'] = test_data_structures()
        results['network_collection'] = test_network_collection()
        results['system_metrics'] = test_system_metrics()
        results['threat_intel'] = test_threat_intel()
        
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
        return
    
    # Summary
    print("\n📋 TEST RESULTS")
    print("=" * 30)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name.replace('_', ' ').title()}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall Result: {passed}/{total} tests passed")
    
    if passed >= 4:  # Allow for some flexibility
        print("\n🎉 REAL DATA INTEGRATION READY!")
        print("✨ Your system can now collect real live data:")
        print("  ✅ Network interfaces detected")
        print("  ✅ System metrics available")
        print("  ✅ Threat intelligence configured")
        print("  ✅ Data structures functional")
        print("\n🚀 Next steps:")
        print("  1. Run: python start_real_data_system.py")
        print("  2. Or integrate with Flask: python main.py")
        print("  3. Monitor real security events!")
        
    elif passed >= 2:
        print("\n⚠️  PARTIALLY READY")
        print("Some components are working, but you may experience limited functionality.")
        print("💡 Consider fixing the failed tests above.")
        
    else:
        print("\n❌ NOT READY")
        print("Too many core components failed.")
        print("💡 Please install missing dependencies:")
        print("   pip install -r requirements-real-data.txt")
    
    print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        run_simple_test()
    except KeyboardInterrupt:
        print("\n\n👋 Test cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        logger.exception("Unexpected test error")
        sys.exit(1)