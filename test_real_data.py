#!/usr/bin/env python3
"""
Real Data Integration Test Script
Tests the real live data collection system vs simulated data
"""

import sys
import time
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_real_network_collection():
    """Test real network data collection."""
    print("\n🌐 Testing Real Network Data Collection")
    print("=" * 50)
    
    try:
        from app.real_data_sources.live_network_collector import get_real_network_collector
        
        collector = get_real_network_collector()
        print("✅ Network collector initialized")
        
        # Start collection for 10 seconds
        print("🚀 Starting network collection (10 seconds)...")
        collector.start_collection()
        
        time.sleep(10)
        
        # Get statistics
        stats = collector.get_collection_stats()
        print(f"📊 Collection Stats:")
        print(f"   - Running: {stats['is_running']}")
        print(f"   - Interface: {stats['interface']}")
        print(f"   - Packets Captured: {stats['packets_captured']}")
        print(f"   - Bytes Captured: {stats['bytes_captured']}")
        print(f"   - Packets/second: {stats['packets_per_second']:.2f}")
        print(f"   - Active Flows: {stats['active_flows']}")
        
        # Get sample data
        batch = collector.get_real_data_batch(5)
        print(f"📦 Sample Events ({len(batch)}):")
        for event in batch:
            print(f"   - {event.timestamp.strftime('%H:%M:%S')} | "
                  f"{event.source_ip} -> {event.dest_ip}:{event.dest_port} | "
                  f"Threats: {len(event.threat_indicators)}")
        
        collector.stop_collection()
        print("✅ Network collection test completed")
        
        return stats['packets_captured'] > 0
        
    except Exception as e:
        print(f"❌ Network collection test failed: {e}")
        return False

def test_threat_intel_feeds():
    """Test threat intelligence feeds."""
    print("\n🛡️  Testing Threat Intelligence Feeds")
    print("=" * 50)
    
    try:
        from app.real_data_sources.threat_intel_feeds import get_threat_intel_feeds
        
        threat_intel = get_threat_intel_feeds()
        print("✅ Threat intel feeds initialized")
        
        # Start collection for 30 seconds
        print("🚀 Starting threat intel collection (30 seconds)...")
        threat_intel.start_collection()
        
        time.sleep(30)
        
        # Get statistics
        stats = threat_intel.get_statistics()
        print(f"📊 Threat Intel Stats:")
        print(f"   - Running: {stats['is_running']}")
        print(f"   - Sources Enabled: {stats['sources_enabled']}")
        print(f"   - Total Indicators: {stats['total_indicators']}")
        print(f"   - Indicators by Type: {dict(stats['indicators_by_type'])}")
        print(f"   - Indicators by Source: {dict(stats['indicators_by_source'])}")
        
        # Test indicator lookup
        test_ips = ['1.1.1.1', '8.8.8.8', '192.168.1.1']
        print(f"🔍 Testing indicator lookups:")
        for ip in test_ips:
            matches = threat_intel.check_indicator(ip, 'ip')
            print(f"   - {ip}: {len(matches)} matches")
            for match in matches[:2]:  # Show first 2 matches
                print(f"     * {match.threat_type} ({match.source}) - {match.confidence}")
        
        threat_intel.stop_collection()
        print("✅ Threat intel test completed")
        
        return stats['total_indicators'] > 0
        
    except Exception as e:
        print(f"❌ Threat intel test failed: {e}")
        return False

def test_real_data_integration():
    """Test full real data integration."""
    print("\n🔗 Testing Real Data Integration")
    print("=" * 50)
    
    try:
        from app.real_data_sources.real_data_integration import get_real_data_integrator
        
        integrator = get_real_data_integrator()
        print("✅ Real data integrator initialized")
        
        # Subscribe to events
        event_count = 0
        high_risk_events = 0
        
        def event_callback(event):
            nonlocal event_count, high_risk_events
            event_count += 1
            if event.threat_score > 0.7:
                high_risk_events += 1
            
            if event_count <= 5:  # Show first 5 events
                print(f"   📡 Event {event_count}: {event.source} | "
                      f"Type: {event.event_type} | "
                      f"Threat Score: {event.threat_score:.2f} | "
                      f"Indicators: {len(event.threat_indicators)}")
        
        integrator.subscribe_to_events(event_callback)
        
        # Start integration for 15 seconds
        print("🚀 Starting real data integration (15 seconds)...")
        integrator.start_real_data_collection()
        
        time.sleep(15)
        
        # Get statistics
        stats = integrator.get_real_time_stats()
        print(f"📊 Integration Stats:")
        print(f"   - Events Processed: {event_count}")
        print(f"   - High Risk Events: {high_risk_events}")
        print(f"   - Events/second: {stats['integrator']['events_per_second']:.2f}")
        print(f"   - Threat Matches: {stats['integrator']['threat_matches']}")
        print(f"   - Buffer Size: {stats['integrator']['buffer_size']}")
        
        # Get recent events
        recent_events = integrator.get_recent_events(5)
        print(f"📋 Recent Events ({len(recent_events)}):")
        for event in recent_events:
            print(f"   - {event['timestamp'][:19]} | "
                  f"{event['source']} | "
                  f"Score: {event['threat_score']:.2f}")
        
        integrator.stop_real_data_collection()
        print("✅ Real data integration test completed")
        
        return event_count > 0
        
    except Exception as e:
        print(f"❌ Real data integration test failed: {e}")
        return False

def test_enhanced_telemetry():
    """Test enhanced telemetry with real data."""
    print("\n📡 Testing Enhanced Telemetry Collection")
    print("=" * 50)
    
    try:
        from app.architecture.real_telemetry_collection import get_enhanced_telemetry_processor
        
        processor = get_enhanced_telemetry_processor()
        print("✅ Enhanced telemetry processor initialized")
        
        # Start processing for 20 seconds
        print("🚀 Starting enhanced telemetry processing (20 seconds)...")
        processor.start_stream_processing()
        
        time.sleep(20)
        
        # Get statistics
        stats = processor.get_stream_stats()
        print(f"📊 Telemetry Stats:")
        print(f"   - Stream Running: {stats['stream_processing']['is_running']}")
        print(f"   - Total Processed: {stats['event_analytics']['total_processed']}")
        print(f"   - Threat Events: {stats['event_analytics']['threat_events']}")
        print(f"   - Network Events: {stats['event_analytics']['network_events']}")
        print(f"   - System Events: {stats['event_analytics']['system_events']}")
        print(f"   - High Risk Events: {stats['event_analytics']['high_risk_events']}")
        print(f"   - Using Real Data: {stats['telemetry_collection']['use_real_data']}")
        
        # Get threat events
        threat_events = processor.telemetry_collector.get_threat_events(5)
        print(f"🚨 Threat Events ({len(threat_events)}):")
        for event in threat_events:
            print(f"   - {event['timestamp'][:19]} | "
                  f"{event['source']} | "
                  f"Score: {event['threat_score']:.2f} | "
                  f"Indicators: {len(event['risk_indicators'])}")
        
        processor.stop_stream_processing()
        print("✅ Enhanced telemetry test completed")
        
        return stats['event_analytics']['total_processed'] > 0
        
    except Exception as e:
        print(f"❌ Enhanced telemetry test failed: {e}")
        return False

def run_comprehensive_test():
    """Run comprehensive real data integration test."""
    print("🚀 REAL DATA INTEGRATION COMPREHENSIVE TEST")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    results = {
        'network_collection': False,
        'threat_intel_feeds': False,
        'real_data_integration': False,
        'enhanced_telemetry': False
    }
    
    # Test each component
    try:
        results['network_collection'] = test_real_network_collection()
        results['threat_intel_feeds'] = test_threat_intel_feeds()
        results['real_data_integration'] = test_real_data_integration()
        results['enhanced_telemetry'] = test_enhanced_telemetry()
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
        return
    
    # Summary
    print("\n📋 TEST SUMMARY")
    print("=" * 30)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name.replace('_', ' ').title()}: {status}")
    
    print(f"\nOverall Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All real data integration tests PASSED!")
        print("\n✨ Your system is now using REAL LIVE DATA instead of simulated data!")
        print("Benefits:")
        print("  - Accurate threat detection from real network traffic")
        print("  - Live threat intelligence from multiple sources")
        print("  - Real system metrics and behavioral analysis")
        print("  - Enhanced security posture with actual data")
    else:
        print("⚠️  Some tests failed. Check the error messages above.")
        print("💡 You may need to:")
        print("  - Check network permissions for packet capture")
        print("  - Verify internet connectivity for threat feeds")
        print("  - Install missing dependencies")
    
    print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        run_comprehensive_test()
    except KeyboardInterrupt:
        print("\n\n👋 Test cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)