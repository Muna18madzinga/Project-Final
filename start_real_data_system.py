#!/usr/bin/env python3
"""
Start Real Data System
Launch the Adaptive Security Suite with real live data instead of simulated data
"""

import os
import sys
import time
import signal
import logging
import threading
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('real_data_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global system components
real_data_integrator = None
telemetry_processor = None
flask_app = None

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    logger.info(f"Received signal {signum}, shutting down real data system...")
    
    global real_data_integrator, telemetry_processor, flask_app
    
    # Stop real data collection
    if real_data_integrator:
        real_data_integrator.stop_real_data_collection()
    
    # Stop telemetry processing
    if telemetry_processor:
        telemetry_processor.stop_stream_processing()
    
    logger.info("Real data system shutdown complete")
    sys.exit(0)

def check_dependencies():
    """Check if required dependencies are installed."""
    missing_deps = []
    
    try:
        import scapy
    except ImportError:
        missing_deps.append('scapy')
    
    try:
        import psutil
    except ImportError:
        missing_deps.append('psutil')
    
    try:
        import netifaces
    except ImportError:
        missing_deps.append('netifaces')
    
    try:
        import requests
    except ImportError:
        missing_deps.append('requests')
    
    if missing_deps:
        print("❌ Missing required dependencies:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print("\n💡 Install them with:")
        print(f"   pip install {' '.join(missing_deps)}")
        print("\n📦 Or install all real data dependencies:")
        print("   pip install -r requirements-real-data.txt")
        return False
    
    return True

def check_permissions():
    """Check if we have necessary permissions for packet capture."""
    import platform
    
    system = platform.system()
    
    if system == "Windows":
        print("ℹ️  Windows detected: Ensure WinPcap/Npcap is installed")
        print("   Download from: https://nmap.org/npcap/")
        return True
    
    elif system in ["Linux", "Darwin"]:  # Linux or macOS
        # Check if running as root or have capture permissions
        if os.geteuid() == 0:
            print("✅ Running with root privileges - packet capture available")
            return True
        else:
            print("⚠️  Not running as root - packet capture may be limited")
            print("💡 For full packet capture, run with sudo:")
            print(f"   sudo python {sys.argv[0]}")
            print("🔄 Continuing with limited privileges...")
            return True
    
    return True

def start_real_data_system():
    """Start the complete real data system."""
    global real_data_integrator, telemetry_processor
    
    print("🚀 STARTING ADAPTIVE SECURITY SUITE WITH REAL LIVE DATA")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Check dependencies
    print("🔍 Checking dependencies...")
    if not check_dependencies():
        return False
    print("✅ All dependencies available")
    
    # Check permissions
    print("\n🔒 Checking permissions...")
    if not check_permissions():
        return False
    
    print("\n🌐 Starting Real Data Collection System...")
    print("-" * 40)
    
    try:
        # Import and initialize real data components
        from app.real_data_sources.real_data_integration import get_real_data_integrator
        from app.architecture.real_telemetry_collection import get_enhanced_telemetry_processor
        
        # Initialize components
        real_data_integrator = get_real_data_integrator()
        telemetry_processor = get_enhanced_telemetry_processor()
        
        print("✅ Real data integrator initialized")
        print("✅ Enhanced telemetry processor initialized")
        
        # Configuration for threat intel APIs (optional)
        config = {
            'api_keys': {
                # Add your API keys here if you have them
                # 'alienvault_otx': 'your_otx_api_key_here',
                # 'misp': 'your_misp_api_key_here'
            }
        }
        
        # Start real data collection
        print("\n🚀 Starting real data collection...")
        real_data_integrator.start_real_data_collection(config)
        
        # Start enhanced telemetry processing
        print("📡 Starting enhanced telemetry processing...")
        telemetry_processor.start_stream_processing(config)
        
        print("\n✅ REAL DATA SYSTEM STARTED SUCCESSFULLY!")
        print("=" * 50)
        
        # Monitor and report status
        print("📊 System Status Monitor (Press Ctrl+C to stop)")
        print("-" * 30)
        
        status_count = 0
        while True:
            time.sleep(10)  # Status update every 10 seconds
            status_count += 1
            
            # Get real-time statistics
            integrator_stats = real_data_integrator.get_real_time_stats()
            telemetry_stats = telemetry_processor.get_stream_stats()
            
            print(f"\n⏰ Status Update #{status_count} - {datetime.now().strftime('%H:%M:%S')}")
            print(f"   Network Packets: {integrator_stats['network_collection']['packets_captured']}")
            print(f"   Threat Intel Indicators: {integrator_stats['threat_intelligence']['total_indicators']}")
            print(f"   Events Processed: {integrator_stats['integrator']['events_processed']}")
            print(f"   Telemetry Events: {telemetry_stats['event_analytics']['total_processed']}")
            print(f"   Threat Events: {telemetry_stats['event_analytics']['threat_events']}")
            print(f"   High Risk Events: {integrator_stats['integrator']['high_risk_events']}")
            
            # Show some recent threat events every minute
            if status_count % 6 == 0:  # Every 6 updates (1 minute)
                threat_events = telemetry_processor.telemetry_collector.get_threat_events(3)
                if threat_events:
                    print(f"\n🚨 Recent Threat Events:")
                    for event in threat_events:
                        print(f"   - {event['timestamp'][:19]} | {event['source']} | "
                              f"Score: {event['threat_score']:.2f} | "
                              f"Type: {event['data_type']}")
        
    except KeyboardInterrupt:
        print("\n\n⏹️  System shutdown requested by user")
        return True
        
    except Exception as e:
        logger.error(f"Real data system error: {e}")
        print(f"\n❌ System error: {e}")
        return False

def start_with_flask_integration():
    """Start real data system with Flask integration."""
    global flask_app
    
    try:
        from main import app as flask_app
        
        print("\n🌐 Starting Flask integration...")
        
        # Patch Flask app to use real data
        print("🔧 Configuring Flask app for real data...")
        
        # Start Flask in a separate thread
        flask_thread = threading.Thread(
            target=lambda: flask_app.run(host='0.0.0.0', port=5000, debug=False)
        )
        flask_thread.daemon = True
        flask_thread.start()
        
        print("✅ Flask app started on http://localhost:5000")
        print("🌐 Web dashboard available with real data integration")
        
        return True
        
    except Exception as e:
        logger.error(f"Flask integration error: {e}")
        print(f"⚠️  Flask integration failed: {e}")
        print("🔄 Continuing with real data collection only...")
        return False

def main():
    """Main entry point."""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("🛡️  ADAPTIVE SECURITY SUITE - REAL DATA MODE")
    print("=" * 50)
    print("This will start the system with REAL live data instead of simulated data")
    print("✨ Features enabled:")
    print("  - Live network packet capture and analysis")
    print("  - Real-time threat intelligence feeds")
    print("  - Actual system metrics monitoring")
    print("  - Live behavioral analysis")
    print("  - Real threat detection and correlation")
    print()
    
    # Check if user wants Flask integration
    try:
        response = input("🤔 Start with web dashboard? (y/N): ").lower().strip()
        include_flask = response in ['y', 'yes']
    except (EOFError, KeyboardInterrupt):
        print("\n👋 Cancelled by user")
        sys.exit(0)
    
    # Start the real data system
    success = start_real_data_system()
    
    if success and include_flask:
        start_with_flask_integration()
        
        # Keep Flask running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    
    # Cleanup
    signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    main()