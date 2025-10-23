"""Test device discovery functionality"""
import sys
sys.path.insert(0, 'c:\\Users\\user\\Desktop\\project-main')

from app.utils.network_device_discovery import NetworkDeviceDiscovery

# Create discovery instance
discovery = NetworkDeviceDiscovery()

print("=" * 60)
print("TESTING NETWORK DEVICE DISCOVERY")
print("=" * 60)

# Test ARP discovery
print("\n1. Testing ARP Table Discovery...")
print("-" * 60)
devices = discovery._discover_via_arp()
print(f"Found {len(devices)} devices via ARP")
for ip, device in devices.items():
    print(f"  - {ip}: {device['name']} ({device['mac']}) - {device['vendor']}")

# Test network range detection
print("\n2. Testing Network Range Detection...")
print("-" * 60)
network_range = discovery._get_network_range()
print(f"Network Range: {network_range}")

# Test full discovery with ARP only
print("\n3. Testing Full Discovery (ARP only)...")
print("-" * 60)
all_devices = discovery.discover_devices(methods=['arp'])
print(f"Total devices found: {len(all_devices)}")
for device in all_devices:
    print(f"  - {device['ip']}: {device['name']}")
    print(f"    MAC: {device['mac']}")
    print(f"    Vendor: {device['vendor']}")
    print(f"    Type: {device['type']}")
    print(f"    Method: {device['discovery_method']}")
    print()

print("=" * 60)
print("TEST COMPLETE")
print("=" * 60)
