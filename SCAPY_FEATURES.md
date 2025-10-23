# Scapy Network Management Features

## Overview

The Adaptive Security Suite now uses **Scapy** for advanced network traffic management and device detection. Scapy provides powerful capabilities for:

- Network device discovery (ARP scanning)
- Real-time packet capture and analysis
- Port scanning
- Traffic pattern analysis
- Network anomaly detection

## Requirements

**Important**: Scapy requires **Administrator/Root privileges** to perform network operations like:
- Sending raw packets
- Capturing network traffic
- ARP scanning

### Running with Admin Privileges

**Windows:**
```bash
# Run Command Prompt as Administrator, then:
cd c:\Users\user\Desktop\project-main
start.bat
```

**Linux/Mac:**
```bash
sudo python main.py
```

## API Endpoints

### 1. Device Discovery

#### `GET /api/devices`
Discover devices on the local network using ARP scanning.

**Query Parameters:**
- `scan` (boolean, default: false): Perform new network scan
- `timeout` (int, default: 3): Scan timeout in seconds

**Examples:**
```bash
# Get cached devices
curl -H "Authorization: Bearer <token>" http://localhost:5001/api/devices

# Perform new scan
curl -H "Authorization: Bearer <token>" http://localhost:5001/api/devices?scan=true&timeout=5
```

**Response:**
```json
{
  "devices": [
    {
      "id": "AA-BB-CC-DD-EE-FF",
      "name": "Apple-123",
      "ip": "192.168.1.123",
      "mac": "AA:BB:CC:DD:EE:FF",
      "type": "Mobile/Computer",
      "vendor": "Apple",
      "status": "online",
      "last_seen": "2025-10-23T14:30:00"
    }
  ],
  "total": 1,
  "scan_performed": true,
  "timestamp": "2025-10-23T14:30:00"
}
```

### 2. Traffic Monitoring

#### `POST /api/network/start-monitoring`
Start real-time network traffic monitoring.

**Request Body:**
```json
{
  "filter": "tcp",
  "packet_count": 0
}
```

**Filter Options:**
- `ip` - All IP traffic (default)
- `tcp` - TCP traffic only
- `udp` - UDP traffic only
- `icmp` - ICMP traffic only
- `port 80` - Specific port
- `host 192.168.1.1` - Specific host

**Response:**
```json
{
  "status": "monitoring_started",
  "filter": "tcp",
  "packet_count": 0,
  "timestamp": "2025-10-23T14:30:00"
}
```

#### `POST /api/network/stop-monitoring`
Stop traffic monitoring.

**Response:**
```json
{
  "status": "monitoring_stopped",
  "timestamp": "2025-10-23T14:30:00"
}
```

#### `GET /api/network/traffic-stats`
Get collected traffic statistics.

**Response:**
```json
{
  "stats": {
    "total_hosts": 5,
    "hosts": {
      "192.168.1.100": {
        "packets_sent": 1234,
        "packets_received": 5678,
        "bytes_sent": 123456,
        "bytes_received": 567890,
        "protocols": {
          "TCP": 100,
          "UDP": 50,
          "ICMP": 10
        },
        "last_seen": "2025-10-23T14:30:00"
      }
    }
  },
  "timestamp": "2025-10-23T14:30:00"
}
```

### 3. Port Scanning

#### `POST /api/network/scan-host`
Scan a specific host for open ports.

**Request Body:**
```json
{
  "target_ip": "192.168.1.1",
  "ports": [21, 22, 80, 443, 3389]
}
```

**Response:**
```json
{
  "result": {
    "ip": "192.168.1.1",
    "open_ports": [80, 443],
    "total_ports_scanned": 5,
    "scan_time": "2025-10-23T14:30:00"
  },
  "timestamp": "2025-10-23T14:30:00"
}
```

### 4. Anomaly Detection

#### `GET /api/network/anomalies`
Detect network anomalies based on traffic patterns.

**Response:**
```json
{
  "anomalies": [
    {
      "type": "high_traffic",
      "ip": "192.168.1.100",
      "packets": 15000,
      "severity": "medium",
      "message": "High packet count from 192.168.1.100"
    },
    {
      "type": "multiple_protocols",
      "ip": "192.168.1.200",
      "protocols": ["TCP", "UDP", "ICMP"],
      "severity": "low",
      "message": "Multiple protocols detected from 192.168.1.200"
    }
  ],
  "total": 2,
  "timestamp": "2025-10-23T14:30:00"
}
```

## Features

### Device Discovery
- **ARP Scanning**: Fast network-wide device discovery
- **Vendor Detection**: Identifies device manufacturers from MAC addresses
- **Device Classification**: Categorizes devices (Computer, IoT, Network Equipment, etc.)
- **Response Caching**: Stores discovered devices for quick retrieval

### Traffic Monitoring
- **Real-time Packet Capture**: Live network traffic analysis
- **Protocol Analysis**: Breaks down traffic by protocol (TCP, UDP, ICMP)
- **Per-Host Statistics**: Tracks packets and bytes per IP address
- **Customizable Filters**: BPF filters for targeted monitoring

### Port Scanning
- **SYN Scanning**: Fast port discovery using TCP SYN packets
- **Custom Port Lists**: Scan specific ports or common service ports
- **Response Analysis**: Identifies open, closed, and filtered ports

### Security Features
- **Anomaly Detection**: Identifies unusual traffic patterns
- **High Traffic Detection**: Alerts on excessive packet counts
- **Protocol Diversity Monitoring**: Detects potential scanning activity
- **Integration with Threat Intelligence**: Cross-references with threat feeds

## Supported Device Vendors

The system can identify devices from the following manufacturers:

- **Apple** (iPhone, iPad, MacBook, iMac)
- **Microsoft** (Windows PCs, Hyper-V VMs)
- **VMware** (Virtual Machines)
- **Raspberry Pi** (IoT devices)
- **Cisco** (Network equipment)
- **Samsung** (Mobile devices)
- **Realtek** (Network adapters)
- And many more...

## Performance Considerations

### Network Scanning
- Default timeout: 3 seconds
- Average scan time for /24 network: 3-5 seconds
- Cached results valid until next scan

### Traffic Monitoring
- Minimal performance impact
- Runs in separate thread
- Configurable packet count limits
- Can filter to reduce load

### Port Scanning
- SYN scanning is fast but detectable
- Default: Common ports only (13 ports)
- Full scan (65535 ports) not recommended for production

## Security Notes

1. **Admin Privileges**: Required for raw packet operations
2. **Firewall**: May block Scapy operations if too restrictive
3. **Antivirus**: Some AV software may flag Scapy as potentially unwanted
4. **Network Policy**: Ensure compliance with organization's network scanning policies
5. **Rate Limiting**: Built-in to avoid network flooding

## Error Handling

### Permission Errors
If you see "Administrator privileges required":
- Windows: Run as Administrator
- Linux/Mac: Use sudo
- Or run from elevated terminal

### Network Interface Errors
If "No network interface available":
- Check network adapter is enabled
- Verify Scapy can detect interfaces
- Try specifying interface manually

### Timeout Errors
If scans timeout frequently:
- Increase timeout parameter
- Check network connectivity
- Verify firewall isn't blocking ARP

## Example Usage Workflow

```bash
# 1. Discover devices on network
curl -X GET "http://localhost:5001/api/devices?scan=true" \
  -H "Authorization: Bearer YOUR_TOKEN"

# 2. Start traffic monitoring
curl -X POST "http://localhost:5001/api/network/start-monitoring" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filter": "tcp", "packet_count": 1000}'

# 3. Check traffic statistics
curl -X GET "http://localhost:5001/api/network/traffic-stats" \
  -H "Authorization: Bearer YOUR_TOKEN"

# 4. Scan a specific host
curl -X POST "http://localhost:5001/api/network/scan-host" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "192.168.1.1", "ports": [80, 443, 8080]}'

# 5. Check for anomalies
curl -X GET "http://localhost:5001/api/network/anomalies" \
  -H "Authorization: Bearer YOUR_TOKEN"

# 6. Stop monitoring
curl -X POST "http://localhost:5001/api/network/stop-monitoring" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Integration with Frontend

The frontend automatically uses these endpoints when:
- Viewing the Devices page
- Dashboard displays network statistics
- Threat monitoring shows anomalies
- Real-time traffic graphs update

## Troubleshooting

### Issue: No devices found
**Solution**:
- Ensure backend is running with admin privileges
- Check you're on the same network as target devices
- Increase scan timeout

### Issue: Traffic monitoring not working
**Solution**:
- Verify admin/root privileges
- Check firewall settings
- Ensure network adapter supports promiscuous mode

### Issue: Port scan returns empty
**Solution**:
- Verify target host is reachable
- Check firewall on target host
- Try basic connectivity (ping) first

## Advanced Configuration

### Custom MAC Vendor Database
Edit `scapy_network_manager.py` to add more vendors:

```python
vendors = {
    'YOUR:MA:C': 'Your Vendor Name',
    # Add more...
}
```

### Custom Anomaly Detection
Modify detection thresholds in `detect_network_anomalies()`:

```python
if stats['packets_sent'] > 10000:  # Adjust threshold
    # Trigger anomaly alert
```

## Next Steps

1. **Run backend as Administrator**
2. **Test device discovery** on Devices page
3. **Start traffic monitoring** to see live stats
4. **Monitor for anomalies** on security dashboard
5. **Integrate with threat intelligence** feeds

## Support

For issues related to Scapy functionality:
- Check Scapy documentation: https://scapy.net/
- Verify admin/root access
- Review firewall settings
- Check system logs for detailed errors
