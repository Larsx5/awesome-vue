# Comprehensive Network Device Scanner

A powerful Python tool for scanning and accessing network devices. Automatically detects and attempts authentication on HikVision cameras, TP-Link routers, MikroTik routers, and other network devices.

## Features

- **Multi-Device Support**: HikVision, TP-Link, MikroTik, Cisco Linksys, Edimax, and more
- **Automatic Discovery**: Uses Nmap and HTTP scanning to identify devices
- **Credential Brute Force**: Tries default credentials and known breach passwords (2020-2026)
- **Real-time Status**: Shows scan progress and authentication attempts
- **Configurable Scanning**: Works with CIDR notation, IP ranges, or single IPs
- **Remote Command Injection**: Execute commands on successfully authenticated devices
- **Detailed Reporting**: Save and display results in JSON format

## Prerequisites

```bash
pip install -r requirements.txt
```

Required libraries:
- `requests` - HTTP requests
- `nmap` - Network scanning
- Python 3.7+

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Interactive Mode

```bash
python network_scanner.py
```

Options:
1. Scan IP Range (CIDR notation)
2. Scan Single IP
3. Scan Local Network (/24)
4. Exit

### Command Line Examples

Scan a specific IP range:
```bash
python network_scanner.py
# Select option 1
# Enter IP range: 192.168.1.0/24
```

Scan a single device:
```bash
python network_scanner.py
# Select option 2
# Enter IP address: 192.168.1.100
```

Scan local network:
```bash
python network_scanner.py
# Select option 3
```

### Python API

```python
from network_scanner import NetworkScanner

# Initialize scanner
scanner = NetworkScanner(
    target_ip_range="192.168.1.0/24",
    ports=[80, 443, 8080, 22],
    threads=50,
    timeout=2.0
)

# Perform scan
result = scanner.scan_network()

# Save detailed results
scanner.save_results("scan_results.json")

# Generate report
scanner.generate_report(result)
```

### Advanced: Automatic Scanner with Injection

```python
from network_scanner import AutomaticScanner

# Quick scan with injection capabilities
automatic = AutomaticScanner("192.168.1.0/24")
automatic.scan_with_injection()
```

## Credentials Database

The scanner includes:

### Default Credentials
- **HikVision**: `admin`/`admin`, `admin`/`12345`, `admin`/`888888`
- **TP-Link**: `admin`/`admin`, `admin`/`日`, `admin`/`admin123`
- **MikroTik**: `admin`/`` (empty), `admin`/`admin`, `admin`/`01`

### Known Breaches (2020-2026)
- Common passwords from major router firmware breaches
- CredHarvester and Credential Tester datasets
- Real-world compromise credentials

## Output

### Terminal Output
```
[+] Starting scan on range: 192.168.1.0/24
[+] Found 254 IP addresses to scan
[*] Using Nmap for service detection...
[*] HikVision device detected at 192.168.1.10:80
[*] Attempting authentication for 192.168.1.10 (HikVision) with 4 credentials
[+] SUCCESS: 192.168.1.10 - Login with 'admin' / 'password1' (65.23ms)
[*] Attempting to perform remote commands on discovered devices...
```

### JSON Output
```json
{
  "scan_info": {
    "target": "192.168.1.0/24",
    "scan_time": "2024-01-15 14:30:00",
    "total_ips": 254,
    "successful_devices": 3
  },
  "devices": [
    {
      "ip": "192.168.1.10",
      "status": "success",
      "device_type": "HikVision",
      "username": "admin",
      "password": "password1",
      "auth_method": "credential_successful"
    }
  ]
}
```

## Device Detection

The scanner identifies devices by:
- Nmap service fingerprinting
- HTTP responses and meta tags
- Login page patterns
- Known device signatures

Supported devices:
- **HikVision** - IP Cameras and DVRs (Ports: 80, 8080, 8000)
- **TP-Link** - Routers and switches (Ports: 80, 8080)
- **MikroTik** - Routers (Ports: 80, 443, 8443, 22)
- **Cisco Linksys** - Home routers (Ports: 80, 443)
- **Edimax** - Network devices (Ports: 80)

## Ethical Use

⚠️ **Important**: 
- Only scan networks you own or have permission to test
- Use responsibly - respect privacy and network security
- Consider rate limiting to avoid DoS
- Be aware of your local network policies

## Advanced Features

### Custom Ports
```python
scanner = NetworkScanner("192.168.1.0/24", ports=[80, 8000, 443, 8443])
```

### Custom Timeout
```python
scanner = NetworkScanner("192.168.1.0/24", timeout=3.0)
```

### Custom Thread Count
```python
scanner = NetworkScanner("192.168.1.0/24", threads=100)
```

### Service Discovery
```bash
nmap -sV -sC <target_ip>
```

## Troubleshooting

### Connection Refused
- Device may be powered down or offline
- Firewall blocking the scanner
- Wrong IP address range

### No Devices Detected
- Devices may use different ports
- Devices may have custom firmware
- Scanning a remote network (use VPN)

### Authentication Failures
- Credentials may have been changed
- Need additional passwords from breach database
- Try specifying custom credentials file

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please submit feature requests and bug reports.

## Version History

- **v1.0.0** - Initial release
  - Devices: HikVision, TP-Link, MikroTik
  - Credential attempts with breach database
  - JSON output and reporting
  - Command-line and API modes

## Security

This tool should be used for:
- Network audits
- Security assessment
- IoT device inventory
- Vulnerability testing

Not for:
- Unauthorized network penetration
- Reverse engineering
- Malicious attacks
