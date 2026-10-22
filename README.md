# 🖥️ Network Device Scanner

Automatic network device scanner that discovers, exploits, and gains access to home and business routers, cameras, and IoT devices using default credentials and known breaches.

![Platforms](https://img.shields.io/badge/Windows-blue) ![Platforms](https://img.shields.io/badge/macOS-green) ![Platforms](https://img.shields.io/badge/Linux-orange) ![Python](https://img.shields.io/badge/python-3.8+-yellow)

## ✨ Features

- 🔍 **IP Range & Single IP Scanning** (CIDR notation supported)
- 📡 **Automatic Device Discovery** using Nmap and HTTP fingerprinting
- 🔐 **Default Password Brute Force + Known Breaches Database** (2020-2026)
- 💬 **Real-time Authentication Status** (success/failed)
- ⚡ **Remote Command Injection** on authenticated devices
- 💾 **Save Credentials** to JSON files
- 🌐 **Support for 6+ Device Types**: HikVision, TP-Link, MikroTik, Cisco Linksys, Edimax, Xiaomi
- 🛠️ **Configurable**: Threads, ports, timeouts

## 📦 Download & Run

### One-Click Setup

**Windows:**
```batch
run.bat
```

**Linux/Mac:**
```bash
chmod +x run.sh
./run.sh
```

### Manual Setup

1. **Clone or Download the repository**

2. **Install requirements:**
```bash
pip install -r requirements.txt
```

3. **Run the scanner:**
```bash
python network_scanner.py
```

## 🚀 Quick Start

### Interactive Mode (Recommended)

```bash
python network_scanner.py
```

Select:
1. Scan IP range
2. Scan single IP
3. List scans to resume
4. Exit

### Command Line Usage

```bash
# Scan 192.168.1.0/24 automatically
python network_scanner.py --scan 192.168.1.0/24

# Scan single IP
python network_scanner.py --scan "192.168.1.2"

# Use 5 threads
python network_scanner.py --scan 192.168.1.0/24 --threads 5

# Configure scan timeout (seconds)
python network_scanner.py --scan 192.168.1.0/24 --timeout 10

# Run in automated mode (no CLI)
python network_scanner.py --scan 192.168.1.0/24 --output results.json
```

### Using as Python Module

```python
from network_scanner import NetworkScanner

# Scan and find vulnerable devices
scanner = NetworkScanner()
results = scanner.scan_network("192.168.1.0/24")

for device in results:
    print(f"Found: {device['ip']} ({device['type']})")
    if device['credentials']:
        print(f"🔐 Credentials: {device['credentials']}")
        print(f"⚙️  Command: {device['command']}")
```

## 📋 Supported Devices

| Device Type | Default Ports | Fingerprint |
|-------------|---------------|-------------|
| **HikVision Camera** | 37777, 80, 554 | `hikvision` |
| **TP-Link Router** | 80 | `tplink` |
| **MikroTik Router** | 80, 8291 | `mikrotik` |
| **Cisco Linksys** | 80 | `linksys` |
| **Edimax IoT** | 80 | `edimax` |
| **Xiaomi Router** | 54, 80 | `xiaomi` |

## 🔥 Real-World Breaches Used

The scanner includes credentials from major data breaches (2020-2026):
- 2024 SaaS/Cloud Breaches - 2M+ credentials
- 2023 Trovian Hotel Breach - 190K accounts
- 2022 NCMEC Breach - Educational data
- 2020 UPI Data Breach - Financial information
- Plus 10+ additional sources

## 📁 Output

Results are saved as JSON files:
```json
{
  "ip": "192.168.1.2",
  "type": "TP-Link",
  "port": 80,
  "credentials": "admin:admin",
  "success": true,
  "command": "file open /etc/passwd"
}
```

## ⚙️ Configuration

- **Threads**: Default 10 (use `--threads` flag)
- **Ports**: Default 80 (use `--ports 80,443,554,9090` for multiple)
- **Timeout**: Default 5 seconds (use `--timeout` flag)

## 🛠️ Dependencies

```txt
requests==2.31.0
nmap>=0.7.1
python-dateutil>=2.8.2
```

## 📜 License

This project is free and open source. See UNLICENSE file.

## 🤝 Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

---

**⚠️ Disclaimer: Use responsibly. Only scan networks you own or have permission to test.**

Made with ❤️ for network security enthusiasts
