#!/usr/bin/env python3
"""
WiFi-Guardian - Real-time WiFi Attack Detector
Detects Deauthentication attacks and Evil Twin access points
Requires: Scapy, wireless card in monitor mode
"""

import sys
import time
from collections import defaultdict
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, RadioTap

class WiFiGuardian:
    def __init__(self, interface="wlan0mon"):
        self.interface = interface
        self.legitimate_aps = {}  # MAC -> (SSID, Channel, RSSI)
        self.deauth_count = defaultdict(int)
        self.evil_twin_candidates = []
        self.alert_threshold = 10  # Deauth packets per second
        
    def is_monitor_mode(self):
        """Check if interface is in monitor mode"""
        try:
            result = subprocess.run(['iwconfig', self.interface],
                                   capture_output=True, text=True)
            return 'Mode:Monitor' in result.stdout
        except:
            return False
    
    def enable_monitor_mode(self):
        """Enable monitor mode on wireless interface"""
        print(f"[*] Enabling monitor mode on {self.interface}...")
        
        commands = [
            f"sudo ip link set {self.interface} down",
            f"sudo iw {self.interface} set monitor none",
            f"sudo ip link set {self.interface} up"
        ]
        
        for cmd in commands:
            os.system(cmd)
        
        print(f"[+] Monitor mode enabled")
    
    def detect_deauth_attack(self, pkt):
        """Detect deauthentication attack patterns"""
        if pkt.haslayer(Dot11Deauth):
            # Extract source and destination MAC
            src = pkt.addr2
            dst = pkt.addr1
            bssid = pkt.addr3
            
            # Count deauth packets
            self.deauth_count[(src, bssid)] += 1
            
            # Alert if threshold exceeded
            if self.deauth_count[(src, bssid)] > self.alert_threshold:
                self.alert_deauth_attack(src, bssid, dst)
    
    def alert_deauth_attack(self, attacker, ap, victim):
        """Alert on deauthentication attack"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print("\n" + "="*60)
        print(f"🚨 DEAUTH ATTACK DETECTED! {timestamp}")
        print("="*60)
        print(f"Attacker MAC: {attacker}")
        print(f"Target AP:    {ap}")
        print(f"Victim:       {victim}")
        print(f"Packet Count: {self.deauth_count[(attacker, ap)]}")
        print("="*60 + "\n")
        
        # Log to file
        with open("wifi_attacks.log", "a") as f:
            f.write(f"{timestamp} | DEAUTH | {attacker} -> {ap} | Count: {self.deauth_count[(attacker, ap)]}\n")
        
        # Play alert sound (optional)
        try:
            os.system("paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga 2>/dev/null &")
        except:
            pass
    
    def detect_evil_twin(self, pkt):
        """Detect Evil Twin access points"""
        if pkt.haslayer(Dot11Beacon):
            # Extract AP information
            bssid = pkt.addr2
            
            # Parse SSID
            ssid = None
            channel = None
            
            try:
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 0:  # SSID
                        ssid = elt.info.decode('utf-8', errors='ignore')
                    elif elt.ID == 3:  # Channel
                        channel = ord(elt.info)
                    elt = elt.payload
            except:
                pass
            
            if not ssid:
                return
            
            # Get signal strength
            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
            
            # Check for Evil Twin (same SSID, different BSSID)
            for known_bssid, (known_ssid, known_channel, known_rssi) in self.legitimate_aps.items():
                if ssid == known_ssid and bssid != known_bssid:
                    # Potential Evil Twin detected
                    self.alert_evil_twin(ssid, bssid, known_bssid, channel, known_channel)
                    return
            
            # Add to known APs
            self.legitimate_aps[bssid] = (ssid, channel, rssi)
    
    def alert_evil_twin(self, ssid, fake_bssid, real_bssid, fake_channel, real_channel):
        """Alert on Evil Twin detection"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print("\n" + "="*60)
        print(f"⚠️  EVIL TWIN DETECTED! {timestamp}")
        print("="*60)
        print(f"Network Name (SSID): {ssid}")
        print(f"Legitimate AP:       {real_bssid} (Channel {real_channel})")
        print(f"FAKE AP:             {fake_bssid} (Channel {fake_channel})")
        print("="*60 + "\n")
        
        # Log to file
        with open("wifi_attacks.log", "a") as f:
            f.write(f"{timestamp} | EVIL_TWIN | {ssid} | Real: {real_bssid} | Fake: {fake_bssid}\n")
        
        # Play alert sound
        try:
            os.system("paplay /usr/share/sounds/freedesktop/stereo/dialog-warning.oga 2>/dev/null &")
        except:
            pass
    
    def packet_handler(self, pkt):
        """Main packet handler"""
        try:
            # Detect deauth attacks
            self.detect_deauth_attack(pkt)
            
            # Detect Evil Twin APs
            self.detect_evil_twin(pkt)
            
        except Exception as e:
            pass  # Silently ignore parsing errors
    
    def start_monitoring(self):
        """Start WiFi monitoring"""
        print("="*60)
        print("WiFi-Guardian - Real-time Attack Detector")
        print("="*60)
        print(f"Interface: {self.interface}")
        print(f"Monitoring for: Deauth attacks, Evil Twin APs")
        print(f"Logs: wifi_attacks.log")
        print("="*60)
        print("\n[*] Starting packet capture... (Press Ctrl+C to stop)\n")
        
        try:
            # Sniff packets
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n\n[*] Stopping WiFi-Guardian...")
            self.print_statistics()
    
    def print_statistics(self):
        """Print detection statistics"""
        print("\n" + "="*60)
        print("Detection Statistics")
        print("="*60)
        print(f"Known APs: {len(self.legitimate_aps)}")
        print(f"Deauth Patterns: {len(self.deauth_count)}")
        print("="*60 + "\n")


class WiFiScanner:
    """Scan for nearby WiFi networks"""
    
    @staticmethod
    def scan_networks(interface="wlan0mon", timeout=30):
        """Scan for WiFi networks"""
        networks = {}
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt.addr2
                
                try:
                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                    
                    # Get channel
                    stats = pkt[Dot11Beacon]
                    channel = ord(pkt[Dot11Elt:3].info) if len(pkt[Dot11Elt:3].info) == 1 else 0
                    
                    # Get signal strength
                    rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
                    
                    # Get encryption
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                    encryption = "WPA2" if "privacy" in cap.lower() else "OPEN"
                    
                    networks[bssid] = {
                        'ssid': ssid,
                        'channel': channel,
                        'rssi': rssi,
                        'encryption': encryption
                    }
                except:
                    pass
        
        print(f"[*] Scanning WiFi networks for {timeout} seconds...")
        sniff(iface=interface, prn=packet_handler, timeout=timeout, store=0)
        
        # Print results
        print("\n" + "="*80)
        print(f"{'SSID':<30} {'BSSID':<20} {'Channel':<10} {'RSSI':<10} {'Encryption'}")
        print("="*80)
        
        for bssid, info in sorted(networks.items(), key=lambda x: x[1]['rssi'], reverse=True):
            print(f"{info['ssid']:<30} {bssid:<20} {info['channel']:<10} {info['rssi']:<10} {info['encryption']}")
        
        print("="*80 + "\n")
        
        return networks


def setup_monitor_mode(interface="wlan0"):
    """Setup wireless interface in monitor mode"""
    print(f"[*] Setting up monitor mode on {interface}...")
    
    commands = [
        f"sudo airmon-ng check kill",
        f"sudo ip link set {interface} down",
        f"sudo iw {interface} set monitor none",
        f"sudo ip link set {interface} up",
    ]
    
    for cmd in commands:
        print(f"[*] Running: {cmd}")
        os.system(cmd)
    
    print(f"[+] Monitor mode enabled on {interface}")
    print(f"[*] Interface is now {interface}mon or {interface}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="WiFi-Guardian - WiFi Attack Detector")
    parser.add_argument("-i", "--interface", default="wlan0mon",
                       help="Wireless interface in monitor mode (default: wlan0mon)")
    parser.add_argument("--scan", action="store_true",
                       help="Scan for WiFi networks and exit")
    parser.add_argument("--setup", metavar="INTERFACE",
                       help="Setup monitor mode on specified interface")
    
    args = parser.parse_args()
    
    if args.setup:
        setup_monitor_mode(args.setup)
        sys.exit(0)
    
    if args.scan:
        WiFiScanner.scan_networks(args.interface)
        sys.exit(0)
    
    # Check root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        print("[!] Please run with: sudo python3 wifi_guardian.py")
        sys.exit(1)
    
    # Start guardian
    guardian = WiFiGuardian(args.interface)
    guardian.start_monitoring()
