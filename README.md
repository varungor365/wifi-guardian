# WiFi-Guardian - Wireless Attack Detector

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-green)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Network-red)](https://github.com/varungor365/wifi-guardian)

Real-time WiFi attack detection system identifying deauthentication attacks, rogue access points, and evil twin attacks.

## ⚠️ LEGAL DISCLAIMER

**FOR NETWORK SECURITY MONITORING ON YOUR OWN NETWORKS ONLY**

Monitor only networks you own or have authorization to monitor. Unauthorized network monitoring is illegal.

---

## 🎯 Features

- **Deauth Attack Detection** - Identify WiFi deauthentication floods
- **Rogue AP Detection** - Detect unauthorized access points
- **Evil Twin Detection** - Identify fake access points
- **Real-Time Monitoring** - Live network traffic analysis
- **Alert System** - Instant notifications of attacks
- **Packet Analysis** - Deep 802.11 frame inspection

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/varungor365/wifi-guardian.git
cd wifi-guardian
pip install -r requirements.txt
```

### Start Monitoring (Requires Root/Admin)

```bash
sudo python wifi_guardian.py --interface wlan0
```

---

## 📊 Expected Output

```
[+] WiFi-Guardian v1.0 - Wireless Attack Detector
[+] Monitoring interface: wlan0
[+] Mode: Monitor
[+] Watching for attacks...

[!] ALERT: Deauthentication attack detected!
    Attacker MAC: 00:11:22:33:44:55
    Target: YourWiFi (Channel 6)
    Packets: 147 in 2.3 seconds
    Severity: HIGH

[!] ALERT: Rogue AP detected!
    SSID: Free-WiFi
    MAC: AA:BB:CC:DD:EE:FF
    Channel: 11
    Signal: -45 dBm
```

---

## 🔧 Requirements

- Python 3.8+
- Scapy
- Wireless adapter with monitor mode support
- Linux (recommended) or macOS

### Setup Monitor Mode

```bash
sudo airmon-ng start wlan0
```

---

## 💻 Usage Examples

### Basic Monitoring
```bash
sudo python wifi_guardian.py --interface wlan0
```

### Advanced Options
```bash
sudo python wifi_guardian.py \
    --interface wlan0mon \
    --channel 6 \
    --log attacks.log \
    --alert-email security@example.com
```

---

## 🛡️ Detection Techniques

1. **Deauth Detection** - Monitors for abnormal deauth frame rates
2. **AP Fingerprinting** - Identifies known-good vs suspicious APs
3. **Signal Analysis** - Detects signal strength anomalies
4. **Frame Analysis** - Deep packet inspection of 802.11 frames

---

## 📚 Documentation

Full documentation in code comments and wiki.

---

## 🤝 Contributing

Contributions for new detection techniques welcome!

---

## 📜 License

GPL-3.0 - See [LICENSE](LICENSE)

---

## 👨‍💻 Author

**Varun Goradhiya**
- GitHub: [@varungor365](https://github.com/varungor365)

---

**Related Projects:**
- [zerocopy-firewall](https://github.com/varungor365/zerocopy-firewall) - eBPF packet filter
- [phantom-lkm](https://github.com/varungor365/phantom-lkm) - Kernel rootkit

---

*Wireless security monitoring tool. Legal use only.* 🔐📡
