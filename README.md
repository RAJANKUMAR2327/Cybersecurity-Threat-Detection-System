# CyberShield — Cybersecurity Threat Detection System

## 🛡️ Overview
A full-stack real-time network threat detection system built with Python, Scapy, and Machine Learning.

## 📁 Project Structure
```
threat_detection/
├── main.py                        # Entry point CLI
├── requirements.txt               # Dependencies
├── core/
│   ├── network_monitor.py         # Packet capture & flow tracking (Scapy)
│   ├── intrusion_detector.py      # Rule-based + ML detection engine
│   └── malware_analyzer.py        # File, payload & process analysis
├── alerts/
│   └── alert_system.py            # Multi-channel alert dispatcher
├── dashboard/
│   ├── dashboard_server.py        # Flask + SocketIO API server
│   └── index.html                 # Real-time security dashboard UI
├── logs/                          # Alert logs (auto-created)
└── captures/                      # PCAP captures (optional)
```

## ⚡ Quick Start

### 1. Install dependencies
```bash
cd threat_detection
pip install -r requirements.txt
```

### 2. Run full system (monitor + dashboard)
```bash
# On Linux/Mac (root needed for raw packet capture)
sudo python main.py

# Without sudo (uses traffic simulation mode)
python main.py
```

### 3. Open dashboard
```
http://localhost:5000
```

## 🎮 Modes

| Command | Description |
|---|---|
| `python main.py` | Full system with web dashboard |
| `python main.py --no-dashboard` | Monitor + console alerts only |
| `python main.py --demo` | Auto-injects simulated attacks |
| `python main.py --scan /path/to/file` | Scan a file for malware |
| `python main.py --port 8080` | Custom dashboard port |

## 🔍 Detection Capabilities

### Rule-Based Detection
| Threat | MITRE Technique | Trigger |
|---|---|---|
| Port Scan | T1046 | 20+ unique ports in 10s |
| SYN Flood | T1499 | 100+ SYNs/sec per source |
| Brute Force | T1110 | 10+ attempts to SSH/RDP/etc in 60s |
| DNS Tunneling | T1048 | DNS payload > 200 bytes |
| ICMP Flood | T1498 | 50+ ICMP packets/sec |
| Suspicious Payload | T1059 | Pattern match (shell, SQL injection, etc) |
| Blacklisted IP | T1071 | Known malicious IP database |
| Malformed Packet | T1599 | Tiny IP fragments |

### ML Anomaly Detection
- **Algorithm**: Isolation Forest
- **Features**: packet count, byte count, duration, PPS, avg packet size, inter-arrival time, flag diversity
- **Auto-trains** on first 200 flows, retrains every 100 new samples
- **Flags** statistical outliers with confidence score

### Malware Analysis
- SHA256 + MD5 hash reputation check
- 14 YARA-like payload pattern signatures
- Shannon entropy analysis (detects packed/encrypted files)
- PE header inspection
- Psutil-based process behavior monitoring

## 🔔 Alert Channels
Configure in `AlertConfig`:
- **Console** — rich colored terminal output (always on)
- **JSON Log** — `logs/alerts.json` (one JSON per line)
- **Email** — SMTP with HTML-formatted alerts
- **Webhook** — Slack/Teams/custom HTTP endpoints

## 🌐 REST API
| Endpoint | Description |
|---|---|
| `GET /api/status` | System health & stats |
| `GET /api/events` | Threat event log |
| `GET /api/flows` | Active network flows |
| `GET /api/packets` | Recent captured packets |
| `GET /api/malware` | Malware scan results |
| `GET /api/top-talkers` | Top source IPs |
| `POST /api/scan-file` | Trigger file scan |
| `POST /api/simulate-attack` | Inject test attack |

## ⚠️ Notes
- Raw packet capture requires **root/administrator** privileges
- Without root, the system runs in **simulation mode** (fake traffic for testing)
- For production use, integrate with a real threat intelligence feed
- The blocklist in `intrusion_detector.py` is a small example — replace with a real feed
