# 🛡️ AEGIS SIEM — Gateway Network Monitor `v4`

> Real-time network security monitoring with packet sniffing, threat detection, and a live React dashboard — for your entire LAN.

![version](https://img.shields.io/badge/version-v4.0-blue)
![node](https://img.shields.io/badge/node-18%2B-green)
![python](https://img.shields.io/badge/python-3.8%2B-yellow)
![license](https://img.shields.io/badge/license-MIT-purple)
![platform](https://img.shields.io/badge/platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-green)

---

## ✨ Features

- 📡 **Gateway-Wide Packet Capture** — Promiscuous mode sniffing catches traffic from every device on your LAN, not just your machine.
- 🌐 **Sites Visited Tracking** — Tracks domains via DNS queries, HTTPS SNI, and HTTP Host headers. Flags malware/C2 domains in real time.
- 💥 **Attack Detection** — Detects SQL injection, XSS, path traversal, brute force, port scans, and malware C2 communications.
- ⚡ **Live Dashboard** — Socket.IO-powered React frontend with real-time event streams, stats, and color-coded attack feeds.
- 🔕 **Smart Alert De-duplication** — High-volume alerts only fire for non-browsing traffic. 5-minute de-duplication window per alert message.

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Socket.IO Client, Axios |
| Backend | Node.js, Express, Socket.IO, PostgreSQL |
| Sniffer | Python 3, Scapy |

---

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- Python 3.8+
- PostgreSQL
- Scapy (`pip install scapy`)

### 1 — Clone the repo

```bash
git clone https://github.com/Husanpreet970/SIEM-Dashboard.git
cd SIEM-Dashboard
```

### 2 — Start the backend

```bash
cd backend
cp .env.example .env   # add your DB credentials
npm install
npm start
```

### 3 — Start the frontend

```bash
cd frontend
cp .env.example .env   # set VITE_BACKEND_URL if needed
npm install
npm run dev
```

### 4 — Start the sniffer

```bash
cd sniffer
pip install -r requirements.txt

# Linux / macOS:
sudo python3 sniffer.py

# Windows (run as Administrator):
python sniffer.py
```

> ⚠️ **Never commit your `.env` files.** They are excluded by `.gitignore` — use `.env.example` as a template only.

---

## 🌐 Gateway Capture Options

| Option | Method | Notes |
|---|---|---|
| A | Run sniffer on your router | Best coverage. Requires Python + Scapy on OpenWrt. |
| B | Promiscuous mode on your PC | Easy. Works on WiFi (broadcast). Switched networks need port mirroring. |
| C | Router port mirror | Mirror all switch traffic to your PC's port, then run sniffer normally. |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/sites` | Sites visited per device IP |
| GET | `/sites/summary` | Top domains across all devices |
| GET | `/stats` | Live stats including `topSites` and `attackStats` |

---

## 🔍 Event Types

| Type | Meaning |
|---|---|
| `https_visit` / `http_visit` / `dns_lookup` | Normal browsing activity |
| `attack` | Active attack payload detected |
| `malware_c2` | Malware command-and-control communication |
| `auth_attempt` | SSH / RDP / FTP brute force |
| `port_scan` | Port scanning activity |
| `port_access` | Access to sensitive ports |

---

## ⚠️ Legal Disclaimer

This tool is intended for **use on networks you own or have explicit permission to monitor**. Unauthorized network monitoring may violate local laws. Use responsibly.

---

## 📄 License

MIT © [Husanpreet970](https://github.com/Husanpreet970)
