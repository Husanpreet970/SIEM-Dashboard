# AEGIS SIEM v4 — Gateway Network Monitor

## What's New in v4

### 1. Gateway-Wide Packet Capture
The sniffer now captures traffic from **every device on your network**, not just your PC.

- **Promiscuous mode** enabled on the network interface so your machine sees all LAN traffic.
- Works on all platforms: Linux (`sudo`), macOS (`sudo`), Windows (run as Administrator).
- Automatically detects your local subnet(s) and filters out loopback-only traffic.
- On Linux: tries `sniff(iface="any")` for maximum coverage.

### 2. Sites Visited Tracking
A new **Sites** tab shows every domain any device on your network has visited:

- Tracks via DNS queries, HTTPS SNI, and HTTP Host headers.
- Shows: domain, how many devices visited it, visit count, last seen time.
- Malware/C2 domains are flagged in red with ☠️.
- Backed by a `site_visits` table (upserts, so no duplicates).
- Smart de-duplication: the same site visit from the same IP is only logged once every 45 seconds to avoid flooding.

### 3. Attack-Focused Alerts (No More Traffic Spam)
The old "high traffic volume" alert was firing constantly for normal browsing.

**New behavior:**
- High-volume alerts **only fire for non-browsing traffic** (not HTTPS/HTTP/DNS).
- Threshold raised to 200 suspicious events/minute (was 100 total events).
- New dedicated **💥 Attacks tab** for attack-specific events and alerts.
- Attack types create specific alerts: SQL injection, XSS, path traversal, shell injection, malware C2, brute force, port scans.
- Alert de-duplication window: 5 minutes per message.

### 4. New Attack Tab
Dedicated tab showing:
- Attack event breakdown (counts by type).
- Attack-specific alerts only (filtered from noise).
- Live attack packet stream, color-coded.

### 5. Smarter Event Classification
Every log entry now has an `event_type`:
- `https_visit`, `http_visit`, `dns_lookup` — browsing
- `attack` — active attack payload detected
- `malware_c2` — malware command-and-control communication
- `auth_attempt` — SSH/RDP/FTP brute force
- `port_scan` — port scanning activity
- `port_access` — access to sensitive ports

---

## Setup

### Requirements
- Node.js 18+
- Python 3.8+
- PostgreSQL
- Scapy (`pip install scapy`)

### Sniffer
```bash
cd sniffer
pip install -r requirements.txt
# Linux/macOS:
sudo python3 sniffer.py
# Windows (as Administrator):
python sniffer.py
```

### Backend
```bash
cd backend
cp .env.example .env   # edit with your DB credentials
npm install
npm start
```

### Frontend
```bash
cd frontend
cp .env.example .env   # set VITE_BACKEND_URL if needed
npm install
npm run dev
```

---

## Gateway Capture Notes

For true gateway-wide capture (all devices on LAN):

**Option A — Run on your router** (best coverage)
- Install Python + Scapy on your router (OpenWrt supports this).
- Point BACKEND_URL to your SIEM server's IP.

**Option B — Promiscuous mode on your PC** (easier)
- Run `sudo python3 sniffer.py` on your PC.
- Works for **switched networks only if your switch supports port mirroring** or you're on a hub/WiFi (which is broadcast by nature).
- On WiFi: all traffic is visible in monitor mode.

**Option C — Router port mirror**
- Configure your managed switch to mirror all traffic to your PC's port.
- Then run the sniffer normally.

---

## New API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /sites` | Sites visited per IP |
| `GET /sites/summary` | Top sites across all devices |
| `GET /stats` | Now includes `topSites` and `attackStats` |
