# 🛡️ AegisNet — Network Intrusion Detection & Prevention System

> **Real-time IDS/IPS engine with AI-powered anomaly detection, a live SOC dashboard, packet capture, and auth log monitoring — built for home labs and small networks.**

---

## Overview

AegisNet is a lightweight, self-hosted Security Operations Center (SOC) stack. It monitors your local network in real time, detects attacks using machine learning, blocks malicious IPs automatically, and presents everything in an interactive web dashboard.

The system is built around four cooperating modules:

```
┌─────────────────────────────────────────────────────────────┐
│                        AegisNet Stack                       │
│                                                             │
│  ┌──────────────┐   flows    ┌──────────────────────────┐   │
│  │ netcapture   │ ─────────► │                          │   │
│  │ (optional    │            │   realengine.py           │   │
│  │  sensor)     │            │   Core IDS/IPS Engine     │   │
│  └──────────────┘            │   • Packet sniffing       │   │
│                              │   • AI anomaly detection  │   │
│  ┌──────────────┐ login_fail │   • Auto IP blocking      │   │
│  │ logwatch.py  │ ─────────► │   • REST API :5050        │   │
│  │ Auth log     │            │                          │   │
│  │ watcher      │            └──────────┬───────────────┘   │
│  └──────────────┘                       │ SQLite (alert.db) │
│                                         ▼                   │
│                              ┌──────────────────────────┐   │
│                              │   scandash.py            │   │
│                              │   Streamlit SOC Dashboard │   │
│                              │   Live map, charts, alerts│   │
│                              └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

### Detection (IDS)
- **Port scan detection** — SYN, FIN, XMAS, NULL, ACK scans
- **DDoS / flood detection** — packet rate thresholds per flow window
- **Brute-force detection** — real failed-login counts fed by `logwatch.py`
- **AI anomaly detection** — `IsolationForest` model trained on live traffic
- **OS fingerprinting** — TTL + TCP window size heuristics
- **ISP / ASN enrichment** — via ip-api.com or local MaxMind GeoLite2 DB

### Prevention (IPS)
- **Auto IP blocking** — `iptables` rules applied on high-severity alerts
- **IP whitelist** — configured IPs are never auto-blocked
- **Block rate-limiter** — prevents duplicate firewall rules
- **Manual block/unblock** — via REST API endpoints

### Dashboard (`scandash.py`)
- Live alert feed with severity colouring
- World map showing attacker geolocations
- Incident deduplication — one row per IP + attack type with hit counter
- Threat score history chart per IP
- Blocked IPs management
- Browsing activity (DNS) monitor
- Login events log
- Email and Telegram notification settings panel
- Secure login with hashed access codes

### Log Watcher (`logwatch.py`)
- Tails `/var/log/auth.log` (Linux) or Apple Unified Log (macOS)
- Detects SSH, PAM, sudo, and FTP failures
- Forwards failed login events to the engine in real time

### Packet Capture (`netcapture.py`)
- Optional remote sensor — runs on a separate machine
- Per-flow aggregation before sending to engine (reduces noise)
- Live flow summary table printed to console

---

## Requirements

- Python **3.11+**
- Linux (Ubuntu/Debian recommended) or macOS
- Root / `sudo` access (required for packet sniffing and iptables)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Quick Start

### 1. Configure secrets

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Optional: local MaxMind GeoLite2 database (see GeoIP section below)
GEOIP_DB_PATH=geoip_db/GeoLite2-City.mmdb

# Email notifications (Gmail)
NOTIFY_EMAIL=0
NOTIFY_EMAIL_FROM=you@gmail.com
NOTIFY_EMAIL_TO=you@gmail.com
NOTIFY_EMAIL_PASS=your_gmail_app_password

# Telegram notifications
NOTIFY_TELEGRAM=0
NOTIFY_TELEGRAM_TOKEN=your_bot_token
NOTIFY_TELEGRAM_CHAT_ID=your_chat_id

# Dashboard login (set your own username + SHA-256 hash of your access code)
DASH_USER=admin
DASH_CODE_HASH=<sha256_of_your_password>
```

To generate a SHA-256 hash for your dashboard password:

```bash
python3 -c "import hashlib; print(hashlib.sha256('your_password'.encode()).hexdigest())"
```

### 2. Configure your network interface and subnet

Edit the top of `realengine.py`:

```python
SNIFF_INTERFACE = "eth0"          # your active interface (ip a / ifconfig)
LAN_SUBNET      = "192.168.1.0/24"  # your local subnet
```

Add your own IPs to the whitelist so they are never auto-blocked:

```python
IP_WHITELIST = {
    "127.0.0.1",
    "192.168.1.1",   # your gateway
}
```

### 3. Run the engine

```bash
sudo python3 realengine.py
```

### 4. Run the dashboard (separate terminal)

```bash
streamlit run scandash.py
```

Open your browser at `http://localhost:8501`

### 5. (Optional) Run the auth log watcher

```bash
sudo python3 logwatch.py
```

### 6. (Optional) Run the remote packet sensor

```bash
sudo python3 netcapture.py
```

---

## REST API

The engine exposes a REST API on port **5050**.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | All alerts |
| `GET` | `/devices` | LAN devices discovered via ARP |
| `GET` | `/blocked` | Currently blocked IPs |
| `POST` | `/inject` | Inject a flow (used by netcapture.py) |
| `POST` | `/login_fail` | Report a failed login (used by logwatch.py) |
| `POST` | `/whitelist` | Add an IP to the whitelist |
| `DELETE` | `/block/<ip>` | Unblock an IP |
| `GET` | `/scan_types` | Recent scan type breakdown |

Example — add an IP to the whitelist:

```bash
curl -X POST http://127.0.0.1:5050/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

---

## Offline Geolocation (optional)

By default AegisNet uses the free [ip-api.com](http://ip-api.com) service (45 req/min limit). For unlimited offline lookups, download the free MaxMind GeoLite2 database:

1. Register at [maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
2. Download `GeoLite2-City.mmdb`
3. Place it at `geoip_db/GeoLite2-City.mmdb`
4. Set `GEOIP_DB_PATH=geoip_db/GeoLite2-City.mmdb` in your `.env`

To keep the database updated, create a `GeoIP.conf` file (see MaxMind docs) and run:

```bash
geoipupdate -f GeoIP.conf -d geoip_db/
```

> **Never commit your `GeoIP.conf`** — it contains your MaxMind license key.

---

## Database

All data is stored in `alert.db` (SQLite). Tables:

| Table | Contents |
|-------|----------|
| `alerts` | Raw alert events |
| `incidents` | Deduplicated incidents (1 row per IP + attack type) |
| `risk_history` | Risk score over time per IP |
| `blocked_ips` | IPs blocked by the engine |
| `devices` | LAN devices discovered via ARP |
| `login_events` | Failed login events from logwatch.py |
| `browsing_activity` | DNS queries observed on the network |

---

## Project Structure

```
AegisNet/
├── realengine.py       # Core IDS/IPS engine (run with sudo)
├── scandash.py         # Streamlit SOC dashboard
├── logwatch.py         # Auth log watcher (run with sudo)
├── netcapture.py       # Optional remote packet sensor (run with sudo)
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable template
├── .gitignore
└── geoip_db/           # Place GeoLite2-City.mmdb here (not committed)
```

---

## Security Notes

- **Never commit `.env` or `GeoIP.conf`** — both contain secrets.
- **Never commit `alert.db`** — it contains real network data from your environment.
- The engine requires root only for raw socket access and iptables. The dashboard can run as a normal user.
- On macOS, iptables blocking is automatically disabled (the engine runs in detection-only mode).

---

## Dependencies

See [`requirements.txt`](requirements.txt) for the full list. Key packages:

| Package | Used for |
|---------|----------|
| `flask` | REST API server |
| `scapy` | Packet sniffing, ARP scanning |
| `scikit-learn` | IsolationForest anomaly detection |
| `streamlit` | SOC dashboard UI |
| `folium` / `plotly` | Map and charts |
| `geoip2` | Offline geolocation |
| `python-dotenv` | Secret management |

---

## License

MIT License — see `LICENSE` for details.

---

*Built for educational and home-lab use. Always get permission before monitoring a network you do not own.*
