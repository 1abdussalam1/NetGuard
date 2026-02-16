# 🛡️ NetGuard v5.1 — Game Network Monitor & IP Blocker
### Designed by WillyNilly

Real-time network monitor for gamers. See every connection, block unwanted servers, protect your privacy.

## ✨ Features
- 📊 **Live Dashboard** — KPI cards, connection table, bandwidth tracking
- 🎮 **Process Filter** — Filter by game (Valorant, Overwatch, etc.)
- 🌍 **Region Filter** — EU, NA, ME, Asia, CDN
- 🚫 **One-Click Block** — Block IPs directly in Windows Firewall
- 🛡️ **Block Manager** — View, add, and remove ALL firewall blocks
- 🌙 **Dark/Light Mode** — Warm Horizon theme
- 📡 **Deep Packet Capture** — Scapy + Npcap for UDP/TCP
- 🔍 **Geo-Lookup** — Country, city, ISP, cloud provider detection
- 📋 **Export** — Full connection log export
- 🔒 **Security Audited** — Input validation, no command injection

## 🚀 Quick Start

### First Time (One-Click Install)
1. Download and extract the zip
2. Double-click **`install.bat`**
3. It will install Python, packages, and Npcap automatically
4. Done! Click **Start NetGuard** or use the Desktop shortcut

### Already Installed
- Double-click **`run_as_admin.bat`** or the Desktop shortcut

## 📋 Requirements
- **Windows 10/11** (any language)
- **Python 3.10+** (installer downloads it if needed)
- **Npcap** (installer downloads it if needed)
- **Admin rights** (needed for firewall + packet capture)

## 🔧 Manual Install (if you prefer)
```
pip install psutil flask scapy
```
Download Npcap from https://npcap.com/
Then run: `python netguard.py`

## 📁 Files
```
netguard/
├── netguard.py          # Main application
├── install.bat          # One-click installer
├── run_as_admin.bat     # Quick launcher
├── README.md            # This file
├── SECURITY-AUDIT.md    # Security audit report
├── fonts/               # Local fonts (no external connections)
│   ├── inter-*.ttf
│   └── jetbrains-*.ttf
├── blocked_ips.json     # Saved blocks (auto-created)
└── run.bat              # Created by installer
```

## 🛡️ Security
- All fonts loaded locally (zero Google connections)
- IP input validated before any firewall operation
- No command injection possible
- Binds to localhost only (127.0.0.1)
- See SECURITY-AUDIT.md for full report

## 📄 License
Free to use. Made with ❤️ by WillyNilly.
