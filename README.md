# 🔍 Basic Network Scanner

A powerful command-line network scanner built in Python.
Designed for educational purposes and authorized network testing.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 🚀 Features

- **Ping Sweep** — Discover all live hosts on a network (e.g. 192.168.1.0/24)
- **Port Scanner** — Multi-threaded TCP port scanning for fast results
- **Service Detection** — Identify what service is running on each open port
- **Banner Grabbing** — Read service banners (HTTP, FTP, SSH etc.)
- **OS Fingerprinting** — Guess the OS using TTL analysis
- **Vulnerability Hints** — Flag dangerous ports (SMB, RDP, Telnet etc.)
- **Report Export** — Save results as JSON, TXT, or HTML
- **Colored CLI Output** — Clean, color-coded terminal output

---

## 📋 Requirements
```
Python 3.x
pip install tabulate colorama
```

---

## 📁 Project Structure
```
network-scanner/
├── scanner.py              ← Main entry point
├── modules/
│   ├── ports.py            ← Multi-threaded port scanner
│   ├── banners.py          ← Service & banner detection
│   ├── fingerprint.py      ← OS fingerprinting via TTL
│   ├── ping_sweep.py       ← Network-wide host discovery
│   ├── vulns.py            ← Vulnerability assessment
│   └── html_report.py      ← HTML report generator
└── output/                 ← Scan reports saved here
```

---

## ⚡ Usage

**Scan a single target:**
```bash
python scanner.py -t 127.0.0.1 -p 1-500
```

**Scan with HTML report:**
```bash
python scanner.py -t 127.0.0.1 -p 1-1024 -o html
```

**Sweep entire network:**
```bash
python scanner.py -n 192.168.1.0/24
```

**Skip OS detection:**
```bash
python scanner.py -t 127.0.0.1 -p 1-500 --no-os
```

**See all options:**
```bash
python scanner.py --help
```

---

## 📊 Sample Output
```
==================================================
      Basic Network Scanner v3.0
==================================================
  Target : 127.0.0.1
  Ports  : 1-500
  Output : html
==================================================

[*] Detecting OS for 127.0.0.1...
  [+] OS Guess: Windows (TTL=128)

[*] Scanning 127.0.0.1 from port 1 to 500...
  [+] Port 135 is OPEN
  [+] Port 445 is OPEN

+--------+--------+-------------+-----------+--------+
|  Port  | Status |   Service   |   Banner  |  Risk  |
+========+========+=============+===========+========+
|  135   |  OPEN  | Windows RPC | No banner |  LOW   |
|  445   |  OPEN  | Windows SMB | No banner |  HIGH  |
+--------+--------+-------------+-----------+--------+

[*] HTML report saved: output/report_127_0_0_1.html
```

---

## 🛡️ Disclaimer

This tool is for **educational purposes** and **authorized network testing only**.
Do not scan networks you don't own or have explicit permission to test.
Unauthorized scanning may be illegal in your country.

---

## 👨‍💻 Author

**Tamil Pagalavan E**
B.E. Computer Science Engineering (Cyber Security)