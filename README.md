# 🔍 Basic Network Scanner

A powerful command-line network scanner built in Python with real-time CVE lookup.
Designed for educational purposes and authorized network testing.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Version](https://img.shields.io/badge/Version-4.0-orange)

---

## 🚀 Features

- **Ping Sweep** — Discover all live hosts on a network (e.g. 192.168.1.0/24)
- **Port Scanner** — Multi-threaded TCP port scanning for fast results
- **Service Detection** — Identify what service is running on each open port
- **Banner Grabbing** — Read service banners (HTTP, FTP, SSH etc.)
- **OS Fingerprinting** — Guess the OS using TTL analysis
- **Vulnerability Hints** — Flag dangerous ports (SMB, RDP, Telnet etc.)
- **CVE Lookup** — Real-time vulnerability lookup from NIST NVD database
- **Report Export** — Save results as JSON, TXT, or HTML
- **Colored CLI Output** — Clean, color-coded terminal output

---

## 📋 Requirements
```
Python 3.x
pip install tabulate colorama requests
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
│   ├── cve_lookup.py       ← Real-time CVE lookup (NIST NVD)
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

**Skip CVE lookup (faster scan):**
```bash
python scanner.py -t 127.0.0.1 -p 1-500 --no-cve
```

**Save as text report:**
```bash
python scanner.py -t 127.0.0.1 -p 1-500 -o txt
```

**See all options:**
```bash
python scanner.py --help
```

---

## 📊 Sample Output
```
=======================================================
       Basic Network Scanner v4.0
=======================================================
  Target : 127.0.0.1
  Ports  : 1-500
  Output : html
=======================================================

[*] Detecting OS for 127.0.0.1...
  [+] OS Guess: Windows (TTL=128)

[*] Scanning 127.0.0.1 from port 1 to 500...
  [+] Port 135 is OPEN
  [+] Port 445 is OPEN

[*] Looking up CVEs for Windows RPC (port 135)...
  [!] Found 3 CVE(s)!

[*] Looking up CVEs for Windows SMB (port 445)...
  [!] Found 3 CVE(s)!

+--------+--------+-------------+-----------+--------+--------------+
|  Port  | Status |   Service   |   Banner  |  Risk  |     CVEs     |
+========+========+=============+===========+========+==============+
|  135   |  OPEN  | Windows RPC | No banner |  LOW   | 3 CVEs found |
|  445   |  OPEN  | Windows SMB | No banner |  HIGH  | 3 CVEs found |
+--------+--------+-------------+-----------+--------+--------------+

[!] CVE Details for port 445 (Windows SMB):
  CVE-1999-0495 | Score: 10.0
  A remote attacker can gain access to a file system using .. (dot dot)...

[*] HTML report saved: output/report_127_0_0_1.html
[*] All done!
```

---

## 📄 HTML Report

The HTML report includes:
- Summary dashboard (Open Ports / High Risk / CVEs Found)
- Color-coded risk levels (RED = High, ORANGE = Medium, BLUE = Low)
- Full CVE details with CVSS scores pulled from NIST NVD
- Scan metadata (target, OS, ports scanned, timestamp)

---

## 🔧 All CLI Options

| Flag | Description | Example |
|------|-------------|---------|
| `-t` | Single target IP | `-t 192.168.1.1` |
| `-n` | Network range to sweep | `-n 192.168.1.0/24` |
| `-p` | Port range | `-p 1-1024` |
| `-o` | Output format (json/txt/html/none) | `-o html` |
| `--no-os` | Skip OS fingerprinting | `--no-os` |
| `--no-cve` | Skip CVE lookup | `--no-cve` |

---

## 🗺️ How It Works
```
Target IP
    │
    ├── 1. OS Fingerprinting (TTL analysis via ping)
    │
    ├── 2. Port Scanning (multi-threaded TCP connect)
    │
    ├── 3. Service Detection (banner grabbing)
    │
    ├── 4. Vulnerability Assessment (known risky ports)
    │
    ├── 5. CVE Lookup (NIST NVD public API)
    │
    └── 6. Report Generation (JSON / TXT / HTML)
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
2nd Year | Aspiring Security Engineer

[![GitHub](https://img.shields.io/badge/GitHub-pagalavan22-181717?logo=github)](https://github.com/pagalavan22)