# Known dangerous ports and why they're risky
VULNERABLE_PORTS = {
    21:   ("FTP",        "Transfers files in plaintext — credentials can be sniffed"),
    22:   ("SSH",        "Secure, but brute-force attacks are common"),
    23:   ("Telnet",     "DANGEROUS — sends everything including passwords in plaintext"),
    25:   ("SMTP",       "Can be abused for spam if misconfigured"),
    53:   ("DNS",        "Can be abused for DNS amplification attacks"),
    80:   ("HTTP",       "Unencrypted web traffic — use HTTPS instead"),
    110:  ("POP3",       "Email in plaintext — credentials exposed"),
    135:  ("RPC",        "Common target for Windows exploits"),
    139:  ("NetBIOS",    "Old Windows sharing — often exploited"),
    443:  ("HTTPS",      "Secure — but check for outdated SSL/TLS versions"),
    445:  ("SMB",        "HIGH RISK — EternalBlue/WannaCry target"),
    1433: ("MSSQL",      "Database port exposed — should not be public"),
    3306: ("MySQL",      "Database port exposed — should not be public"),
    3389: ("RDP",        "HIGH RISK — common ransomware entry point"),
    5900: ("VNC",        "Remote desktop — often has weak passwords"),
    8080: ("HTTP-Alt",   "Alternate web port — check for misconfigurations"),
}

def check_vulns(port):
    """Return (risk_level, description) for a given port."""
    if port in VULNERABLE_PORTS:
        service, desc = VULNERABLE_PORTS[port]
        if port in [23, 445, 3389]:
            return "HIGH", desc
        elif port in [21, 110, 139, 3306, 1433, 5900]:
            return "MEDIUM", desc
        else:
            return "LOW", desc
    return "INFO", "No known vulnerabilities"
