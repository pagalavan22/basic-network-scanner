import socket

# Common ports and their service names
COMMON_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "Windows RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "Windows SMB",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5900: "VNC",
    8080: "HTTP Alternate",
}

def get_banner(ip, port):
    """Try to grab the banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        # Send a simple HTTP request to wake up the service
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if banner:
            # Return just the first line of the banner
            return banner.split("\n")[0]
    except:
        pass
    return None

def identify_service(ip, port):
    """Return service name and banner for a given port."""
    service = COMMON_SERVICES.get(port, "Unknown")
    banner  = get_banner(ip, port)
    return service, banner