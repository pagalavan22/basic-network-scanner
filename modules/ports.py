import socket
import concurrent.futures

def scan_port(ip, port):
    """Try to connect to a single port. Returns port if open, else None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # wait max 1 second per port
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port  # port is open
    except:
        pass
    return None

def scan_ports(ip, start_port=1, end_port=1024):
    """Scan a range of ports on the given IP using multiple threads."""
    open_ports = []
    ports = range(start_port, end_port + 1)

    print(f"\n[*] Scanning {ip} from port {start_port} to {end_port}...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for port, result in zip(ports, results):
        if result is not None:
            print(f"  [+] Port {result} is OPEN")
            open_ports.append(result)

    return open_ports
