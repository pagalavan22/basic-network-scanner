import subprocess
import concurrent.futures
import ipaddress

def ping_host(ip):
    """Ping a single IP. Returns IP if alive, else None."""
    try:
        output = subprocess.check_output(
            ["ping", "-n", "1", "-w", "500", str(ip)],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")

        if "TTL=" in output:
            return str(ip)
    except:
        pass
    return None

def ping_sweep(network):
    """
    Scan all IPs in a network range.
    Example network: '192.168.1.0/24'
    """
    live_hosts = []

    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        print(f"  [!] Invalid network: {network}")
        return []

    hosts = list(net.hosts())  # all IPs except network & broadcast
    total  = len(hosts)

    print(f"\n[*] Sweeping {network} ({total} hosts)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(ping_host, hosts))

    for result in results:
        if result:
            print(f"  [+] Host alive: {result}")
            live_hosts.append(result)

    print(f"\n[*] Found {len(live_hosts)} live host(s) out of {total}")
    return live_hosts