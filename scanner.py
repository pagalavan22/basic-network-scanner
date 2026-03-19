import argparse
import json
import os
from modules.ports import scan_ports
from modules.banners import identify_service
from modules.fingerprint import get_os
from modules.ping_sweep import ping_sweep
from tabulate import tabulate

def parse_ports(port_arg):
    if "-" in port_arg:
        start, end = port_arg.split("-")
        return int(start), int(end)
    elif "," in port_arg:
        ports = [int(p) for p in port_arg.split(",")]
        return min(ports), max(ports)
    else:
        p = int(port_arg)
        return p, p

def scan_single(target, ports_arg, output_fmt, skip_os):
    """Scan a single IP target."""
    start, end = parse_ports(ports_arg)

    print("=" * 50)
    print("      Basic Network Scanner v3.0")
    print("=" * 50)
    print(f"  Target : {target}")
    print(f"  Ports  : {ports_arg}")
    print(f"  Output : {output_fmt}")
    print("=" * 50)

    # OS Fingerprinting
    os_guess = "Skipped"
    if not skip_os:
        print(f"\n[*] Detecting OS for {target}...")
        os_guess = get_os(target)
        print(f"  [+] OS Guess: {os_guess}")

    # Port Scanning
    open_ports = scan_ports(target, start, end)

    # Banner Grabbing
    results = []
    for port in open_ports:
        service, banner = identify_service(target, port)
        results.append({
            "port": port,
            "status": "OPEN",
            "service": service,
            "banner": banner if banner else "No banner"
        })

    # Display table
    print("\n--- Scan Results ---")
    if results:
        table = [[r["port"], r["status"], r["service"], r["banner"]]
                 for r in results]
        print(tabulate(table,
                       headers=["Port", "Status", "Service", "Banner"],
                       tablefmt="grid"))
    else:
        print("  No open ports found.")

    # Save report
    save_report(target, os_guess, ports_arg, results, output_fmt)

def save_report(target, os_guess, ports, results, fmt):
    if fmt == "none":
        return

    os.makedirs("output", exist_ok=True)
    filename = f"output/report_{target.replace('.', '_')}"

    if fmt == "json":
        path = filename + ".json"
        report = {
            "target": target,
            "os_guess": os_guess,
            "ports_scanned": ports,
            "open_ports": results
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=4)
        print(f"\n[*] JSON report saved: {path}")

    elif fmt == "txt":
        path = filename + ".txt"
        with open(path, "w") as f:
            f.write(f"Target : {target}\n")
            f.write(f"OS     : {os_guess}\n")
            f.write(f"Ports  : {ports}\n\n")
            for r in results:
                f.write(f"Port {r['port']} | {r['service']} | {r['banner']}\n")
        print(f"\n[*] TXT report saved: {path}")

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Scanner v3.0",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target",
                        help="Single target IP (e.g. 127.0.0.1)")
    parser.add_argument("-n", "--network",
                        help="Network to sweep (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",
                        default="1-1024",
                        help="Port range: '1-500' or '80,443' (default: 1-1024)")
    parser.add_argument("-o", "--output",
                        default="json",
                        choices=["json", "txt", "none"],
                        help="Output format (default: json)")
    parser.add_argument("--no-os",
                        action="store_true",
                        help="Skip OS fingerprinting")

    args = parser.parse_args()

    if args.network:
        # Ping sweep mode
        print("=" * 50)
        print("      Basic Network Scanner v3.0")
        print("=" * 50)
        print(f"  Mode    : Ping Sweep")
        print(f"  Network : {args.network}")
        print("=" * 50)

        live_hosts = ping_sweep(args.network)

        if live_hosts and args.ports:
            choice = input("\n[?] Scan open ports on live hosts? (y/n): ")
            if choice.lower() == "y":
                for host in live_hosts:
                    print(f"\n{'='*50}")
                    scan_single(host, args.ports, args.output, args.no_os)

    elif args.target:
        scan_single(args.target, args.ports, args.output, args.no_os)

    else:
        print("[!] Please provide -t (single IP) or -n (network range)")
        print("    Example: python scanner.py -t 127.0.0.1 -p 1-500")
        print("    Example: python scanner.py -n 192.168.1.0/24")

    print("\n[*] All done!\n")

if __name__ == "__main__":
    main()