import argparse
import json
import os
from modules.ports import scan_ports
from modules.banners import identify_service
from modules.fingerprint import get_os
from tabulate import tabulate

def parse_ports(port_arg):
    """Parse port argument like '1-500' or '80,443,8080'"""
    if "-" in port_arg:
        start, end = port_arg.split("-")
        return int(start), int(end)
    elif "," in port_arg:
        ports = [int(p) for p in port_arg.split(",")]
        return min(ports), max(ports)
    else:
        p = int(port_arg)
        return p, p

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Scanner - by You!",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target",
                        required=True,
                        help="Target IP address (e.g. 127.0.0.1)")
    parser.add_argument("-p", "--ports",
                        default="1-1024",
                        help="Port range: '1-500' or '80,443' (default: 1-1024)")
    parser.add_argument("-o", "--output",
                        default="json",
                        choices=["json", "txt", "none"],
                        help="Output format: json, txt, or none (default: json)")
    parser.add_argument("--no-os",
                        action="store_true",
                        help="Skip OS fingerprinting")

    args = parser.parse_args()

    print("=" * 50)
    print("      Basic Network Scanner v2.0")
    print("=" * 50)
    print(f"  Target : {args.target}")
    print(f"  Ports  : {args.ports}")
    print(f"  Output : {args.output}")
    print("=" * 50)

    # OS Fingerprinting
    os_guess = "Skipped"
    if not args.no_os:
        print(f"\n[*] Detecting OS for {args.target}...")
        os_guess = get_os(args.target)
        print(f"  [+] OS Guess: {os_guess}")

    # Port Scanning
    start, end = parse_ports(args.ports)
    open_ports = scan_ports(args.target, start, end)

    # Banner Grabbing
    results = []
    if open_ports:
        for port in open_ports:
            service, banner = identify_service(args.target, port)
            results.append({
                "port": port,
                "status": "OPEN",
                "service": service,
                "banner": banner if banner else "No banner"
            })

    # Display results table
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
    if args.output != "none":
        os.makedirs("output", exist_ok=True)
        filename = f"output/report_{args.target.replace('.', '_')}"

        if args.output == "json":
            report = {
                "target": args.target,
                "os_guess": os_guess,
                "ports_scanned": f"{start}-{end}",
                "open_ports": results
            }
            path = filename + ".json"
            with open(path, "w") as f:
                json.dump(report, f, indent=4)
            print(f"\n[*] JSON report saved: {path}")

        elif args.output == "txt":
            path = filename + ".txt"
            with open(path, "w") as f:
                f.write(f"Target : {args.target}\n")
                f.write(f"OS     : {os_guess}\n")
                f.write(f"Ports  : {start}-{end}\n\n")
                for r in results:
                    f.write(f"Port {r['port']} | {r['service']} | {r['banner']}\n")
            print(f"\n[*] TXT report saved: {path}")

    print("[*] Scan complete.\n")

if __name__ == "__main__":
    main()