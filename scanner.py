import argparse
import json
import os
from colorama import init, Fore, Style
from modules.ports import scan_ports
from modules.banners import identify_service
from modules.fingerprint import get_os
from modules.ping_sweep import ping_sweep
from modules.vulns import check_vulns
from modules.html_report import generate_html
from modules.cve_lookup import search_cves
from tabulate import tabulate

init(autoreset=True)

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

def save_report(target, os_guess, ports, results, fmt):
    if fmt == "none":
        return
    os.makedirs("output", exist_ok=True)
    filename = f"output/report_{target.replace('.', '_')}"

    if fmt == "json":
        path = filename + ".json"
        with open(path, "w") as f:
            json.dump({"target": target, "os_guess": os_guess,
                       "ports_scanned": ports, "open_ports": results}, f, indent=4)
        print(Fore.CYAN + f"\n[*] JSON report saved: {path}")

    elif fmt == "txt":
        path = filename + ".txt"
        with open(path, "w") as f:
            f.write(f"Target : {target}\nOS     : {os_guess}\nPorts  : {ports}\n\n")
            for r in results:
                f.write(f"Port {r['port']} | {r['service']} | "
                        f"{r['risk']} | {r['banner']}\n")
                for cve in r.get("cves", []):
                    f.write(f"  CVE: {cve['id']} | Score: {cve['score']}\n")
        print(Fore.CYAN + f"\n[*] TXT report saved: {path}")

    elif fmt == "html":
        path = filename + ".html"
        with open(path, "w") as f:
            f.write(generate_html(target, os_guess, ports, results))
        print(Fore.CYAN + f"\n[*] HTML report saved: {path}")

def scan_single(target, ports_arg, output_fmt, skip_os, skip_cve):
    start, end = parse_ports(ports_arg)

    print(Fore.CYAN + "=" * 55)
    print(Fore.CYAN + "       Basic Network Scanner v4.0")
    print(Fore.CYAN + "=" * 55)
    print(f"  Target : {Fore.YELLOW}{target}")
    print(f"  Ports  : {Fore.YELLOW}{ports_arg}")
    print(f"  Output : {Fore.YELLOW}{output_fmt}")
    print(Fore.CYAN + "=" * 55)

    # OS Fingerprinting
    os_guess = "Skipped"
    if not skip_os:
        print(Fore.CYAN + f"\n[*] Detecting OS for {target}...")
        os_guess = get_os(target)
        print(Fore.GREEN + f"  [+] OS Guess: {os_guess}")

    # Port Scanning
    open_ports = scan_ports(target, start, end)

    # Banner + Vuln + CVE
    results = []
    for port in open_ports:
        service, banner = identify_service(target, port)
        risk, vuln_desc = check_vulns(port)

        cves = []
        if not skip_cve and service != "Unknown":
            print(Fore.CYAN + f"\n[*] Looking up CVEs for {service} (port {port})...")
            cves = search_cves(service, port)
            if cves:
                print(Fore.RED + f"  [!] Found {len(cves)} CVE(s)!")
            else:
                print(Fore.GREEN + f"  [+] No CVEs found")

        results.append({
            "port":      port,
            "status":    "OPEN",
            "service":   service,
            "banner":    banner if banner else "No banner",
            "risk":      risk,
            "vuln_desc": vuln_desc,
            "cves":      cves
        })

    # Display results table
    print("\n" + Fore.CYAN + "--- Scan Results ---")
    if results:
        table = []
        for r in results:
            risk_color = (Fore.RED    if r["risk"] == "HIGH"   else
                          Fore.YELLOW if r["risk"] == "MEDIUM" else
                          Fore.BLUE   if r["risk"] == "LOW"    else
                          Fore.WHITE)
            cve_count = (Fore.RED + f"{len(r['cves'])} CVEs found" + Style.RESET_ALL
                         if r["cves"] else Fore.GREEN + "Clean" + Style.RESET_ALL)
            table.append([
                r["port"],
                Fore.GREEN + "OPEN" + Style.RESET_ALL,
                r["service"],
                r["banner"],
                risk_color + r["risk"] + Style.RESET_ALL,
                cve_count
            ])
        print(tabulate(table,
                       headers=["Port", "Status", "Service",
                                 "Banner", "Risk", "CVEs"],
                       tablefmt="grid"))

        # Print CVE details below table
        for r in results:
            if r["cves"]:
                print(Fore.RED + f"\n[!] CVE Details for port {r['port']} ({r['service']}):")
                for cve in r["cves"]:
                    print(Fore.YELLOW + f"  {cve['id']}" +
                          Fore.WHITE  + f" | Score: {cve['score']}")
                    print(Fore.WHITE  + f"  {cve['description']}")
    else:
        print(Fore.YELLOW + "  No open ports found.")

    save_report(target, os_guess, ports_arg, results, output_fmt)

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Scanner v4.0",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target",   help="Single target IP")
    parser.add_argument("-n", "--network",  help="Network sweep (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",    default="1-1024",
                        help="Port range (default: 1-1024)")
    parser.add_argument("-o", "--output",   default="json",
                        choices=["json", "txt", "html", "none"])
    parser.add_argument("--no-os",          action="store_true",
                        help="Skip OS fingerprinting")
    parser.add_argument("--no-cve",         action="store_true",
                        help="Skip CVE lookup (faster scan)")

    args = parser.parse_args()

    if args.network:
        print(Fore.CYAN + "=" * 55)
        print(Fore.CYAN + "       Basic Network Scanner v4.0")
        print(Fore.CYAN + "=" * 55)
        live_hosts = ping_sweep(args.network)
        if live_hosts:
            choice = input(Fore.CYAN + "\n[?] Scan open ports on live hosts? (y/n): ")
            if choice.lower() == "y":
                for host in live_hosts:
                    scan_single(host, args.ports, args.output,
                                args.no_os, args.no_cve)

    elif args.target:
        scan_single(args.target, args.ports, args.output,
                    args.no_os, args.no_cve)

    else:
        print(Fore.RED + "[!] Provide -t (single IP) or -n (network range)")
        print("    python scanner.py -t 127.0.0.1 -p 1-500")
        print("    python scanner.py -n 192.168.1.0/24")

    print(Fore.CYAN + "\n[*] All done!\n")

if __name__ == "__main__":
    main()