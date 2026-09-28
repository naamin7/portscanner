#!/usr/bin/env python3
"""
portscanner.py — A simple multithreaded TCP port scanner
Usage: python portscanner.py <target> [options]
"""

import socket
import argparse
import threading
from datetime import datetime

# Thread-safe list to collect results
results = []
results_lock = threading.Lock()

# Common service names for well-known ports
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        raise SystemExit(1)


def grab_banner(sock: socket.socket) -> str:
    """Try to grab a service banner from an open socket."""
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner[:60] if banner else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float):
    """Attempt a TCP connection to a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))

        if result == 0:
            banner = grab_banner(sock)
            service = COMMON_SERVICES.get(port, "Unknown")
            with results_lock:
                results.append((port, service, banner))
        sock.close()
    except Exception:
        pass


def run_scan(ip: str, ports: list, timeout: float, max_threads: int):
    """Scan a list of ports using a thread pool."""
    semaphore = threading.Semaphore(max_threads)
    threads = []

    def worker(port):
        with semaphore:
            scan_port(ip, port, timeout)

    for port in ports:
        t = threading.Thread(target=worker, args=(port,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()


def parse_ports(port_arg: str) -> list:
    """Parse port argument: single, range, or comma-separated."""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="Simple multithreaded TCP port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python portscanner.py scanme.nmap.org
  python portscanner.py 192.168.1.1 -p 22,80,443
  python portscanner.py 10.0.0.1 -p 1-1024 --threads 200
  python portscanner.py example.com -p 1-65535 --timeout 0.5
        """
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Ports to scan: e.g. 80, 22-443, 22,80,443 (default: 1-1024)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Max concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )
    args = parser.parse_args()

    ip = resolve_target(args.target)
    ports = parse_ports(args.ports)

    print("=" * 55)
    print(f"  Port Scanner")
    print("=" * 55)
    print(f"  Target   : {args.target} ({ip})")
    print(f"  Ports    : {len(ports)} ({args.ports})")
    print(f"  Threads  : {args.threads}")
    print(f"  Timeout  : {args.timeout}s")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)
    print()

    run_scan(ip, ports, args.timeout, args.threads)

    results.sort(key=lambda x: x[0])

    if results:
        print(f"{'PORT':<8} {'SERVICE':<14} {'BANNER'}")
        print("-" * 55)
        for port, service, banner in results:
            print(f"{port:<8} {service:<14} {banner}")
        print()
        print(f"[+] {len(results)} open port(s) found.")
    else:
        print("[-] No open ports found in the given range.")

    print(f"\nScan completed at {datetime.now().strftime('%H:%M:%S')}")


if __name__ == "__main__":
    main()
