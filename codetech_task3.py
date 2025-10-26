"""
pentest_toolkit.py
Single-file Python "Penetration Testing Toolkit" (educational & safe)

What it contains (all in one file):
- scan_ports(target, ports, timeout)        : simple TCP port scanner
- grab_banner(target, port, timeout)        : banner grabber (HTTP HEAD by default)
- brute_force_simulator(username)           : safe simulated brute-force (no real attacks)
- dns_info(target)                          : basic DNS / host information (resolve, aliases, reverse)
- simple_cli()                              : interactive menu

IMPORTANT:
- This toolkit is for educational, defensive, and ethical use only.
- Do NOT run against systems you do not own or do not have explicit permission to test.
- No destructive or automated attack code is included.
"""

import socket
import sys
import time
import threading
from queue import Queue

# -------------------------
# Port Scanner (multi-threaded, safe)
# -------------------------
def _worker_scan(q, target_ip, timeout, results):
    while not q.empty():
        try:
            port = q.get_nowait()
        except Exception:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            code = s.connect_ex((target_ip, port))
            if code == 0:
                results.append(port)
        except Exception:
            pass
        finally:
            s.close()
            q.task_done()

def scan_ports(target, ports=None, timeout=0.5, threads=50):
    """
    Scans a set/list of ports on the target hostname/IP.
    - target: hostname or IPv4 address (string)
    - ports: list of integers (defaults to common ports)
    - timeout: per-connection timeout in seconds
    - threads: concurrency
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080]

    print(f"\n[+] Resolving target '{target}'...")
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Hostname could not be resolved.")
        return
    except Exception as e:
        print(f"[-] Error resolving host: {e}")
        return

    print(f"[+] Starting port scan on {target} ({target_ip})")
    q = Queue()
    for p in ports:
        q.put(p)

    results = []
    worker_count = min(threads, len(ports))
    thread_list = []
    for _ in range(worker_count):
        t = threading.Thread(target=_worker_scan, args=(q, target_ip, timeout, results))
        t.daemon = True
        t.start()
        thread_list.append(t)

    q.join()  # wait for queue to be processed

    if results:
        results_sorted = sorted(results)
        print(f"[✔] Open ports on {target} ({target_ip}): {results_sorted}")
    else:
        print(f"[✖] No open ports (from the scanned list) on {target} ({target_ip}).")

# -------------------------
# Banner Grabber
# -------------------------
def grab_banner(target, port=80, timeout=2):
    """
    Connects to target:port and attempts a simple banner grab.
    Default is HTTP HEAD request if port==80 or 8080.
    """
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Hostname could not be resolved.")
        return
    except Exception as e:
        print(f"[-] Error resolving host: {e}")
        return

    print(f"\n[+] Connecting to {target} ({target_ip}) on port {port} for banner grabbing...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target_ip, port))
        # If HTTP-ish port, send HEAD. Else, send a short byte sequence and read.
        if port in (80, 8080, 8000, 443):  # 443 won't respond to plaintext; be cautious
            try:
                head = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: pentest-toolkit\r\nConnection: close\r\n\r\n"
                s.send(head.encode())
            except Exception:
                pass
        else:
            try:
                # send small probe that won't be destructive
                s.send(b"\r\n")
            except Exception:
                pass

        data = s.recv(2048)
        if data:
            try:
                text = data.decode('utf-8', errors='ignore')
            except Exception:
                text = repr(data)
            print("[+] Banner / response:")
            print("-" * 60)
            print(text.strip())
            print("-" * 60)
        else:
            print("[i] No banner returned (service may not respond to this probe).")
    except Exception as e:
        print(f"[-] Could not connect or read from {target}:{port} — {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass

# -------------------------
# Brute Force Simulator (SAFE)
# -------------------------
def brute_force_simulator(username=None):
    """
    Simulates a brute-force password guessing process.
    This function does NOT attempt to authenticate against any real service.
    It demonstrates the logic and timing of trying password candidates.
    """
    if username is None:
        username = input("Enter username (for simulation): ").strip() or "demo_user"

    print(f"\n[+] Starting BRUTE-FORCE SIMULATION for user: {username}")
    # Example small password list (in real pentesting you'd use wordlists — DON'T do that without permission)
    candidates = [
        "1234", "password", "admin", "letmein", "welcome", "qwerty",
        "user@123", "Password1", "changeme"
    ]

    # For demonstration, define a "correct" password (only local simulation)
    correct_password = "user@123"

    found = False
    for idx, pwd in enumerate(candidates, 1):
        print(f"  Try {idx}/{len(candidates)} -> {pwd}")
        time.sleep(0.6)  # simulate delay
        if pwd == correct_password:
            print(f"[✔] (SIM) Password found for {username}: {pwd}")
            found = True
            break

    if not found:
        print("[✖] (SIM) Password not found in provided candidate list.")

    print("[i] This was a simulation. Do not run brute-force attacks against systems without permission.")

# -------------------------
# DNS / Host Info
# -------------------------
def dns_info(target):
    """
    Provides basic host information:
     - Resolves hostname -> IP(s)
     - Reverse lookup (IP -> hostname) if possible
     - Shows aliases
    No external DNS libraries are required.
    """
    print(f"\n[+] Gathering DNS/host info for '{target}'...")
    try:
        # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        host, aliases, ips = socket.gethostbyname_ex(target)
        print(f"Canonical name: {host}")
        if aliases:
            print(f"Aliases: {aliases}")
        print(f"IP addresses: {ips}")

        # reverse lookup on first IP
        if ips:
            try:
                rev = socket.gethostbyaddr(ips[0])
                print(f"Reverse lookup of {ips[0]}: {rev[0]}")
            except Exception as e:
                print(f"[i] Reverse lookup not available: {e}")
    except socket.gaierror:
        print("[-] Hostname could not be resolved.")
    except Exception as e:
        print(f"[-] Error when gathering DNS info: {e}")

# -------------------------
# Helper: validate port range string -> list
# -------------------------
def parse_ports(port_input):
    """
    Accepts inputs like:
     - "80" -> [80]
     - "20-25" -> [20,21,22,23,24,25]
     - "22,80,443" -> [22,80,443]
     - combination like "20-25,80,443"
    """
    ports = set()
    parts = [p.strip() for p in port_input.split(',') if p.strip()]
    for part in parts:
        if '-' in part:
            try:
                a, b = part.split('-', 1)
                a, b = int(a.strip()), int(b.strip())
                if a > b:
                    a, b = b, a
                for i in range(max(1, a), min(65535, b) + 1):
                    ports.add(i)
            except Exception:
                continue
        else:
            try:
                num = int(part)
                if 1 <= num <= 65535:
                    ports.add(num)
            except Exception:
                continue
    return sorted(ports)

# -------------------------
# CLI / Main Menu
# -------------------------
def simple_cli():
    banner = r"""
    ============================================
           PENETRATION TESTING TOOLKIT
           (educational & safe demonstration)
    ============================================
    """
    print(banner)
    while True:
        print("\nSelect an option:")
        print("  1) Port Scanner")
        print("  2) Banner Grabber")
        print("  3) Brute Force Simulator (SAFE)")
        print("  4) DNS / Host Info")
        print("  5) Exit")
        ch = input("Enter choice (1-5): ").strip()
        if ch == '1':
            target = input("Enter target hostname or IP: ").strip()
            if not target:
                print("[-] No target provided.")
                continue
            port_input = input("Enter ports (e.g. 80,443 or 20-25 or leave blank for defaults): ").strip()
            if port_input:
                ports = parse_ports(port_input)
                if not ports:
                    print("[-] No valid ports parsed. Using defaults.")
                    ports = None
            else:
                ports = None
            try:
                timeout = float(input("Connection timeout in seconds (default 0.5): ").strip() or 0.5)
            except Exception:
                timeout = 0.5
            try:
                threads = int(input("Concurrent threads (default 50): ").strip() or 50)
            except Exception:
                threads = 50

            scan_ports(target, ports=ports, timeout=timeout, threads=threads)

        elif ch == '2':
            target = input("Enter target hostname or IP: ").strip()
            if not target:
                print("[-] No target provided.")
                continue
            try:
                port = int(input("Port (default 80): ").strip() or 80)
            except Exception:
                port = 80
            try:
                timeout = float(input("Timeout seconds (default 2): ").strip() or 2)
            except Exception:
                timeout = 2
            grab_banner(target, port=port, timeout=timeout)

        elif ch == '3':
            uname = input("Enter username for simulation (optional): ").strip() or None
            brute_force_simulator(username=uname)

        elif ch == '4':
            target = input("Enter hostname or IP for DNS info: ").strip()
            if not target:
                print("[-] No target provided.")
                continue
            dns_info(target)

        elif ch == '5':
            print("Exiting. Stay ethical and only test with permission.")
            break
        else:
            print("Invalid choice. Try again.")

# -------------------------
# If run directly
# -------------------------
if __name__ == "__main__":
    try:
        simple_cli()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(0)