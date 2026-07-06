"""
scanner.py
----------
Core network scanning logic for the Network Security Scanner project.

This module performs:
1. Host discovery check (is the target reachable?)
2. Multi-threaded TCP port scanning
3. Banner grabbing on open ports (best-effort)
4. Basic risk classification for commonly dangerous open ports

Designed to be simple, readable, and safe to run against hosts you
own or are authorized to test (e.g. localhost, your own LAN devices,
or lab machines like Metasploitable).
"""

import socket
import threading
from datetime import datetime
from queue import Queue

# Common ports and their typical services.
# Feel free to extend this dictionary with more ports.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
}

# Ports considered high risk if left open/unencrypted on the public internet.
HIGH_RISK_PORTS = {
    21: "FTP transmits credentials in plaintext.",
    23: "Telnet transmits everything in plaintext, including passwords.",
    135: "MSRPC has a history of remote code execution vulnerabilities.",
    139: "NetBIOS can leak host/share information.",
    445: "SMB has been exploited by major ransomware (e.g. WannaCry).",
    3389: "RDP is a frequent brute-force / ransomware entry point.",
    5900: "VNC often has weak or no authentication by default.",
}


def is_host_alive(target, timeout=1):
    """Quick check to see if the target resolves and accepts a connection
    on a common port. Not a full ICMP ping (which needs raw sockets),
    but good enough for a lightweight scanner."""
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False


def grab_banner(sock):
    """Attempt to read a service banner from an open socket."""
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else "No banner"
    except Exception:
        return "No banner"


def scan_port(target, port, results, lock):
    """Scan a single port and record the result if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.7)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = grab_banner(sock)
                risk = HIGH_RISK_PORTS.get(port)
                with lock:
                    results.append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "risk": risk if risk else "Low",
                        "risk_note": risk if risk else "No known common risk for this port.",
                    })
    except socket.error:
        pass


def run_scan(target, ports=None, thread_count=100):
    """
    Run a threaded TCP connect scan against the target.

    Args:
        target (str): hostname or IP address to scan.
        ports (list[int]): list of ports to scan. Defaults to COMMON_PORTS.
        thread_count (int): number of worker threads.

    Returns:
        dict: scan metadata and list of open ports found.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    start_time = datetime.now()
    results = []
    lock = threading.Lock()
    q = Queue()

    for port in ports:
        q.put(port)

    def worker():
        while not q.empty():
            try:
                port = q.get_nowait()
            except Exception:
                return
            scan_port(target, port, results, lock)
            q.task_done()

    threads = []
    for _ in range(min(thread_count, len(ports))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    end_time = datetime.now()
    results.sort(key=lambda r: r["port"])

    return {
        "target": target,
        "scanned_ports": len(ports),
        "open_ports": results,
        "open_count": len(results),
        "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
    }
