# 🔒 Network Security Scanner

A lightweight, multi-threaded **TCP port scanner** with a simple **Flask web dashboard**, built to demonstrate core networking and cybersecurity fundamentals. Enter a target IP/hostname, scan common ports, and get an instant report showing which ports are open, what service is likely running, and whether that port is a known security risk — with the option to export a CSV report.

Built as a portfolio project for cybersecurity placement/internship applications.

---

## ✨ Features

- **Multi-threaded TCP port scanning** — scans common ports (or a custom list) quickly using Python's `threading`.
- **Service identification** — maps well-known ports to their typical services (SSH, HTTP, FTP, RDP, SMB, etc.).
- **Banner grabbing** — attempts to read the service banner returned by an open port for extra recon detail.
- **Risk classification** — flags historically risky ports (e.g. Telnet, SMB, RDP, VNC) and explains *why* they're risky.
- **Simple web UI** — no command-line required; run a scan and view results in the browser.
- **CSV export** — download a report of the scan for documentation or a security write-up.
- **Input validation** — rejects unresolvable hosts and malformed custom port lists.

---

## 🛠️ Tech Stack

- **Python 3** — core scanning logic
- **Flask** — lightweight web framework for the dashboard
- **Sockets & Threading** (standard library) — the actual scan engine
- **HTML/CSS** — simple dark-themed front end (no JS framework needed)

---

## 📂 Project Structure

```
network-security-scanner/
├── app.py              # Flask routes (index, scan, CSV export)
├── scanner.py           # Core scanning engine (threaded TCP connect scan)
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html       # Web UI (form + results table)
├── static/
│   └── style.css        # Styling
└── README.md
```

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/network-security-scanner.git
cd network-security-scanner
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app
```bash
python app.py
```

### 4. Open in browser
Visit **http://127.0.0.1:5000**

---

## 🧪 How to Use

1. Enter a target IP or hostname (e.g. `127.0.0.1` to scan your own machine).
2. Optionally enter a comma-separated list of custom ports (e.g. `22,80,443,8080`).
3. Click **Start Scan**.
4. Review the table of open ports, detected services, banners, and risk levels.
5. Click **Export CSV Report** to download the results.

---

## 🧠 How It Works (Under the Hood)

1. `scanner.py` maintains a dictionary of common ports mapped to typical services.
2. For each port, it opens a raw TCP socket and attempts `connect_ex()` — a non-blocking connection attempt.
3. If the connection succeeds (return code `0`), the port is marked open, and the scanner attempts to read a banner.
4. A thread pool (using a `Queue`) distributes ports across multiple worker threads so the scan completes quickly even for many ports.
5. Results are cross-referenced against a small "high-risk port" dictionary to flag common attack surfaces (e.g. **SMB → EternalBlue/WannaCry**, **Telnet → plaintext credentials**).

---

## ⚠️ Ethical Use Disclaimer

This tool is intended **strictly for educational purposes and authorized security testing**.

- Only scan systems you **own** or have **explicit written permission** to test.
- Good practice targets: `127.0.0.1` (localhost), your own home router, or a deliberately vulnerable lab VM such as **Metasploitable2** or **DVWA**.
- Scanning third-party systems without authorization may violate laws such as the **Computer Fraud and Abuse Act (US)**, the **Computer Misuse Act (UK)**, or equivalent legislation elsewhere.

---

## 📈 Possible Future Improvements

- [ ] Add UDP scanning support
- [ ] Integrate with `nmap` for OS fingerprinting
- [ ] Add authentication so the dashboard isn't open to anyone on the network
- [ ] Store scan history in a database (SQLite) instead of memory
- [ ] Add a packet sniffer module using `scapy` for live traffic analysis
- [ ] Dockerize the app for easy deployment

---

## 🎯 What This Project Demonstrates

For recruiters/interviewers reviewing this repo, this project shows hands-on understanding of:
- TCP/IP networking fundamentals (sockets, ports, connection states)
- Common attack surfaces and why certain services/ports are considered risky
- Concurrent programming (threading, queues, race-condition-safe list writes with locks)
- Building and structuring a small full-stack web application
- Secure coding basics (input validation, no arbitrary code execution)

---

## 👤 Author

Add your name, LinkedIn, and GitHub profile link here.

---

## 📄 License

This project is released under the MIT License — free to use and modify for learning purposes.
