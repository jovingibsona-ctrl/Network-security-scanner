"""
app.py
------
Flask web front-end for the Network Security Scanner.

Run with:
    python app.py

Then open http://127.0.0.1:5000 in your browser.

IMPORTANT / ETHICS NOTICE:
Only scan hosts you own or have explicit written permission to test
(e.g. localhost, your own router, or a lab VM like Metasploitable).
Scanning systems without authorization is illegal in most countries.
"""

import csv
import io
import ipaddress
import socket

from flask import Flask, render_template, request, Response, flash, redirect, url_for

from scanner import run_scan, COMMON_PORTS

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-me"  # only needed for flash messages

# In-memory storage of the last scan result (simple, no database needed)
last_scan_result = None


def is_valid_target(target):
    """Basic validation: must be a resolvable hostname or valid IP."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", result=last_scan_result)


@app.route("/scan", methods=["POST"])
def scan():
    global last_scan_result
    target = request.form.get("target", "").strip()
    custom_ports = request.form.get("ports", "").strip()

    if not target:
        flash("Please enter a target IP or hostname.", "error")
        return redirect(url_for("index"))

    if not is_valid_target(target):
        flash(f"'{target}' could not be resolved. Check the address and try again.", "error")
        return redirect(url_for("index"))

    ports = None
    if custom_ports:
        try:
            ports = [int(p.strip()) for p in custom_ports.split(",") if p.strip()]
        except ValueError:
            flash("Custom ports must be a comma-separated list of numbers, e.g. 22,80,443", "error")
            return redirect(url_for("index"))

    last_scan_result = run_scan(target, ports=ports)
    return render_template("index.html", result=last_scan_result)


@app.route("/export")
def export_csv():
    """Export the last scan result as a downloadable CSV report."""
    global last_scan_result
    if not last_scan_result:
        flash("No scan results to export yet.", "error")
        return redirect(url_for("index"))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Target", last_scan_result["target"]])
    writer.writerow(["Scan Time", last_scan_result["start_time"]])
    writer.writerow(["Duration (s)", last_scan_result["duration_seconds"]])
    writer.writerow([])
    writer.writerow(["Port", "Service", "Banner", "Risk Level", "Risk Note"])
    for r in last_scan_result["open_ports"]:
        writer.writerow([r["port"], r["service"], r["banner"], r["risk"], r["risk_note"]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_report.csv"},
    )


if __name__ == "__main__":
    app.run(debug=True)
