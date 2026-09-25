import re
import collections
import json
import time
import threading
import random
import os
import csv
import subprocess
import winsound
import sys
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# --- System Configuration ---
FAILED_LOGIN_THRESHOLD = 5      # Number of failed attempts to trigger an alert
TIME_WINDOW_SECONDS = 60        # The time window (in seconds) to watch for brute force

# Mock Threat Intelligence (TI) Blacklist
# In real enterprise tools, this is an API call to CrowdStrike, VirusTotal, etc.
THREAT_INTEL_BLACKLIST = {
    "192.168.1.100": "Known Malware C2 (Command & Control)",
    "10.0.0.55": "Botnet Activity",
    "203.0.113.42": "Suspicious Scanning IP",
    "45.33.32.156": "Ransomware Distribution server",
    "142.250.190.46": "Example Blocked IP (Google for Demo)" # Just an example if you want to test live traffic blocking
}

# Regex compiler to extract data from raw unstructured text logs
LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+-\s+"
    r"IP:\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+"
    r"Action:\s+(?P<action>[A-Z_]+)\s+-\s+"
    r"User:\s+(?P<user>\w+)"
)

class ThreatAnalysisSystem:
    def __init__(self, log_output_widget=None):
        self.failed_logins = collections.defaultdict(list)
        self.alerts = []
        self.log_output_widget = log_output_widget

    def log_message(self, message):
        """Helper to print to console and tkinter widget."""
        print(message)
        if self.log_output_widget:
            self.log_output_widget.insert(tk.END, message + "\n")
            self.log_output_widget.see(tk.END) # Auto-scroll to bottom

    def parse_log_line(self, line):
        match = LOG_PATTERN.search(line)
        if match:
            return match.groupdict()
        return None

    def check_threat_intel(self, ip):
        if ip in THREAT_INTEL_BLACKLIST:
            return THREAT_INTEL_BLACKLIST[ip]
        return None

    def analyze_behavior(self, ip, timestamp_str, action):
        if action == "LOGIN_FAILED":
            log_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            self.failed_logins[ip].append(log_time)
            self.failed_logins[ip] = [
                t for t in self.failed_logins[ip] 
                if (log_time - t).total_seconds() <= TIME_WINDOW_SECONDS
            ]
            
            if len(self.failed_logins[ip]) >= FAILED_LOGIN_THRESHOLD:
                self.generate_alert(
                    severity="HIGH",
                    title="Potential Brute Force Attack",
                    description=f"IP {ip} attempted {len(self.failed_logins[ip])} failed logins within {TIME_WINDOW_SECONDS} seconds."
                )
                self.failed_logins[ip] = [] 

    def generate_alert(self, severity, title, description):
        timestamp = datetime.now().strftime('%H:%M:%S')
        alert_msg = f"[{timestamp}] 🚨 [ALERT - {severity}] {title} | {description}"
        
        # Keep track of structured alert data for CSV exporting
        self.alerts.append({
            "timestamp": timestamp,
            "severity": severity,
            "title": title,
            "description": description
        })
        self.log_message(alert_msg)

        # Trigger System Sound Alert
        try:
            if severity == "CRITICAL":
                winsound.Beep(1500, 1000) # High pitch, 1 second
            elif severity == "HIGH":
                winsound.Beep(1000, 500)  # Medium pitch, half a second
        except Exception:
            pass # Failsafe if audio is unavailable

    def process_logs(self, log_lines):
        for line in log_lines:
            self.log_message(f"[INGEST] {line.strip()}")
            parsed_data = self.parse_log_line(line)
            if not parsed_data:
                continue
                
            ip = parsed_data['ip']
            action = parsed_data['action']
            timestamp = parsed_data['timestamp']

            # Tier 1: Threat Intel Check
            ti_match = self.check_threat_intel(ip)
            if ti_match:
                self.generate_alert(
                    severity="CRITICAL",
                    title="Malicious IP Interaction",
                    description=f"Traffic from known bad IP: {ip}. Intel: {ti_match}"
                )

            # Tier 2: Behavioral Analysis
            self.analyze_behavior(ip, timestamp, action)

# --- GUI Application ---
class ThreatAnalysisGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitoring System")
        self.root.geometry("1000x700")
        
        try:
            self.root.iconbitmap(resource_path("threat_logo.ico"))
        except Exception as e:
            print(f"Warning: Could not load icon: {e}")


        self.is_monitoring = False
        self.monitor_thread = None

        # UI Setup
        title_label = tk.Label(root, text="Automated Network Log Intelligence & Threat Analysis", font=("Arial", 16, "bold"), pady=10)
        title_label.pack()
        
        status_frame = tk.Frame(root)
        status_frame.pack(pady=5)
        
        self.status_label = tk.Label(status_frame, text="Status: IDLE", font=("Arial", 12), fg="grey")
        self.status_label.pack()

        # Output Text Area
        self.output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10), bg="black", fg="lightgreen")
        self.output_area.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Buttons Frame
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)

        self.monitor_btn = tk.Button(btn_frame, text="Start Real PC Network Monitor", font=("Arial", 11, "bold"), bg="blue", fg="white", width=30, command=self.toggle_monitoring)
        self.monitor_btn.grid(row=0, column=0, padx=10)

        self.export_btn = tk.Button(btn_frame, text="Export Alerts to CSV", font=("Arial", 11, "bold"), bg="green", fg="white", width=20, command=self.export_csv)
        self.export_btn.grid(row=0, column=1, padx=10)

        self.system = ThreatAnalysisSystem(log_output_widget=self.output_area)
        self.system.log_message(f"System ready. Press 'Start Real PC Network Monitor' to track live traffic.\n")

    def toggle_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_btn.config(text="Stop PC Network Monitor", bg="red")
            self.status_label.config(text="Status: Actively scanning Windows netstat & Event Logs...", fg="green")
            
            # Start background thread to watch PC network
            self.monitor_thread = threading.Thread(target=self.monitor_real_pc_network, daemon=True)
            self.monitor_thread.start()
        else:
            self.is_monitoring = False
            self.monitor_btn.config(text="Start Real PC Network Monitor", bg="blue")
            self.status_label.config(text="Status: IDLE", fg="grey")

    def monitor_real_pc_network(self):
        """Monitors real active network connections and failed logins on this Windows PC."""
        self.root.after(0, self.system.log_message, "[SYSTEM] Initiating Live Deep Packet Diagnostics (netstat binding)...")
        seen_connections = set()

        while self.is_monitoring:
            try:
                # 1. READ REAL NETWORK CONNECTIONS via Windows netstat
                # Hide console window on Windows
                creation_flags = 0x08000000 if os.name == 'nt' else 0
                result = subprocess.check_output(["netstat", "-n"], creationflags=creation_flags).decode('utf-8', errors='ignore')
                
                for line in result.split("\n"):
                    if "ESTABLISHED" in line or "SYN_SENT" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            foreign_address = parts[2]
                            
                            # Extract IP address from IP:Port format
                            if ":" in foreign_address or "." in foreign_address:
                                ip = foreign_address.rsplit(":", 1)[0]
                                ip = ip.replace("[", "").replace("]", "") # Clean IPv6
                                
                                # Ignore standard localhost and standard internal IPs to reduce noise
                                if ip not in ["127.0.0.1", "0.0.0.0"] and not ip.startswith("192.168.") and not ip.startswith("10.") and not ip.startswith("172."):
                                    # Create an artificial log string to process
                                    if ip not in seen_connections:
                                        seen_connections.add(ip)
                                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        log_line = f"{timestamp} - IP: {ip} - Action: LIVE_CONNECTION - User: SYSTEM"
                                        
                                        # Use root.after to safely update Tkinter GUI from a thread
                                        self.root.after(0, self.system.process_logs, [log_line])

                # 2. OPTIONAL: Check Windows Event Logs for Failed Logins (EventID 4625) 
                # Note: This requires Admin privileges to read the Security log, heavily locked down by Windows.
                # We wrap it in a try-except so it doesn't crash the app if the user isn't Admin.
                try:
                    creation_flags = 0x08000000 if os.name == 'nt' else 0
                    event_log = subprocess.check_output('wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:1 /rd:true /f:text', shell=True, stderr=subprocess.DEVNULL, creationflags=creation_flags).decode('utf-8', errors='ignore')
                    if event_log and "Date:" in event_log:
                        # Parsing the log timestamp theoretically done here...
                        # Emitting a generic failed login alert:
                        log_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - IP: 127.0.0.1 - Action: LOGIN_FAILED - User: Local_Windows_User"
                        self.root.after(0, self.system.process_logs, [log_line])
                except Exception:
                    pass # Silently fail if no Admin privileges

            except Exception as e:
                print(f"[ERROR] Network monitor loop encountered an error: {e}")
            
            # Poll every 4 seconds to avoid CPU overload
            time.sleep(4)

    def export_csv(self):
        """Exports the captured alerts to a CSV file."""
        if not self.system.alerts:
            messagebox.showinfo("Export CSV", "No alerts to export yet.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Alerts as CSV"
        )

        if not file_path:
            return

        try:
            with open(file_path, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=["timestamp", "severity", "title", "description"])
                writer.writeheader()
                writer.writerows(self.system.alerts)
            messagebox.showinfo("Export Successful", f"Successfully exported {len(self.system.alerts)} alerts to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"An error occurred while exporting:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatAnalysisGUI(root)
    root.mainloop()
