# Threat Analysis & Network Log Intelligence System

An automated Python-based utility designed to audit active network connections and system security events on Windows systems. By combining static threat intelligence feeds with behavioral analysis, it alerts administrators to potential brute-force attempts and malicious outbound activity.

---

## 🔍 Overview

The application binds to Windows network telemetry and event logging utilities to build a real-time monitor. It features a graphical console to visualize traffic ingestion and system alerts.

### How it works
1. **Network Binding (`netstat`):** Automatically scans active external TCP/IP connections.
2. **Threat Intelligence Check:** Compares remote IP addresses against a Threat Intelligence database containing known malicious command & control (C2) hosts, ransomware distributors, and botnet IPs.
3. **Event Log Auditing (`wevtutil`):** Queries Windows Security Event Logs for Event ID `4625` (failed logon attempts) in real-time.
4. **Behavioral Analysis:** Triggers brute-force alerts if multiple login failures occur within a defined time frame from the same origin IP.

---

## ✨ Features

- **Real-Time Log Ingestion:** Live scrolling terminal feed showing diagnostic events and connection activities.
- **Audible Warning System:** Utilizes `winsound` to trigger distinct beep frequencies for warning severities (High vs. Critical).
- **Export capabilities:** Save all security events and logged alerts to structured CSV files for post-incident analysis.
- **Admin Event-Log Parser:** Safely attempts admin event logging without crashing if run as a standard user.
- **Clean Tkinter GUI:** Implements a retro, dark terminal-style console view.

---

## 🛠️ Requirements & Dependencies

- **Operating System:** Windows (required for `winsound` and Windows Security event logs query).
- **Python Version:** Python 3.x
- **Standard Libraries:** `tkinter`, `threading`, `subprocess`, `re`, `json`, `csv`, `winsound`.
- **System Permissions:** Running the script as **Administrator** is highly recommended to authorize Event Log queries (`wevtutil`).

---

## 🚀 How to Run

1. Open PowerShell or Command Prompt.
2. Navigate to the project directory:
   ```powershell
   cd "Projects/Threat Analysis"
   ```
3. Run the application:
   ```powershell
   python threat_analysis.py
   ```
4. Click the **Start Real PC Network Monitor** button to initiate scans.
5. Use **Export Alerts to CSV** to save logs.

---

## 📂 Project Structure

- `threat_analysis.py`: Main application code, containing log-parsing algorithms, network monitoring loop, and GUI.
- `threat_logo.ico`: Application icon asset.
- `setup.iss`: Inno Setup configuration script to compile the application into a standalone Windows Executable (`.exe`) installer.
