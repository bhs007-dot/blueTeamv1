# Advanced Monitoring Tool

## Description
This Python script is a specialized network traffic monitoring tool designed for cybersecurity professionals, such as penetration testers with OSCP or CEH certifications. It monitors network traffic for specified IP addresses or hosts, detects potential compromises based on common indicators (e.g., suspicious file downloads, protocol usage), and provides detailed analysis if a compromise is detected. The analysis includes key details like who (hacker IP), when (timestamp), where (inferred locations), what (actions taken), and how (methods used, including exploited ports and services).

This tool uses `tshark` (from Wireshark) for real-time packet capture and `psutil` for basic process analysis. It is intended for authorized use in penetration testing or security assessments only.

## Features
- **Real-time Monitoring**: Captures and analyzes network traffic in real-time.
- **Compromise Detection**: Identifies indicators of compromise, such as file downloads with suspicious extensions (.exe, .bat, etc.), FTP transfers, RDP/SSH sessions, and custom patterns.
- **Detailed Reporting**: If a compromise is detected, it reports:
  - Who: Source IP of the potential attacker.
  - When: Timestamp of the event.
  - What: Actions performed (e.g., file download or command execution).
  - How: Method used (e.g., exploited service and port).
  - Where: Inferred storage or system locations (e.g., temp directories).
- **User-Friendly Interface**: Simple menu-driven system for starting monitoring sessions with customizable inputs (e.g., duration, ports).
- **Error Handling**: Includes checks for missing dependencies and user interrupts.

## Installation
1. **Clone or Download the Script**: Save the `advanced_monitoring_tool.py` file to your local machine.
2. **Install Python Dependencies**:
   - Ensure you have Python 3 installed.
   - Install required libraries using pip:
     ```
     pip install psutil
     ```
3. **Install Wireshark and tshark**:
   - Download and install Wireshark from the official website (https://www.wireshark.org).
   - Ensure `tshark` is installed and added to your system's PATH. On Linux/macOS, you can verify with `tshark --version`. If not found, install via your package manager (e.g., `sudo apt install tshark` on Ubuntu).
4. **Run the Script**: Execute with Python:
5. python advanced_monitoring_tool.py

## Usage
1. Run the script, and it will display a simple menu.
2. Select option `1` to start monitoring.
3. Enter the required inputs:
- **IP or Host**: The target to monitor (e.g., `192.168.1.100`).
- **Duration**: Time in seconds (e.g., `60`) or type `infinite` for continuous monitoring.
- **Suspicious Destination**: Optional IP or pattern to flag (e.g., `8.8.8.8`).
- **Ports to Monitor**: Optional comma-separated list (e.g., `80,443,3389`).
4. The script will monitor traffic and alert if a compromise is detected, providing a detailed breakdown.
5. Press `Ctrl+C` to stop monitoring manually.

### Example Workflow
- Start the script: `python advanced_monitoring_tool.py`
- Choose option `1`.
- Input: Target IP = `192.168.1.1`, Duration = `300`, Suspicious Destination = `leave blank`, Ports = `22,3389`.
- If suspicious activity is detected, it will output details like:
  
=== COMPROMISE DETECTED === Compromised: YES Who (Hacker IP): 192.168.1.100 When: May 29, 2025 14:30:00 What he did: Possible SSH login or command execution; Suspicious processes running: PID: 1234, Name: bash How he did it: Via SSH Where kept: SSH keys or .ssh directory (check /home/user/.ssh or %USERPROFILE%.ssh) Exploited Service: SSH Exploited Port: 22 Session: ACTIVE

## Dependencies
- **Python 3**: Required to run the script.
- **psutil**: For process monitoring (installed via pip).
- **tshark**: For network packet capture (part of Wireshark).
- **Other Libraries**: The script uses standard Python libraries like `subprocess` and `re`, which are included with Python.

## Author
- Created by: IT Solutions 007 (based on collaboration with PentestGPT).
- Contact: Follow on Instagram @itsolutions007 for updates or inquiries.

## Disclaimer
This tool is intended for educational and authorized penetration testing purposes only. Unauthorized use against systems you do not own or have permission to test is illegal and unethical. Always obtain explicit consent before use. The author and contributors are not responsible for any misuse or damage caused by this script.

## Contributing
If you'd like to improve this script, feel free to fork the repository, make changes, and submit a pull request. For issues or suggestions, open an issue on the repository or contact the author.

