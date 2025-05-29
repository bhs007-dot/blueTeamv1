import subprocess
import re
import psutil

def run_advanced_monitoring():
    print("\n[+] Advanced Compromise Detection and Analysis Tool")
    target_ip = input("Enter the IP or host to monitor: ").strip()
    duration = input("Enter monitoring duration in seconds (e.g., 60), or 'infinite' for continuous: ").strip()
    if not duration:
        duration = "60"
    suspicious_dest = input("Enter suspicious destination IP or pattern to flag (optional): ").strip()
    monitor_ports = input("Enter ports to monitor (e.g., 80,443,3389), or leave blank for default: ").strip()
    
    # Build capture and display filters
    capture_filter = f"host {target_ip}" if target_ip else ""
    display_filter = (
        '(http.request.method == "GET" && (http.request.uri matches ".exe" || http.request.uri matches ".bat" || '
        'http.request.uri matches ".ps1" || http.request.uri matches ".sh" || http.request.uri matches ".rat")) || '
        'ftp || (tcp.port == 23 || tcp.port == 21 || tcp.port == 69) || (tcp.port == 3389) || (tcp.port == 22) '  # Includes RDP (3389) and SSH (22)
    )
    if monitor_ports:
        display_filter += f' || tcp.port in {{{monitor_ports}}}'
    if suspicious_dest:
        display_filter += f' || ip.dst == "{suspicious_dest}" || ip.src == "{suspicious_dest}"'
    
    # tshark command to capture detailed fields
    tshark_cmd = [
        "tshark", "-i", "any", "-f", capture_filter, "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "http.request.uri", "-e", "ftp.request.command", "-e", "ssh.protocol", "-e", "rdp",
        "-e", "frame.protocols"
    ]
    if duration.lower() != "infinite":
        tshark_cmd = ["timeout", duration] + tshark_cmd
    
    print(f"[*] Monitoring started for {target_ip}. Press Ctrl+C to stop.")
    session_active = False
    last_hacker_ip = ""
    try:
        proc = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            fields = line.split('\t')
            timestamp = fields[0] if len(fields) > 0 else "Unknown"
            src_ip = fields[1] if len(fields) > 1 else "Unknown"
            dst_ip = fields[2] if len(fields) > 2 else "Unknown"
            src_port = fields[3] if len(fields) > 3 else "Unknown"
            dst_port = fields[4] if len(fields) > 4 else "Unknown"
            uri = fields[6] if len(fields) > 6 else "N/A"
            ftp_cmd = fields[7] if len(fields) > 7 else "N/A"
            ssh_proto = fields[8] if len(fields) > 8 else "N/A"
            rdp_info = fields[9] if len(fields) > 9 else "N/A"
            protocol_info = fields[10] if len(fields) > 10 else "Unknown"
            
            compromised = False
            who = src_ip  # Who: Hacker IP
            when = timestamp  # When: Timestamp
            what_did = "No action detected"
            how_did = "Unknown method"
            where_kept = "Unknown location"
            exploited_service = "N/A"
            exploited_port = "N/A"
            
            # Detection logic for compromise indicators
            if re.search(r'\.exe|\.bat|\.ps1|\.sh|\.rat', uri, re.IGNORECASE):
                compromised = True
                what_did = f"Downloaded and possibly executed a suspicious file: {uri}"
                how_did = "Via HTTP GET request"
                where_kept = "Likely in Downloads, %TEMP%, /tmp, or user profile directory"
                exploited_service = "HTTP"
                exploited_port = dst_port if "http" in protocol_info.lower() else "Unknown"
                session_active = True
                last_hacker_ip = src_ip
            elif ftp_cmd:
                compromised = True
                what_did = f"Transferred file or executed command via FTP: {ftp_cmd}"
                how_did = "Via FTP"
                where_kept = "FTP root or user home directory"
                exploited_service = "FTP"
                exploited_port = "21"
                session_active = True
                last_hacker_ip = src_ip
            elif "3389" in [src_port, dst_port] or "rdp" in rdp_info.lower():
                compromised = True
                what_did = "Potential remote desktop access or session hijack"
                how_did = "Via RDP protocol"
                where_kept = "RDP session files or registry (check %SYSTEMROOT%\\System32\\config)"
                exploited_service = "RDP"
                exploited_port = "3389"
                session_active = True
                last_hacker_ip = src_ip
            elif "22" in [src_port, dst_port] or "ssh" in ssh_proto.lower():
                compromised = True
                what_did = "Possible SSH login or command execution"
                how_did = "Via SSH"
                where_kept = "SSH keys or .ssh directory (check /home/user/.ssh or %USERPROFILE%\\.ssh)"
                exploited_service = "SSH"
                exploited_port = "22"
                session_active = True
                last_hacker_ip = src_ip
            elif re.search(r'port 23|port 21|port 69', line):  # Telnet, FTP, TFTP
                compromised = True
                what_did = "Remote command execution via insecure protocol"
                how_did = "Via Telnet, FTP, or TFTP"
                where_kept = "Shell history or temp folders"
                exploited_service = "Telnet/FTP/TFTP"
                exploited_port = "23/21/69"
                session_active = True
                last_hacker_ip = src_ip
            elif suspicious_dest and (suspicious_dest in src_ip or suspicious_dest in dst_ip):
                compromised = True
                what_did = "Connected to suspicious destination"
                how_did = "Direct IP communication"
                where_kept = "Unknown"
                exploited_service = "Custom"
                exploited_port = dst_port or src_port
                session_active = True
                last_hacker_ip = src_ip
            elif re.search(r'cmd=|exec=|system\(', uri, re.IGNORECASE):
                compromised = True
                what_did = "Potential command injection detected"
                how_did = "Via URI parameter injection"
                where_kept = "Executed in memory or logged in system files"
                exploited_service = "HTTP/Web"
                exploited_port = dst_port
                session_active = True
                last_hacker_ip = src_ip
            
            # Enhanced analysis: Check for suspicious processes if compromised
            if compromised:
                try:
                    processes = psutil.process_iter(['pid', 'name', 'cmdline'])
                    suspicious_procs = [p.info for p in processes if 'cmd' in p.info['cmdline'] or 'bash' in p.info['name'] or 'powershell' in p.info['name']]
                    if suspicious_procs:
                        proc_details = ", ".join([f"PID: {p['pid']}, Name: {p['name']}" for p in suspicious_procs[:5]])
                        what_did += f"; Suspicious processes running: {proc_details}"
                        where_kept += "; Check active processes with task manager or ps command"
                except Exception as e:
                    print(f"[!] Error checking processes: {e}. Continuing...")
            
            if compromised:
                print("\n=== COMPROMISE DETECTED ===")
                print(f"Compromised: YES")
                print(f"Who (Hacker IP): {who}")
                print(f"When: {when}")
                print(f"What he did: {what_did}")
                print(f"How he did it: {how_did}")
                print(f"Where kept: {where_kept}")
                print(f"Exploited Service: {exploited_service}")
                print(f"Exploited Port: {exploited_port}")
                print(f"Session: ACTIVE")
                print("===========================")
        proc.stdout.close()
        proc.wait()
    except KeyboardInterrupt:
        print("\n[!] Monitoring interrupted by user.")
    except FileNotFoundError:
        print("[!] tshark not found. Please install Wireshark and ensure tshark is in your PATH.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
    
    if session_active:
        print(f"\nSession ended. Last detected hacker IP: {last_hacker_ip}")
    else:
        print("No compromise detected during monitoring.")

def main():
    while True:
        print("\nAdvanced Monitoring Tool Menu:")
        print("1. Start Monitoring")
        print("2. Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            run_advanced_monitoring()
        elif choice == "2":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

