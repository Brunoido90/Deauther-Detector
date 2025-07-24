import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import queue
import random
from datetime import datetime, timedelta
import subprocess # For executing shell commands

# --- IMPORTANT REQUIREMENTS FOR REAL FUNCTIONALITY ---
# 1. Install Scapy: pip install scapy
# 2. Put WLAN adapter into monitor mode (OS-dependent!)
#    - Linux: Installation of 'aircrack-ng' (includes airmon-ng) is HIGHLY RECOMMENDED: sudo apt install aircrack-ng
#      The script attempts to use airmon-ng to automatically activate monitor mode.
#    - Windows: Install Npcap with the "Support raw 802.11 traffic (and monitor mode) for wireless adapters" option enabled.
#               Not all WLAN adapters support monitor mode on Windows.
#               Automatic switching is very difficult on Windows and is not directly supported here.
#               You may need to manually put the adapter into monitor mode, if possible on Windows.
# 3. Run script with administrator/root privileges (e.g., sudo python YourScriptName.py on Linux/macOS,
#    as Administrator on Windows).
# -----------------------------------------------------------

try:
    from scapy.all import Dot11, Dot11Deauth, sniff, RadioTap, get_if_list # get_if_list for interface scanning
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not found. The detector will run in simulation mode.")
    print("Please install Scapy (pip install scapy) for real functionality.")

# --- Honeypot Simulation & Advanced Functions ---
class HoneypotSimulator:
    def __init__(self, data_queue):
        self.data_queue = data_queue
        self.honeypot_active = False
        self.attacker_macs = set()  # Stored attacker MACs

    def simulate_attacker_response(self, src_mac):
        """Simulates an automatic response to attackers (e.g., countermeasures)."""
        if src_mac not in self.attacker_macs:
            self.attacker_macs.add(src_mac)
            self.data_queue.put({
                "type": "honeypot",
                "message": f"⚠️ HONEYPOT TRIGGERED! Attacker {src_mac} isolated.",
                "severity": "critical"
            })
            return f"Countermeasure: Fake AP started for {src_mac}"
        return None

# --- GUI with Honeypot Integration ---
class DeauthDetectorGUI:
    def __init__(self, master):
        self.master = master
        master.title("Deauth Detector + Honeypot")
        master.geometry("1000x700")

        self.data_queue = queue.Queue()
        self.detection_active = False
        self.honeypot = HoneypotSimulator(self.data_queue)
        self.running = True # Flag for safe thread termination
        self.sniff_thread = None # Reference to the sniffing thread
        self.deauth_timestamps = [] # Stores timestamps of deauth packets for window logic
        self.original_interface = None # Stores the name of the original interface
        self.monitor_interface = None # Stores the name of the monitor interface

        # --- Styles ---
        self.setup_styles()

        # --- Frames ---
        self.setup_frames()

        # --- Widgets ---
        self.setup_status_frame()
        self.setup_interface_frame() # New frame for the interface
        self.setup_alert_frame()
        self.setup_rssi_frame()
        self.setup_honeypot_frame()
        self.setup_log_frame()

        # --- Start GUI Update Loop ---
        self.master.after(100, self.update_gui)

        # --- Protocol for closing the window ---
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        # Progressbar colors
        self.style.configure("Red.Horizontal.TProgressbar", background='#FF0000', troughcolor='white')
        self.style.configure("Orange.Horizontal.TProgressbar", background='#FF8C00', troughcolor='white')
        self.style.configure("Yellow.Horizontal.TProgressbar", background='#FFFF00', troughcolor='white')
        self.style.configure("Green.Horizontal.TProgressbar", background='#00FF00', troughcolor='white')
        # Alarm Label
        self.style.configure("Critical.TLabel", foreground="red", font=('Arial', 16, 'bold'))
        self.style.configure("Warning.TLabel", foreground="orange", font=('Arial', 14))
        self.style.configure("Normal.TLabel", foreground="green", font=('Arial', 12))

    def setup_frames(self):
        self.status_frame = ttk.LabelFrame(self.master, text="Status", padding=10)
        self.interface_frame = ttk.LabelFrame(self.master, text="Network Interface", padding=10) # New Frame
        self.alert_frame = ttk.LabelFrame(self.master, text="Alarm", padding=10)
        self.rssi_frame = ttk.LabelFrame(self.master, text="Signal Strength (RSSI)", padding=10)
        self.honeypot_frame = ttk.LabelFrame(self.master, text="Honeypot Control", padding=10)
        self.log_frame = ttk.LabelFrame(self.master, text="Event Log", padding=10)
        
        for frame in [self.status_frame, self.interface_frame, self.alert_frame, self.rssi_frame, self.honeypot_frame, self.log_frame]:
            frame.pack(fill="x", padx=10, pady=5)

    def setup_status_frame(self):
        self.status_label = ttk.Label(self.status_frame, text="Detector: Inactive", style="Normal.TLabel")
        self.status_label.pack()
        
        self.start_btn = ttk.Button(self.status_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_btn.pack(pady=5)

    def setup_interface_frame(self):
        self.interface_label = ttk.Label(self.interface_frame, text="Enter Interface Name (e.g., wlan0):")
        self.interface_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.interface_entry = ttk.Entry(self.interface_frame, width=30)
        self.interface_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.scan_btn = ttk.Button(self.interface_frame, text="Scan Interfaces", command=self.scan_interfaces)
        self.scan_btn.pack(side=tk.LEFT)

        if not SCAPY_AVAILABLE:
            self.interface_entry.config(state="disabled")
            self.scan_btn.config(state="disabled")
            self.interface_entry.insert(0, "Scapy not available (Simulation)")
        else:
            # Optionally, you can still call scan_interfaces to populate the log on startup
            # self.scan_interfaces() 
            pass # User wants to manually enter, so no default value set here initially

    def setup_alert_frame(self):
        self.alert_label = ttk.Label(self.alert_frame, text="NO ATTACK ACTIVE", style="Normal.TLabel")
        self.alert_label.pack(pady=10)

    def setup_rssi_frame(self):
        self.rssi_progress = ttk.Progressbar(self.rssi_frame, orient="horizontal", length=400, 
                                             style="Green.Horizontal.TProgressbar")
        self.rssi_progress.pack(pady=5)
        self.rssi_value_label = ttk.Label(self.rssi_frame, text="Current RSSI: N/A")
        self.rssi_value_label.pack()

    def setup_honeypot_frame(self):
        self.honeypot_toggle = ttk.Checkbutton(self.honeypot_frame, text="Activate Honeypot",
                                               command=self.toggle_honeypot)
        self.honeypot_toggle.pack(pady=5)
        
        self.countermeasure_label = ttk.Label(self.honeypot_frame, text="Ready for countermeasures...")
        self.countermeasure_label.pack()

    def setup_log_frame(self):
        self.log_text = tk.Text(self.log_frame, wrap="word", state="disabled", height=15, font=('Consolas', 10))
        self.log_text.pack(fill="both", expand=True, pady=5)
        
        # Log tags for colors
        self.log_text.tag_configure("critical", foreground="red", font=('Consolas', 10, 'bold'))
        self.log_text.tag_configure("warning", foreground="orange")
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("normal", foreground="black")

    def scan_interfaces(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy is not installed.")
            return

        try:
            all_interfaces = get_if_list()
            
            if not all_interfaces:
                messagebox.showwarning("No Interfaces Found",
                                       "Scapy could not find any network interfaces. "
                                       "Ensure Scapy is correctly installed and the script is running with administrator/root privileges.")
                self.add_log_entry("No interfaces found by Scapy.", "critical")
                return

            self.add_log_entry(f"Detected Interfaces: {', '.join(all_interfaces)}", "info")
            messagebox.showinfo("Interfaces Found", 
                                f"Available interfaces logged. Please enter the desired WLAN interface name (e.g., wlan0) in the input field.")

        except PermissionError:
            messagebox.showerror("Error", "Permission error when scanning interfaces. "
                                           "Please ensure you run the script with administrator/root privileges (e.g., with 'sudo').")
            self.add_log_entry("Error: Permission error when scanning interfaces.", "critical")
            # Ensure GUI elements are re-enabled
            self.interface_entry.config(state="normal")
            self.scan_btn.config(state="normal")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred while scanning interfaces: {str(e)}")
            self.add_log_entry(f"Unexpected error when scanning interfaces: {str(e)}", "critical")
            # Ensure GUI elements are re-enabled
            self.interface_entry.config(state="normal")
            self.scan_btn.config(state="normal")

    def _reset_gui_on_error(self):
        """Resets GUI elements to their initial state after an error during monitoring setup."""
        self.detection_active = False
        self.status_label.config(text="Detector: Inactive")
        self.start_btn.config(text="Start Monitoring")
        self.interface_entry.config(state="normal")
        self.scan_btn.config(state="normal")
        self.monitor_interface = None
        self.original_interface = None
        # No need to explicitly stop sniff_thread here, as the error likely came from within it,
        # or it will terminate due to detection_active being False.

    def toggle_monitoring(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy is not installed. The detector can only simulate.")
            return

        if not self.detection_active: # Start Monitoring
            selected_interface = self.interface_entry.get().strip()
            if not selected_interface:
                messagebox.showerror("Error", "Please enter a network interface name.")
                return

            self.original_interface = selected_interface # Store for later reset
            
            # Attempt to activate monitor mode (Linux-specific with airmon-ng)
            try:
                # airmon-ng check kill terminates interfering processes
                self.add_log_entry("Attempting to stop interfering processes with 'airmon-ng check kill'...", "info")
                check_kill_result = subprocess.run(["airmon-ng", "check", "kill"], check=True, capture_output=True, text=True)
                self.add_log_entry(f"airmon-ng check kill stdout: {check_kill_result.stdout.strip()}", "info")
                if check_kill_result.stderr:
                    self.add_log_entry(f"airmon-ng check kill stderr: {check_kill_result.stderr.strip()}", "warning")
                self.add_log_entry("Interfering processes terminated (if any).", "info")

                # airmon-ng start puts the interface into monitor mode
                self.add_log_entry(f"Attempting to start monitor mode on {self.original_interface} with 'airmon-ng start'...", "info")
                start_monitor_result = subprocess.run(["airmon-ng", "start", self.original_interface], check=True, capture_output=True, text=True)
                self.add_log_entry(f"airmon-ng start stdout: {start_monitor_result.stdout.strip()}", "info")
                if start_monitor_result.stderr:
                    self.add_log_entry(f"airmon-ng start stderr: {start_monitor_result.stderr.strip()}", "warning")

                output_lines = []
                # Check if the output is a string to avoid "not text attribute" error
                if isinstance(start_monitor_result.stdout, str):
                    output_lines = start_monitor_result.stdout.splitlines()
                else:
                    self.add_log_entry(f"ERROR: airmon-ng start returned unexpected output type for stdout: {type(start_monitor_result.stdout)}. Expected string.", "critical")
                    messagebox.showerror("Error", "Unexpected output from airmon-ng. Please check your airmon-ng installation and ensure it's compatible with your Python environment.")
                    self._reset_gui_on_error() # Call helper to reset GUI state
                    return # Exit function early

                # Attempt to find the name of the new monitor interface
                self.monitor_interface = None
                for line in output_lines:
                    if "monitor mode enabled on" in line:
                        # Example: (monitor mode enabled on wlan0mon)
                        parts = line.split()
                        if len(parts) > 4 and parts[3] == "on":
                            self.monitor_interface = parts[4].strip(')')
                            break
                    elif "Monitor mode enabled for" in line:
                        # Example: Monitor mode enabled for wlan0mon
                        parts = line.split()
                        if len(parts) > 3 and parts[3] == "for":
                            self.monitor_interface = parts[4].strip()
                            break
                
                if not self.monitor_interface:
                    # Fallback if airmon-ng doesn't clearly output the name, 
                    # or if the interface was already in monitor mode and the name remained the same.
                    # This is a heuristic and may fail.
                    if "mon" in self.original_interface:
                        self.monitor_interface = self.original_interface
                    else:
                        # Attempt to append 'mon' to the name
                        self.monitor_interface = self.original_interface + "mon" 
                    self.add_log_entry(f"Could not clearly extract monitor interface from airmon-ng output. Trying: {self.monitor_interface}", "warning")

                # --- NEW CHECK: Verify if the monitor interface is found by Scapy ---
                # Add a small delay to give the system time to register the new interface
                time.sleep(1) 
                if self.monitor_interface not in get_if_list():
                    error_msg = f"Monitor interface '{self.monitor_interface}' not found by Scapy after airmon-ng. " \
                                "This might indicate a driver issue, a problem with airmon-ng, or incorrect privileges. " \
                                "Please check your system configuration and ensure the adapter fully supports monitor mode."
                    self.add_log_entry(f"ERROR: {error_msg}", "critical")
                    messagebox.showerror("Error", error_msg)
                    self._reset_gui_on_error()
                    return
                # --- END NEW CHECK ---

                self.add_log_entry(f"Interface {self.original_interface} successfully put into monitor mode. New interface: {self.monitor_interface}", "info")
                
                # Update GUI to show the monitor interface
                self.interface_entry.delete(0, tk.END)
                self.interface_entry.insert(0, self.monitor_interface)
                self.interface_entry.config(state="disabled") # Disable during monitoring
                self.scan_btn.config(state="disabled")

                self.detection_active = True
                self.status_label.config(text=f"Detector: ACTIVE (Interface: {self.monitor_interface})")
                self.start_btn.config(text="Stop Monitoring")
                self.deauth_timestamps = [] # Reset on start
                self.sniff_thread = threading.Thread(target=self.start_sniffing, args=(self.monitor_interface,))
                self.sniff_thread.daemon = True
                self.sniff_thread.start()

            except FileNotFoundError:
                messagebox.showerror("Error", "airmon-ng not found. Please install aircrack-ng (sudo apt install aircrack-ng).")
                self.add_log_entry("Error: airmon-ng not found.", "critical")
                self._reset_gui_on_error() # Call helper to reset GUI state
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Error executing airmon-ng: {e.stderr}\n"
                                               "Please ensure you run the script with administrator/root privileges.")
                self.add_log_entry(f"Error with airmon-ng: {e.stderr}", "critical")
                self._reset_gui_on_error() # Call helper to reset GUI state
            except Exception as e:
                messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
                self.add_log_entry(f"Unexpected error: {str(e)}", "critical")
                self._reset_gui_on_error() # Call helper to reset GUI state
            
        else: # Stop Monitoring
            self.detection_active = False
            self.status_label.config(text="Detector: Inactive")
            self.start_btn.config(text="Start Monitoring")
            self.interface_entry.config(state="normal") # Re-enable
            self.scan_btn.config(state="normal")
            
            self.add_log_entry("Stopping monitoring...", "info")
            if self.sniff_thread and self.sniff_thread.is_alive():
                # The sniff_thread will terminate via `stop_filter`
                pass 
            
            # Attempt to deactivate monitor mode (Linux-specific)
            if self.monitor_interface and self.original_interface:
                try:
                    self.add_log_entry(f"Attempting to stop monitor mode on {self.monitor_interface} with 'airmon-ng stop'...", "info")
                    stop_monitor_result = subprocess.run(["airmon-ng", "stop", self.monitor_interface], check=True, capture_output=True, text=True)
                    self.add_log_entry(f"airmon-ng stop stdout: {stop_monitor_result.stdout.strip()}", "info")
                    if stop_monitor_result.stderr:
                        self.add_log_entry(f"airmon-ng stop stderr: {stop_monitor_result.stderr.strip()}", "warning")
                    
                    # Explicitly set original interface back to managed mode
                    self.add_log_entry(f"Setting interface {self.original_interface} to managed mode...", "info")
                    subprocess.run(["sudo", "ip", "link", "set", self.original_interface, "down"], check=True, capture_output=True, text=True)
                    subprocess.run(["sudo", "iwconfig", self.original_interface, "mode", "managed"], check=True, capture_output=True, text=True)
                    subprocess.run(["sudo", "ip", "link", "set", self.original_interface, "up"], check=True, capture_output=True, text=True)
                    self.add_log_entry(f"Interface {self.original_interface} successfully set to managed mode.", "info")

                    # Restart NetworkManager to restore connectivity
                    self.add_log_entry("Restarting NetworkManager...", "info")
                    nm_restart_result = subprocess.run(["systemctl", "restart", "NetworkManager"], check=False, capture_output=True, text=True)
                    self.add_log_entry(f"NetworkManager restart stdout: {nm_restart_result.stdout.strip()}", "info")
                    if nm_restart_result.stderr:
                        self.add_log_entry(f"NetworkManager restart stderr: {nm_restart_result.stderr.strip()}", "warning")
                    
                    self.add_log_entry(f"Interface {self.original_interface} successfully reset. NetworkManager restarted.", "info")
                    self.monitor_interface = None
                    self.original_interface = None
                    # No need to rescan, just clear the entry or set to default if desired
                    # self.scan_interfaces() 
                except FileNotFoundError:
                    self.add_log_entry("airmon-ng or ip/iwconfig not found, could not deactivate monitor mode. Manual intervention may be required.", "critical")
                    messagebox.showerror("Error", "Required tools (airmon-ng/ip/iwconfig) not found for mode deactivation. Manual intervention may be required to restore Wi-Fi.")
                except subprocess.CalledProcessError as e:
                    self.add_log_entry(f"Error deactivating monitor mode or setting managed mode: {e.stderr}", "critical")
                    messagebox.showerror("Error", f"Error during Wi-Fi restoration: {e.stderr}. Manual intervention may be required.")
                except Exception as e:
                    self.add_log_entry(f"Unexpected error when resetting monitor mode: {str(e)}", "critical")
                    messagebox.showerror("Error", f"Unexpected error during Wi-Fi restoration: {str(e)}. Manual intervention may be required.")


    def toggle_honeypot(self):
        self.honeypot.honeypot_active = not self.honeypot.honeypot_active
        status = "ACTIVE" if self.honeypot.honeypot_active else "Inactive"
        messagebox.showinfo("Honeypot", f"Honeypot mode is now {status}!")
        self.add_log_entry(f"Honeypot mode: {status}", "info")


    def start_sniffing(self, interface):
        """Starts the Scapy sniffing process."""
        try:
            # filter='type management subtype deauth' is the filter for deauth packets
            self.add_log_entry(f"Starting Scapy sniff on interface: {interface}...", "info")
            sniff(iface=interface, prn=self.packet_callback, stop_filter=lambda x: not self.detection_active, store=0)
            self.add_log_entry(f"Scapy sniff on {interface} stopped.", "info")
        except PermissionError as e:
            messagebox.showerror("Error", f"Permission error during sniffing: {e}. Run the script as administrator/root.")
            self.data_queue.put({"type": "error", "message": f"Permission error during sniffing: {e}"})
            self._reset_gui_on_error() # Call helper to reset GUI state
        except Exception as e:
            messagebox.showerror("Error", f"Error sniffing on {interface}: {str(e)}")
            self.data_queue.put({"type": "error", "message": f"Sniffing error on {interface}: {str(e)}"})
            self._reset_gui_on_error() # Call helper to reset GUI state


    def packet_callback(self, packet):
        """Called for each sniffed packet."""
        if not self.detection_active:
            return # Stop processing if detector is inactive

        if packet.haslayer(Dot11Deauth):
            try:
                src_mac = packet[Dot11].addr2 if packet[Dot11].addr2 else "N/A"
                dst_mac = packet[Dot11].addr1 if packet[Dot11].addr1 else "N/A"
                bssid = packet[Dot11].addr3 if packet[Dot11].addr3 else "N/A"

                rssi = "N/A"
                if packet.haslayer(RadioTap):
                    # RSSI can be in RadioTap as 'dbm_antsignal' or 'power'
                    if hasattr(packet[RadioTap], 'dbm_antsignal'):
                        rssi = packet[RadioTap].dbm_antsignal
                    elif hasattr(packet[RadioTap], 'power'): # Sometimes also 'power'
                        rssi = packet[RadioTap].power

                current_time = datetime.now()
                self.deauth_timestamps.append(current_time)

                # Remove old timestamps (e.g., older than 5 seconds)
                window_start_time = current_time - timedelta(seconds=5)
                self.deauth_timestamps = [ts for ts in self.deauth_timestamps if ts >= window_start_time]
                
                num_deauth_in_window = len(self.deauth_timestamps)

                severity = "normal"
                if num_deauth_in_window >= 10:
                    severity = "critical"
                elif num_deauth_in_window >= 5:
                    severity = "warning"

                self.data_queue.put({
                    "type": "deauth",
                    "timestamp": current_time.strftime('%H:%M:%S'),
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "bssid": bssid,
                    "rssi": rssi,
                    "num_deauth_in_window": num_deauth_in_window,
                    "severity": severity
                })

                # Honeypot response if active
                if self.honeypot.honeypot_active and severity == "critical":
                    countermeasure = self.honeypot.simulate_attacker_response(src_mac)
                    if countermeasure:
                        self.data_queue.put({
                            "type": "countermeasure",
                            "message": countermeasure,
                            "severity": "info"
                        })

            except Exception as e:
                # Error parsing packet or processing data
                self.data_queue.put({"type": "error", "message": f"Error processing deauth packet: {str(e)}"})

    def update_gui(self):
        try:
            while True:
                data = self.data_queue.get_nowait()
                self.process_data(data)
        except queue.Empty:
            pass
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.add_log_entry(f"GUI Update Error: {str(e)}", "critical")
            
        self.master.after(100, self.update_gui)

    def process_data(self, data):
        if data["type"] == "deauth":
            self.process_deauth_packet(data)
        elif data["type"] == "honeypot":
            self.add_log_entry(data["message"], data["severity"])
        elif data["type"] == "countermeasure":
            self.countermeasure_label.config(text=data["message"])
            self.add_log_entry(data["message"], data["severity"])
        elif data["type"] == "error":
            messagebox.showerror("Error", data["message"])
            self.add_log_entry(f"ERROR: {data['message']}", "critical")
            # If the error is critical and prevents sniffing, reset GUI state
            # This ensures buttons are re-enabled etc.
            if "sniffing" in data["message"].lower() or "permission" in data["message"].lower() or "not found by scapy" in data["message"].lower() or "unexpected output from airmon-ng" in data["message"].lower():
                self.master.after(0, self._reset_gui_on_error) # Schedule reset on main thread

    def process_deauth_packet(self, data):
        # RSSI Display
        rssi = data["rssi"]
        if isinstance(rssi, (int, float)):
            # Scale RSSI from -90 (0%) to -30 (100%) for the progress bar
            # RSSI range is 60 (-30 - -90)
            progress_value = max(0, min(100, (rssi + 90) / 60 * 100))
            self.rssi_progress["value"] = progress_value
            self.rssi_value_label.config(text=f"Current RSSI: {rssi} dBm")
            
            # Adjust progress bar color based on RSSI value
            if rssi >= -40: # Very good
                self.rssi_progress.config(style="Green.Horizontal.TProgressbar")
            elif rssi >= -60: # Good
                self.rssi_progress.config(style="Yellow.Horizontal.TProgressbar")
            elif rssi >= -80: # Medium
                self.rssi_progress.config(style="Orange.Horizontal.TProgressbar")
            else: # Weak
                self.rssi_progress.config(style="Red.Horizontal.TProgressbar")
        else:
            self.rssi_progress["value"] = 0
            self.rssi_progress.config(style="Red.Horizontal.TProgressbar")
            self.rssi_value_label.config(text=f"Current RSSI: {rssi} (Not available)")


        # Alarm Logic
        if data["num_deauth_in_window"] >= 10 and self.detection_active:
            self.alert_label.config(text="!!! DEAUTH ATTACK !!!", style="Critical.TLabel")
            self.master.bell()
        elif data["num_deauth_in_window"] >= 5:
            self.alert_label.config(text="Possible Attack", style="Warning.TLabel")
        else:
            self.alert_label.config(text="No Attack", style="Normal.TLabel")

        # Log entry
        log_msg = (
            f"[{data['timestamp']}] {data['src_mac']} → {data['dst_mac']} | "
            f"BSSID: {data['bssid']} | RSSI: {rssi} dBm | Packets (5s): {data['num_deauth_in_window']}"
        )
        self.add_log_entry(log_msg, data["severity"])

    def add_log_entry(self, message, severity="normal"):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n", severity)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def on_closing(self):
        """Called when the window is closed to safely terminate threads."""
        self.running = False # Set flag to terminate GUI update loop
        self.detection_active = False # Stop sniffing thread
        
        # Attempt to deactivate monitor mode if it was active
        if self.monitor_interface and self.original_interface:
            try:
                self.add_log_entry(f"Attempting to stop monitor mode on {self.monitor_interface} with 'airmon-ng stop'...", "info")
                stop_monitor_result = subprocess.run(["airmon-ng", "stop", self.monitor_interface], check=True, capture_output=True, text=True)
                self.add_log_entry(f"airmon-ng stop stdout: {stop_monitor_result.stdout.strip()}", "info")
                if stop_monitor_result.stderr:
                    self.add_log_entry(f"airmon-ng stop stderr: {stop_monitor_result.stderr.strip()}", "warning")
                    
                # Explicitly set original interface back to managed mode
                self.add_log_entry(f"Setting interface {self.original_interface} to managed mode and bringing it up...", "info")
                subprocess.run(["sudo", "ip", "link", "set", self.original_interface, "down"], check=True, capture_output=True, text=True)
                subprocess.run(["sudo", "iwconfig", self.original_interface, "mode", "managed"], check=True, capture_output=True, text=True)
                subprocess.run(["sudo", "ip", "link", "set", self.original_interface, "up"], check=True, capture_output=True, text=True)
                self.add_log_entry(f"Interface {self.original_interface} successfully set to managed mode and brought up.", "info")

                # Restart NetworkManager to restore connectivity
                self.add_log_entry("Restarting NetworkManager...", "info")
                nm_restart_result = subprocess.run(["systemctl", "restart", "NetworkManager"], check=False, capture_output=True, text=True)
                self.add_log_entry(f"NetworkManager restart stdout: {nm_restart_result.stdout.strip()}", "info")
                if nm_restart_result.stderr:
                    self.add_log_entry(f"NetworkManager restart stderr: {nm_restart_result.stderr.strip()}", "warning")
                
                self.add_log_entry(f"Interface {self.original_interface} successfully reset. NetworkManager restarted.", "info")
                self.monitor_interface = None
                self.original_interface = None
            except FileNotFoundError:
                self.add_log_entry("airmon-ng or ip/iwconfig not found, could not deactivate monitor mode. Manual intervention may be required.", "critical")
                messagebox.showerror("Error", "Required tools (airmon-ng/ip/iwconfig) not found for mode deactivation. Manual intervention may be required to restore Wi-Fi.")
            except subprocess.CalledProcessError as e:
                self.add_log_entry(f"Error deactivating monitor mode or setting managed mode: {e.stderr}", "critical")
                messagebox.showerror("Error", f"Error during Wi-Fi restoration: {e.stderr}. Manual intervention may be required.")
            except Exception as e:
                self.add_log_entry(f"Unexpected error when resetting monitor mode: {str(e)}", "critical")
                messagebox.showerror("Error", f"Unexpected error during Wi-Fi restoration: {str(e)}. Manual intervention may be required.")

        if self.sniff_thread and self.sniff_thread.is_alive():
            # Give the sniffing thread some time to terminate
            # Since stop_filter is used, it should terminate soon.
            pass 
        self.master.destroy() # Close the Tkinter window

if __name__ == "__main__":
    root = tk.Tk()
    app = DeauthDetectorGUI(root)
    root.mainloop()
