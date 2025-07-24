import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import queue
from datetime import datetime, timedelta
import subprocess
import sys

try:
    from scapy.all import Dot11, Dot11Deauth, sniff, RadioTap, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not found. Running in simulation mode.")
    print("Install Scapy with: pip install scapy")

class HoneypotSimulator:
    def __init__(self, data_queue):
        self.data_queue = data_queue
        self.honeypot_active = False
        self.attacker_macs = set()

    def simulate_attacker_response(self, src_mac):
        if src_mac not in self.attacker_macs:
            self.attacker_macs.add(src_mac)
            self.data_queue.put({
                "type": "honeypot",
                "message": f"⚠️ HONEYPOT TRIGGERED! Attacker {src_mac} isolated.",
                "severity": "critical"
            })
            return f"Countermeasure: Fake AP started for {src_mac}"
        return None

class DeauthDetectorGUI:
    def __init__(self, master):
        self.master = master
        master.title("Deauth Detector + Honeypot")
        master.geometry("1000x700")

        self.data_queue = queue.Queue()
        self.detection_active = False
        self.honeypot = HoneypotSimulator(self.data_queue)
        self.running = True
        self.sniff_thread = None
        self.deauth_timestamps = []
        self.original_interface = None
        self.monitor_interface = None

        self.setup_gui()
        self.master.after(100, self.update_gui)
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        if sys.platform.startswith('linux'):
            self._check_linux_tools_availability()

    def setup_gui(self):
        self.setup_styles()
        
        # Create frames
        self.status_frame = ttk.LabelFrame(self.master, text="Status", padding=10)
        self.interface_frame = ttk.LabelFrame(self.master, text="Network Interface", padding=10)
        self.alert_frame = ttk.LabelFrame(self.master, text="Alarm", padding=10)
        self.rssi_frame = ttk.LabelFrame(self.master, text="Signal Strength (RSSI)", padding=10)
        self.honeypot_frame = ttk.LabelFrame(self.master, text="Honeypot Control", padding=10)
        self.log_frame = ttk.LabelFrame(self.master, text="Event Log", padding=10)
        
        for frame in [self.status_frame, self.interface_frame, self.alert_frame, 
                     self.rssi_frame, self.honeypot_frame, self.log_frame]:
            frame.pack(fill="x", padx=10, pady=5)

        # Status Frame
        self.status_label = ttk.Label(self.status_frame, text="Detector: Inactive", style="Normal.TLabel")
        self.status_label.pack()
        self.start_btn = ttk.Button(self.status_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_btn.pack(pady=5)

        # Interface Frame
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

        # Alert Frame
        self.alert_label = ttk.Label(self.alert_frame, text="NO ATTACK ACTIVE", style="Normal.TLabel")
        self.alert_label.pack(pady=10)

        # RSSI Frame
        self.rssi_progress = ttk.Progressbar(self.rssi_frame, orient="horizontal", length=400, 
                                           style="Green.Horizontal.TProgressbar")
        self.rssi_progress.pack(pady=5)
        self.rssi_value_label = ttk.Label(self.rssi_frame, text="Current RSSI: N/A")
        self.rssi_value_label.pack()

        # Honeypot Frame
        self.honeypot_toggle = ttk.Checkbutton(self.honeypot_frame, text="Activate Honeypot",
                                             command=self.toggle_honeypot)
        self.honeypot_toggle.pack(pady=5)
        self.countermeasure_label = ttk.Label(self.honeypot_frame, text="Ready for countermeasures...")
        self.countermeasure_label.pack()

        # Log Frame
        self.log_text = tk.Text(self.log_frame, wrap="word", state="disabled", height=15, font=('Consolas', 10))
        self.log_text.pack(fill="both", expand=True, pady=5)
        for tag in ["critical", "warning", "info", "normal"]:
            self.log_text.tag_configure(tag, foreground={
                "critical": "red",
                "warning": "orange",
                "info": "blue",
                "normal": "black"
            }[tag], font=('Consolas', 10, 'bold' if tag == "critical" else 'normal'))

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Red.Horizontal.TProgressbar", background='#FF0000', troughcolor='white')
        self.style.configure("Orange.Horizontal.TProgressbar", background='#FF8C00', troughcolor='white')
        self.style.configure("Yellow.Horizontal.TProgressbar", background='#FFFF00', troughcolor='white')
        self.style.configure("Green.Horizontal.TProgressbar", background='#00FF00', troughcolor='white')
        self.style.configure("Critical.TLabel", foreground="red", font=('Arial', 16, 'bold'))
        self.style.configure("Warning.TLabel", foreground="orange", font=('Arial', 14))
        self.style.configure("Normal.TLabel", foreground="green", font=('Arial', 12))

    def _check_linux_tools_availability(self):
        tools = ["airmon-ng", "ip", "iwconfig", "systemctl"]
        missing_tools = []
        for tool in tools:
            try:
                subprocess.run(["which", tool], check=True, capture_output=True, text=True)
            except (FileNotFoundError, subprocess.CalledProcessError):
                missing_tools.append(tool)
            except Exception as e:
                self.add_log_entry(f"Error checking tool '{tool}': {e}", "warning")

        if missing_tools:
            msg = f"WARNING: Missing tools: {', '.join(missing_tools)}. " \
                  "Automatic monitor mode setup may not work correctly."
            self.add_log_entry(msg, "critical")
            messagebox.showwarning("Missing Linux Tools", msg)

    # ... [Keep all your other methods but remove duplicates] ...

    def on_closing(self):
        """Clean up resources when closing the window."""
        self.running = False
        self.detection_active = False
        
        if sys.platform.startswith('linux') and self.monitor_interface and self.original_interface:
            try:
                self._deactivate_monitor_mode()
            except Exception as e:
                self.add_log_entry(f"Error during cleanup: {str(e)}", "critical")
                messagebox.showerror("Cleanup Error", f"Error during cleanup: {str(e)}")
        
        self.master.destroy()

def main():
    root = tk.Tk()
    app = DeauthDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
