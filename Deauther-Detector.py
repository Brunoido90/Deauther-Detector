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
    print("WARNING: Scapy not found. The detector will run in simulation mode.")
    print("Please install Scapy (pip install scapy) for real functionality.")

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

        self.setup_styles()
        self.setup_gui()
        
        self.master.after(100, self.update_gui)
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        if sys.platform.startswith('linux'):
            self._check_linux_tools_availability()

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

    def setup_gui(self):
        # Status Frame
        self.status_frame = ttk.LabelFrame(self.master, text="Status", padding=10)
        self.status_frame.pack(fill="x", padx=10, pady=5)
        
        self.status_label = ttk.Label(self.status_frame, text="Detector: Inactive", style="Normal.TLabel")
        self.status_label.pack()
        
        self.start_btn = ttk.Button(self.status_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_btn.pack(pady=5)

        # Interface Frame
        self.interface_frame = ttk.LabelFrame(self.master, text="Network Interface", padding=10)
        self.interface_frame.pack(fill="x", padx=10, pady=5)
        
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
        self.alert_frame = ttk.LabelFrame(self.master, text="Alarm", padding=10)
        self.alert_frame.pack(fill="x", padx=10, pady=5)
        
        self.alert_label = ttk.Label(self.alert_frame, text="NO ATTACK ACTIVE", style="Normal.TLabel")
        self.alert_label.pack(pady=10)

        # RSSI Frame
        self.rssi_frame = ttk.LabelFrame(self.master, text="Signal Strength (RSSI)", padding=10)
        self.rssi_frame.pack(fill="x", padx=10, pady=5)
        
        self.rssi_progress = ttk.Progressbar(self.rssi_frame, orient="horizontal", length=400, 
                                           style="Green.Horizontal.TProgressbar")
        self.rssi_progress.pack(pady=5)
        self.rssi_value_label = ttk.Label(self.rssi_frame, text="Current RSSI: N/A")
        self.rssi_value_label.pack()

        # Honeypot Frame
        self.honeypot_frame = ttk.LabelFrame(self.master, text="Honeypot Control", padding=10)
        self.honeypot_frame.pack(fill="x", padx=10, pady=5)
        
        self.honeypot_toggle = ttk.Checkbutton(self.honeypot_frame, text="Activate Honeypot",
                                             command=self.toggle_honeypot)
        self.honeypot_toggle.pack(pady=5)
        
        self.countermeasure_label = ttk.Label(self.honeypot_frame, text="Ready for countermeasures...")
        self.countermeasure_label.pack()

        # Log Frame
        self.log_frame = ttk.LabelFrame(self.master, text="Event Log", padding=10)
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = tk.Text(self.log_frame, wrap="word", state="disabled", height=15, font=('Consolas', 10))
        self.log_text.pack(fill="both", expand=True, pady=5)
        
        self.log_text.tag_configure("critical", foreground="red", font=('Consolas', 10, 'bold'))
        self.log_text.tag_configure("warning", foreground="orange")
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("normal", foreground="black")

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
            msg = f"WARNING: Missing tools: {', '.join(missing_tools)}. Automatic monitor mode setup may not work."
            self.add_log_entry(msg, "critical")
            messagebox.showwarning("Missing Linux Tools", msg)

    def scan_interfaces(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy is not installed.")
            return

        try:
            all_interfaces = get_if_list()
            if not all_interfaces:
                messagebox.showwarning("No Interfaces", "No network interfaces found.")
                return

            self.add_log_entry(f"Detected Interfaces: {', '.join(all_interfaces)}", "info")
            messagebox.showinfo("Interfaces Found", f"Available interfaces: {', '.join(all_interfaces)}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan interfaces: {str(e)}")
            self.add_log_entry(f"Interface scan error: {str(e)}", "critical")

    def toggle_monitoring(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy is not installed. The detector can only simulate.")
            return

        if not self.detection_active:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        selected_interface = self.interface_entry.get().strip()
        if not selected_interface:
            messagebox.showerror("Error", "Please enter a network interface name.")
            return

        self.original_interface = selected_interface
        self.monitor_interface = None
        
        try:
            if sys.platform.startswith('linux'):
                try:
                    self.monitor_interface = self._activate_monitor_mode_airmon(self.original_interface)
                except Exception as e:
                    self.add_log_entry(f"airmon-ng failed: {e}. Trying alternative...", "warning")
                    try:
                        self.monitor_interface = self._activate_monitor_mode_iw(self.original_interface)
                    except Exception as e_alt:
                        raise Exception(f"Both methods failed: {e_alt}")
            else:
                self.add_log_entry("Assuming interface is in monitor mode", "info")
                self.monitor_interface = self.original_interface

            if not self.monitor_interface:
                raise Exception("Failed to determine monitor interface")

            time.sleep(2)
            if SCAPY_AVAILABLE and self.monitor_interface not in get_if_list():
                raise Exception(f"Interface {self.monitor_interface} not found by Scapy")

            self.interface_entry.delete(0, tk.END)
            self.interface_entry.insert(0, self.monitor_interface)
            self.interface_entry.config(state="disabled")
            self.scan_btn.config(state="disabled")

            self.detection_active = True
            self.status_label.config(text=f"Detector: ACTIVE ({self.monitor_interface})")
            self.start_btn.config(text="Stop Monitoring")
            self.deauth_timestamps = []
            
            self.sniff_thread = threading.Thread(target=self.start_sniffing, args=(self.monitor_interface,))
            self.sniff_thread.daemon = True
            self.sniff_thread.start()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}")
            self.add_log_entry(f"Start monitoring error: {str(e)}", "critical")
            self._reset_gui_on_error()

    def stop_monitoring(self):
        self.detection_active = False
        self.status_label.config(text="Detector: Inactive")
        self.start_btn.config(text="Start Monitoring")
        self.interface_entry.config(state="normal")
        self.scan_btn.config(state="normal")
        
        self.add_log_entry("Stopping monitoring...", "info")
        
        if sys.platform.startswith('linux') and self.monitor_interface and self.original_interface:
            try:
                self._deactivate_monitor_mode()
            except Exception as e:
                messagebox.showerror("Error", f"Error during Wi-Fi restoration: {str(e)}")
                self.add_log_entry(f"Cleanup error: {str(e)}", "critical")

    def _activate_monitor_mode_airmon(self, interface):
        self.add_log_entry("Attempting to stop interfering processes...", "info")
        try:
            subprocess.run(["airmon-ng", "check", "kill"], check=True, capture_output=True, text=True)
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            self.add_log_entry(f"airmon-ng check kill failed: {str(e)}", "warning")

        self.add_log_entry(f"Starting monitor mode on {interface}...", "info")
        result = subprocess.run(["airmon-ng", "start", interface], check=True, capture_output=True, text=True)
        
        # Parse output to find monitor interface
        for line in result.stdout.splitlines():
            if "monitor mode enabled on" in line:
                return line.split()[-1].strip(')')
            elif "Monitor mode enabled for" in line:
                return line.split()[-1].strip()
        
        return interface + "mon" if not interface.endswith("mon") else interface

    def _activate_monitor_mode_iw(self, interface):
        self.add_log_entry(f"Using ip/iwconfig to activate monitor mode on {interface}", "info")
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        return interface

    def _deactivate_monitor_mode(self):
        self.add_log_entry(f"Stopping monitor mode on {self.monitor_interface}", "info")
        subprocess.run(["airmon-ng", "stop", self.monitor_interface], check=True)
        
        self.add_log_entry(f"Restoring {self.original_interface}", "info")
        subprocess.run(["sudo", "ip", "link", "set", self.original_interface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", self.original_interface, "mode", "managed"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", self.original_interface, "up"], check=True)
        
        self.add_log_entry("Restarting NetworkManager", "info")
        subprocess.run(["systemctl", "restart", "NetworkManager"], check=False)
        
        self.monitor_interface = None
        self.original_interface = None

    def _reset_gui_on_error(self):
        self.detection_active = False
        self.status_label.config(text="Detector: Inactive")
        self.start_btn.config(text="Start Monitoring")
        self.interface_entry.config(state="normal")
        self.scan_btn.config(state="normal")
        self.monitor_interface = None
        self.original_interface = None

    def toggle_honeypot(self):
        self.honeypot.honeypot_active = not self.honeypot.honeypot_active
        status = "ACTIVE" if self.honeypot.honeypot_active else "Inactive"
        self.add_log_entry(f"Honeypot mode: {status}", "info")
        messagebox.showinfo("Honeypot", f"Honeypot mode is now {status}!")

    def start_sniffing(self, interface):
        try:
            self.add_log_entry(f"Starting sniffing on {interface}", "info")
            sniff(iface=interface, prn=self.packet_callback, stop_filter=lambda x: not self.detection_active, store=0)
            self.add_log_entry(f"Stopped sniffing on {interface}", "info")
        except Exception as e:
            self.data_queue.put({
                "type": "error", 
                "message": f"Sniffing error: {str(e)}"
            })
            self._reset_gui_on_error()

    def packet_callback(self, packet):
        if not self.detection_active or not packet.haslayer(Dot11Deauth):
            return

        try:
            src_mac = packet[Dot11].addr2 if packet[Dot11].addr2 else "N/A"
            dst_mac = packet[Dot11].addr1 if packet[Dot11].addr1 else "N/A"
            bssid = packet[Dot11].addr3 if packet[Dot11].addr3 else "N/A"

            rssi = "N/A"
            if packet.haslayer(RadioTap):
                if hasattr(packet[RadioTap], 'dbm_antsignal'):
                    rssi = packet[RadioTap].dbm_antsignal
                elif hasattr(packet[RadioTap], 'power'):
                    rssi = packet[RadioTap].power

            current_time = datetime.now()
            self.deauth_timestamps.append(current_time)
            window_start = current_time - timedelta(seconds=5)
            self.deauth_timestamps = [ts for ts in self.deauth_timestamps if ts >= window_start]
            
            num_deauth = len(self.deauth_timestamps)
            severity = "critical" if num_deauth >= 10 else "warning" if num_deauth >= 5 else "normal"

            self.data_queue.put({
                "type": "deauth",
                "timestamp": current_time.strftime('%H:%M:%S'),
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "bssid": bssid,
                "rssi": rssi,
                "num_deauth_in_window": num_deauth,
                "severity": severity
            })

            if self.honeypot.honeypot_active and severity == "critical":
                response = self.honeypot.simulate_attacker_response(src_mac)
                if response:
                    self.data_queue.put({
                        "type": "countermeasure",
                        "message": response,
                        "severity": "info"
                    })

        except Exception as e:
            self.data_queue.put({
                "type": "error",
                "message": f"Packet processing error: {str(e)}"
            })

    def update_gui(self):
        try:
            while True:
                data = self.data_queue.get_nowait()
                self.process_data(data)
        except queue.Empty:
            pass
        finally:
            if self.running:
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
            self.add_log_entry(f"ERROR: {data['message']}", "critical")
            if "sniffing" in data['message'].lower():
                self._reset_gui_on_error()

    def process_deauth_packet(self, data):
        # Update RSSI display
        if isinstance(data["rssi"], (int, float)):
            rssi = data["rssi"]
            progress = max(0, min(100, (rssi + 90) / 60 * 100))
            self.rssi_progress["value"] = progress
            self.rssi_value_label.config(text=f"Current RSSI: {rssi} dBm")
            
            if rssi >= -40:
                style = "Green.Horizontal.TProgressbar"
            elif rssi >= -60:
                style = "Yellow.Horizontal.TProgressbar"
            elif rssi >= -80:
                style = "Orange.Horizontal.TProgressbar"
            else:
                style = "Red.Horizontal.TProgressbar"
            self.rssi_progress.config(style=style)
        else:
            self.rssi_progress["value"] = 0
            self.rssi_progress.config(style="Red.Horizontal.TProgressbar")
            self.rssi_value_label.config(text=f"Current RSSI: {data['rssi']}")

        # Update alert status
        if data["num_deauth_in_window"] >= 10 and self.detection_active:
            self.alert_label.config(text="!!! DEAUTH ATTACK !!!", style="Critical.TLabel")
            self.master.bell()
        elif data["num_deauth_in_window"] >= 5:
            self.alert_label.config(text="Possible Attack", style="Warning.TLabel")
        else:
            self.alert_label.config(text="No Attack", style="Normal.TLabel")

        # Add log entry
        log_msg = (f"[{data['timestamp']}] {data['src_mac']} → {data['dst_mac']} | "
                  f"BSSID: {data['bssid']} | RSSI: {data['rssi']} dBm | "
                  f"Packets (5s): {data['num_deauth_in_window']}")
        self.add_log_entry(log_msg, data["severity"])

    def add_log_entry(self, message, severity="normal"):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n", severity)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def on_closing(self):
        self.running = False
        self.detection_active = False
        
        if sys.platform.startswith('linux') and self.monitor_interface and self.original_interface:
            try:
                self._deactivate_monitor_mode()
            except Exception as e:
                self.add_log_entry(f"Cleanup error: {str(e)}", "critical")
        
        self.master.destroy()

def main():
    root = tk.Tk()
    app = DeauthDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
