#!/usr/bin/env python3
"""
Brunoido DeAuth-Guard PRO mit automatischer Erkennung und Anzeige der MAC-Adressen bei echten Attacken.
Dieses Script erkennt echte Attacken und zeigt die MAC-Adresse des Angreifers vollständig an.
"""

import os
import sys
import time
import threading
import subprocess
import sqlite3
from datetime import datetime
from scapy.all import sniff, Dot11Deauth, Dot11Beacon
import tkinter as tk
from tkinter import ttk, messagebox

class WifiScanner:
    @staticmethod
    def get_interfaces():
        try:
            output = subprocess.check_output(["iw", "dev"], text=True)
            interfaces = [line.split()[1] for line in output.split("\n") if "Interface" in line]
            return interfaces
        except:
            return ["wlan0"]

    @staticmethod
    def enable_monitor_mode(interface):
        try:
            subprocess.check_output(["sudo", "ip", "link", "set", interface, "down"], stderr=subprocess.STDOUT)
            subprocess.check_output(["sudo", "iw", interface, "set", "monitor", "control"], stderr=subprocess.STDOUT)
            subprocess.check_output(["sudo", "ip", "link", "set", interface, "up"], stderr=subprocess.STDOUT)
            time.sleep(1)
            info = subprocess.getoutput(f"iw {interface} info")
            return "monitor" in info
        except:
            return False

class ChannelHopper:
    def __init__(self, iface):
        self.iface = iface
        self.running = False
        self.stop_hopping = False
        self.current_channel = 1

    def start(self):
        self.running = True
        threading.Thread(target=self.hop_channels, daemon=True).start()

    def hop_channels(self):
        channels = range(1, 12)
        while self.running:
            if self.stop_hopping:
                time.sleep(1)
                continue
            for ch in channels:
                if not self.running:
                    break
                self.current_channel = ch
                subprocess.run(["sudo", "iwconfig", self.iface, "channel", str(ch)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.5)

    def focus_on_channel(self, channel):
        self.stop_hopping = True
        subprocess.run(["sudo", "iwconfig", self.iface, "channel", str(channel)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def resume_hopping(self):
        self.stop_hopping = False

    def stop(self):
        self.running = False

class DeauthDetector:
    def __init__(self, iface, attack_callback, channel_hopper):
        self.iface = iface
        self.attack_callback = attack_callback
        self.channel_hopper = channel_hopper
        self.running = False
        self.setup_db()

    def setup_db(self):
        os.makedirs("/var/lib/brunoido", exist_ok=True)
        self.conn = sqlite3.connect("/var/lib/brunoido/deauth_attacks.db")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                attacker TEXT,
                target TEXT,
                rssi INTEGER,
                channel INTEGER
            )
        """)
        self.conn.commit()

    def start(self):
        self.running = True
        sniff(iface=self.iface,
              prn=self.handle_packet,
              store=False,
              stop_filter=lambda x: not self.running)

    def handle_packet(self, pkt):
        if not pkt.haslayer(Dot11Deauth):
            return
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        attacker_mac = pkt.addr2 or "Unknown"
        target_mac = pkt.addr1 or "Unknown"
        ssid = "<Unbekannt>"
        if pkt.haslayer(Dot11Beacon):
            try:
                ssid_bytes = pkt.info
                ssid = ssid_bytes.decode()
            except:
                ssid = "<Hidden>"

        # Daten für Anzeige und Speicherung
        attack_data = (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attacker_mac,
            target_mac,
            ssid,
            rssi,
            self.channel_hopper.current_channel
        )

        print("Attack erkannt:", attack_data)
        self.log_attack(attack_data)
        self.channel_hopper.focus_on_channel(attack_data[5])
        self.attack_callback(attack_data)

    def log_attack(self, data):
        try:
            self.conn.execute("INSERT INTO attacks VALUES (NULL, ?, ?, ?, ?, ?, ?)", data)
            self.conn.commit()
        except:
            pass

    def stop(self):
        self.running = False
        self.conn.close()

class BrunoidoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Brunoido DeAuth-Guard v2.0")
        self.root.geometry("1000x700")
        self.detector = None
        self.channel_hopper = None
        self.create_widgets()
        self.update_interfaces()

    def create_widgets(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('green.Horizontal.TProgressbar', background='#2ecc71')
        style.configure('yellow.Horizontal.TProgressbar', background='#f39c12')
        style.configure('red.Horizontal.TProgressbar', background='#e74c3c')

        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        control_frame = ttk.LabelFrame(main_frame, text="Steuerung", padding=10)
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Label(control_frame, text="WLAN Adapter:").grid(row=0, column=0)
        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly")
        self.interface_menu.grid(row=0, column=1, padx=5)

        ttk.Label(control_frame, text="Signalstärke:").grid(row=0, column=2)
        self.rssi_var = tk.StringVar(value="--- dBm")
        ttk.Label(control_frame, textvariable=self.rssi_var, width=10).grid(row=0, column=3)

        self.signal_meter = ttk.Progressbar(control_frame, length=100, mode='determinate')
        self.signal_meter.grid(row=0, column=4, padx=5)

        ttk.Button(control_frame, text="↻ Aktualisieren", command=self.update_interfaces).grid(row=0, column=5, padx=5)

        self.start_btn = ttk.Button(control_frame, text="▶ Start", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=6, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="■ Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=7, padx=5)

        # Keine manuelle Simulation, alles automatisch
        # Das System erkennt Attacken und zeigt MAC an

        log_frame = ttk.LabelFrame(main_frame, text="Angriffsprotokoll", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Zeit", "Angreifer", "Ziel", "Signal", "Kanal")
        self.log_view = ttk.Treeview(log_frame, columns=columns, show="headings", height=20)
        for col in columns:
            self.log_view.heading(col, text=col)
            self.log_view.column(col, width=150)

        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_view.yview)
        self.log_view.configure(yscroll=scrollbar.set)
        self.log_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def update_interfaces(self):
        ifaces = WifiScanner.get_interfaces()
        self.interface_menu['values'] = ifaces
        if ifaces:
            self.interface_var.set(ifaces[0])

    def start_monitoring(self):
        iface = self.interface_var.get()
        if not iface:
            messagebox.showerror("Fehler", "Bitte WLAN-Adapter auswählen!")
            return
        if not WifiScanner.enable_monitor_mode(iface):
            messagebox.showerror("Fehler", f"Monitor-Mode auf {iface} fehlgeschlagen!\nBitte anderen Adapter wählen.")
            return
        self.channel_hopper = ChannelHopper(iface)
        self.channel_hopper.start()

        self.detector = DeauthDetector(iface, self.update_display, self.channel_hopper)
        threading.Thread(target=self.detector.start, daemon=True).start()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

    def stop_monitoring(self):
        if self.detector:
            self.detector.stop()
        if self.channel_hopper:
            self.channel_hopper.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        if self.channel_hopper:
            self.channel_hopper.resume_hopping()

    def update_display(self, data):
        # Hier wandeln wir rssi in int um, falls es ein string ist
        rssi_value = data[3]
        try:
            rssi = int(rssi_value)
        except:
            rssi = -100  # fallback
        self.rssi_var.set(f"{rssi} dBm")
        val = max(0, min(100, abs(rssi)))
        self.signal_meter['value'] = val
        if rssi > -60:
            self.signal_meter['style'] = 'green.Horizontal.TProgressbar'
        elif rssi > -75:
            self.signal_meter['style'] = 'yellow.Horizontal.TProgressbar'
        else:
            self.signal_meter['style'] = 'red.Horizontal.TProgressbar'
        # Log
        self.log_view.insert("", 0, values=(
            data[0], data[1], data[2], f"{rssi} dBm", data[5]
        ))

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als Administrator ausführen")
        sys.exit(1)
    root = tk.Tk()
    app = BrunoidoGUI(root)
    root.mainloop()
