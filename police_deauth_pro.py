#!/usr/bin/env python3
"""
POLIZEI DeAuth-Guard ULTIMATIVE
Automatisierte WLAN-Überwachung mit garantierter Adaptererkennung
"""

import os
import sys
import time
import threading
import subprocess
import sqlite3
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11, sendp

# ================= KONFIGURATION =================
DB_PATH = "/var/lib/police/deauth_attacks.db"
LOG_PATH = "/var/log/police/deauth_guard.log"
UPDATE_INTERVAL = 5000  # Adapter-Check alle 5 Sekunden

class NetworkManager:
    @staticmethod
    def get_wifi_adapters():
        """Erkennt alle WLAN-Adapter mit 4 verschiedenen Methoden"""
        methods = [
            NetworkManager._get_via_ip_link,
            NetworkManager._get_via_sysfs,
            NetworkManager._get_via_iwconfig,
            NetworkManager._get_via_hardware
        ]
        
        for method in methods:
            try:
                adapters = method()
                if adapters:
                    return adapters
            except:
                continue
        return ["wlan0"]  # Notfall-Fallback

    @staticmethod
    def _get_via_ip_link():
        """Moderne Methode mit ip-Befehl"""
        output = subprocess.check_output(["ip", "link", "show"], text=True)
        return [
            line.split(':')[1].split()[0]
            for line in output.split('\n')
            if 'state UP' in line and 'wireless' in line
        ]

    @staticmethod
    def _get_via_sysfs():
        """Linux Kernel SysFS Methode"""
        return [
            iface for iface in os.listdir('/sys/class/net')
            if os.path.exists(f'/sys/class/net/{iface}/wireless')
        ]

    @staticmethod
    def _get_via_iwconfig():
        """Legacy Wireless Extensions"""
        output = subprocess.check_output(["iwconfig"], text=True, stderr=subprocess.DEVNULL)
        return [line.split()[0] for line in output.split('\n') if "IEEE" in line]

    @staticmethod
    def _get_via_hardware():
        """Low-Level Hardware-Erkennung"""
        adapters = []
        # PCI-Adapter
        if os.path.exists('/usr/bin/lspci'):
            output = subprocess.check_output(["lspci"], text=True)
            adapters += [
                f"wlp{idx}s0"
                for idx, line in enumerate(output.split('\n'))
                if 'Network controller' in line
            ]
        # USB-Adapter
        output = subprocess.check_output(["lsusb"], text=True)
        adapters += [
            f"wlx{line.split()[5].replace(':', '')}"
            for line in output.split('\n')
            if 'Wireless' in line
        ]
        return adapters

    @staticmethod
    def enable_monitor_mode(interface):
        """Aktiviert Monitor-Mode mit allen verfügbaren Methoden"""
        methods = [
            ["sudo", "ip", "link", "set", interface, "down"],
            ["sudo", "iw", interface, "set", "monitor", "control"],
            ["sudo", "ip", "link", "set", interface, "up"],
            ["sudo", "airmon-ng", "check", "kill"],
            ["sudo", "airmon-ng", "start", interface],
            ["sudo", "ifconfig", interface, "down"],
            ["sudo", "iwconfig", interface, "mode", "monitor"],
            ["sudo", "ifconfig", interface, "up"]
        ]
        
        for cmd in methods:
            try:
                subprocess.run(cmd, check=True, timeout=10)
                time.sleep(1)
            except:
                continue
        
        # Erfolgsprüfung
        try:
            result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
            return "Mode:Monitor" in result.stdout
        except:
            return False

class DeauthDetector:
    def __init__(self, interface, status_callback):
        self.interface = interface
        self.status_callback = status_callback
        self.running = False
        self.setup_database()

    def setup_database(self):
        """Initialisiert die forensische Datenbank"""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attacker_mac TEXT NOT NULL,
                target_mac TEXT NOT NULL,
                bssid TEXT,
                rssi INTEGER,
                channel INTEGER
            )
        """)

    def start(self):
        """Startet die Überwachung"""
        self.running = True
        sniff(iface=self.interface,
              prn=self.handle_packet,
              store=False,
              monitor=True,
              stop_filter=lambda x: not self.running)

    def handle_packet(self, packet):
        """Verarbeitet Deauth-Pakete"""
        if packet.haslayer(Dot11Deauth):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            attacker = packet.addr2 or "Unknown"
            target = packet.addr1 or "Unknown"
            bssid = packet.addr3 or "Unknown"
            rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -100
            channel = self.get_channel(packet)

            self.log_attack(timestamp, attacker, target, bssid, rssi, channel)
            self.status_callback(
                f"Angriff erkannt! {attacker[:8]}... → {target[:8]}... (Kanal: {channel})"
            )

    def get_channel(self, packet):
        """Extrahiert den Kanal aus dem Paket"""
        if hasattr(packet, 'channel'):
            return packet.channel
        return 0

    def log_attack(self, timestamp, attacker, target, bssid, rssi, channel):
        """Speichert Angriffe in der Datenbank"""
        self.conn.execute(
            "INSERT INTO attacks VALUES (NULL, ?, ?, ?, ?, ?, ?)",
            (timestamp, attacker, target, bssid, rssi, channel)
        )
        self.conn.commit()

    def stop(self):
        """Stoppt die Überwachung"""
        self.running = False
        self.conn.close()

class PoliceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("POLIZEI DeAuth-Guard PRO")
        self.root.geometry("1000x700")
        self.setup_ui()
        
        self.detector = None
        self.auto_refresh()

    def setup_ui(self):
        """Erstellt die Benutzeroberfläche"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Hauptframe
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Adaptersteuerung", padding=10)
        control_frame.pack(fill=tk.X, pady=5)

        # Interface Auswahl
        ttk.Label(control_frame, text="WLAN Interface:").grid(row=0, column=0, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(control_frame, textvariable=self.interface_var)
        self.interface_menu.grid(row=0, column=1, padx=5, sticky="ew")

        # Buttons
        self.refresh_btn = ttk.Button(control_frame, text="Aktualisieren", command=self.refresh_adapters)
        self.refresh_btn.grid(row=0, column=2, padx=5)

        self.start_btn = ttk.Button(control_frame, text="Start", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=3, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=4, padx=5)

        # Status Anzeige
        self.status_var = tk.StringVar(value="Bereit zur Überwachung")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=5)

        # Angriffsprotokoll
        attack_frame = ttk.LabelFrame(main_frame, text="Letzte Angriffe", padding=10)
        attack_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Zeit", "Angreifer", "Ziel", "BSSID", "Signal", "Kanal")
        self.tree = ttk.Treeview(attack_frame, columns=columns, show="headings", height=15)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(attack_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def refresh_adapters(self):
        """Aktualisiert die Liste der WLAN-Adapter"""
        adapters = NetworkManager.get_wifi_adapters()
        monitor_adapters = []

        for adapter in adapters:
            if NetworkManager.enable_monitor_mode(adapter):
                monitor_adapters.append(f"{adapter}mon")
            monitor_adapters.append(adapter)

        self.interface_menu['values'] = monitor_adapters
        if monitor_adapters:
            self.interface_var.set(monitor_adapters[0])
            self.status_var.set(f"{len(monitor_adapters)} Adapter verfügbar")
        else:
            self.status_var.set("Keine WLAN-Adapter gefunden!")

    def auto_refresh(self):
        """Automatische Adapter-Aktualisierung"""
        self.refresh_adapters()
        self.root.after(UPDATE_INTERVAL, self.auto_refresh)

    def start_monitoring(self):
        """Startet die DeAuth-Überwachung"""
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Fehler", "Kein WLAN-Interface ausgewählt!")
            return

        self.detector = DeauthDetector(interface, self.update_status)
        threading.Thread(target=self.detector.start, daemon=True).start()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"Überwache {interface}...")

    def stop_monitoring(self):
        """Stoppt die Überwachung"""
        if self.detector:
            self.detector.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Bereit zur Überwachung")

    def update_status(self, message):
        """Aktualisiert die Statusanzeige"""
        self.status_var.set(message)
        self.root.update()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als Administrator ausführen: sudo python3 police_deauth_ultimate.py")
        sys.exit(1)

    root = tk.Tk()
    app = PoliceGUI(root)
    root.mainloop()
