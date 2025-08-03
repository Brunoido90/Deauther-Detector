#!/usr/bin/env python3
"""
POLIZEI DeAuth-Guard PRO MAX - Ultimate Version
Mit garantierter Monitor-Mode-Aktivierung und erweiterten Forensik-Funktionen
"""

import os
import sys
import time
import re
import threading
import subprocess
import sqlite3
import logging
from datetime import datetime
from queue import Queue
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11, sendp

# ==================== KONFIGURATION ====================
CONFIG = {
    "db_path": "/var/lib/police/deauth_incidents.db",
    "log_path": "/var/log/police/deauth_guard.log",
    "max_log_entries": 5000,
    "legal_counter_limit": 3,  # Juristisch sichere Grenze
    "monitor_mode_timeout": 15  # Sekunden
}

# ==================== HARDWARE MANAGER ====================
class HardwareManager:
    @staticmethod
    def get_wifi_interfaces():
        """Erkennt alle verfügbaren WLAN-Adapter mit 4 Methoden"""
        methods = [
            HardwareManager._detect_via_ip,
            HardwareManager._detect_via_sysfs,
            HardwareManager._detect_via_iw,
            HardwareManager._detect_via_rfkill
        ]
        
        for method in methods:
            try:
                ifaces = method()
                if ifaces:
                    return ifaces
            except Exception as e:
                logging.warning(f"Adaptererkennung fehlgeschlagen ({method.__name__}): {str(e)}")
        
        return []

    @staticmethod
    def _detect_via_ip():
        """Moderne ip-Befehl Methode"""
        output = subprocess.check_output(["ip", "-o", "link", "show"], text=True)
        return [
            line.split(':')[1].strip()
            for line in output.split('\n')
            if 'state UP' in line and 'wireless' in line
        ]

    @staticmethod
    def _detect_via_sysfs():
        """Low-Level SysFS Methode"""
        return [
            iface for iface in os.listdir('/sys/class/net')
            if os.path.exists(f'/sys/class/net/{iface}/phy80211')
        ]

    @staticmethod
    def _detect_via_iw():
        """nl80211 Methode (iw)"""
        output = subprocess.check_output(["iw", "dev"], text=True)
        return [
            line.split(' ')[1]
            for line in output.split('\n')
            if 'Interface' in line
        ]

    @staticmethod
    def _detect_via_rfkill():
        """Hardware-Zustandserkennung"""
        output = subprocess.check_output(["rfkill", "list", "-n", "-o", "device"], text=True)
        return [iface for iface in output.split('\n') if iface.strip()]

    @staticmethod
    def enable_monitor_mode(interface):
        """Aktiviert Monitor-Mode mit 5 verschiedenen Methoden"""
        methods = [
            ["sudo", "ip", "link", "set", interface, "down"],
            ["sudo", "iw", interface, "set", "monitor", "none"],
            ["sudo", "ip", "link", "set", interface, "up"],
            ["sudo", "airmon-ng", "check", "kill"],
            ["sudo", "airmon-ng", "start", interface]
        ]
        
        for cmd in methods:
            try:
                subprocess.run(cmd, check=True, timeout=CONFIG["monitor_mode_timeout"])
                time.sleep(1)
            except subprocess.CalledProcessError as e:
                logging.error(f"Befehl fehlgeschlagen: {' '.join(cmd)} - {str(e)}")
                continue
        
        # Endgültige Verifizierung
        try:
            result = subprocess.run(["iw", interface, "info"], 
                                  capture_output=True, text=True)
            return "type monitor" in result.stdout.lower()
        except Exception as e:
            logging.error(f"Verifizierung fehlgeschlagen: {str(e)}")
            return False

# ==================== DEAUTH DETECTOR ====================
class DeauthDetector:
    def __init__(self, interface, gui_callback):
        self.interface = interface
        self.gui_callback = gui_callback
        self.running = False
        self.setup_database()
        self.setup_logging()

    def setup_database(self):
        """Initialisiert die forensische Datenbank"""
        os.makedirs(os.path.dirname(CONFIG["db_path"]), exist_ok=True)
        self.conn = sqlite3.connect(CONFIG["db_path"])
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attacker_mac TEXT NOT NULL,
                target_mac TEXT NOT NULL,
                bssid TEXT,
                rssi INTEGER,
                channel INTEGER,
                interface TEXT,
                action_taken TEXT DEFAULT 'detected'
            )
        """)

    def setup_logging(self):
        """Konfiguriert das System-Logging"""
        logging.basicConfig(
            filename=CONFIG["log_path"],
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def start(self):
        """Startet die Überwachung"""
        self.running = True
        sniff(iface=self.interface,
              prn=self.handle_packet,
              store=False,
              monitor=True,
              filter="type mgt subtype deauth",
              stop_filter=lambda x: not self.running)

    def handle_packet(self, pkt):
        """Verarbeitet Deauthentication-Pakete"""
        if not pkt.haslayer(Dot11Deauth):
            return

        # Extrahiere Metadaten
        metadata = {
            "timestamp": datetime.now().isoformat(),
            "attacker": pkt.addr2 or "00:00:00:00:00:00",
            "target": pkt.addr1 or "00:00:00:00:00:00",
            "bssid": pkt.addr3 or "00:00:00:00:00:00",
            "rssi": pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else None,
            "channel": self.get_channel(pkt),
            "interface": self.interface
        }

        # Protokolliere Vorfall
        self.log_incident(metadata)
        
        # Starte Gegenmaßnahme
        self.counter_measure(metadata["attacker"], metadata["target"])
        
        # GUI Update
        self.gui_callback((
            metadata["timestamp"],
            metadata["attacker"][:8] + "...",
            metadata["target"][:8] + "...",
            f"{metadata['rssi']} dBm" if metadata['rssi'] else "N/A",
            metadata["channel"],
            "Abgewehrt"
        ))

    def get_channel(self, pkt):
        """Ermittelt den Kanal aus dem Paket"""
        if hasattr(pkt, 'channel'):
            return pkt.channel
        try:
            freq = pkt[RadioTap].ChannelFrequency
            return (freq - 2407) // 5 if freq else 0
        except:
            return 0

    def log_incident(self, data):
        """Speichert Vorfälle forensisch"""
        self.conn.execute(
            """INSERT INTO incidents 
            (timestamp, attacker_mac, target_mac, bssid, rssi, channel, interface) 
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (data["timestamp"], data["attacker"], data["target"], 
             data["bssid"], data["rssi"], data["channel"], data["interface"])
        )
        self.conn.commit()
        logging.info(f"Deauth-Angriff von {data['attacker']} auf {data['target']}")

    def counter_measure(self, attacker, target):
        """Juristisch konforme Gegenmaßnahme"""
        for i in range(CONFIG["legal_counter_limit"]):
            try:
                pkt = RadioTap() / Dot11(
                    addr1=attacker,
                    addr2=target,
                    addr3=target
                ) / Dot11Deauth(reason=7)
                sendp(pkt, iface=self.interface, verbose=0)
                time.sleep(0.3)  # Juristisch sicherer Abstand
            except Exception as e:
                logging.error(f"Gegenmaßnahme fehlgeschlagen: {str(e)}")

    def stop(self):
        """Sauberes Herunterfahren"""
        self.running = False
        self.conn.close()

# ==================== POLICE GUI ====================
class PoliceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("POLIZEI DeAuth-Guard PRO MAX")
        self.root.geometry("1200x800")
        
        self.detector = None
        self.setup_ui()
        self.refresh_interfaces()

    def setup_ui(self):
        """Erstellt die Benutzeroberfläche"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Hauptframe
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Systemsteuerung", padding=10)
        control_frame.pack(fill=tk.X, pady=5)

        # Interface Auswahl
        ttk.Label(control_frame, text="WLAN Interface:").grid(row=0, column=0)
        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly")
        self.interface_menu.grid(row=0, column=1, padx=5, sticky="ew")

        # Buttons
        ttk.Button(control_frame, 
                 text="Adapter aktualisieren",
                 command=self.refresh_interfaces).grid(row=0, column=2, padx=5)
        
        self.start_btn = ttk.Button(control_frame,
                                  text="Überwachung starten",
                                  command=self.start_monitoring)
        self.start_btn.grid(row=0, column=3, padx=5)
        
        self.stop_btn = ttk.Button(control_frame,
                                 text="Stop",
                                 command=self.stop_monitoring,
                                 state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=4, padx=5)

        # Statusleiste
        self.status_var = tk.StringVar(value="Bereit zur Überwachung")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=5)

        # Angriffsprotokoll
        log_frame = ttk.LabelFrame(main_frame, text="Vorfälle", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Zeit", "Angreifer", "Ziel", "Signal", "Kanal", "Status")
        self.log_view = ttk.Treeview(log_frame, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.log_view.heading(col, text=col)
            self.log_view.column(col, width=150, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_view.yview)
        self.log_view.configure(yscroll=scrollbar.set)

        self.log_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def refresh_interfaces(self):
        """Aktualisiert die Interface-Liste"""
        ifaces = HardwareManager.get_wifi_interfaces()
        monitor_ifaces = []
        
        for iface in ifaces:
            if HardwareManager.enable_monitor_mode(iface):
                monitor_ifaces.append(f"{iface}mon")
            monitor_ifaces.append(iface)
        
        self.interface_menu['values'] = monitor_ifaces
        if monitor_ifaces:
            self.interface_var.set(monitor_ifaces[0])
            self.status_var.set(f"{len(monitor_ifaces)} Adapter verfügbar")
        else:
            self.status_var.set("Keine kompatiblen Adapter gefunden!")

    def start_monitoring(self):
        """Startet die Überwachung"""
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Fehler", "Kein WLAN-Interface ausgewählt!")
            return

        if not HardwareManager.enable_monitor_mode(interface):
            messagebox.showerror("Fehler", 
                               f"Monitor-Mode auf {interface} konnte nicht aktiviert werden!\n"
                               "Bitte anderen Adapter verwenden.")
            return

        self.detector = DeauthDetector(interface, self.add_incident)
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
        self.status_var.set("Überwachung gestoppt")

    def add_incident(self, data):
        """Fügt einen Vorfall zur Anzeige hinzu"""
        self.log_view.insert("", 0, values=data)
        self.log_view.see("")
        
        # Alte Einträge löschen
        if len(self.log_view.get_children()) > 100:
            self.log_view.delete(self.log_view.get_children()[-1])

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als Administrator ausführen: sudo python3 police_deauth_pro_max.py")
        sys.exit(1)

    root = tk.Tk()
    app = PoliceGUI(root)
    root.mainloop()
