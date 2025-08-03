#!/usr/bin/env python3
"""
DeAuth-Guard PRO mit Signalpegel (RSSI)
"""

import os
import sys
import time
import re
import sqlite3
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11, sendp

# ================= KONFIGURATION =================
DB_FILE = "police_deauth.db"
MAX_ATTACKS = 100  # Maximale Angriffe zur Anzeige

# ================= FUNKTIONEN =================
class DeauthMonitor:
    def __init__(self, interface, gui_update_callback):
        self.interface = interface
        self.gui_update = gui_update_callback
        self.running = False
        self.setup_database()

    def setup_database(self):
        self.conn = sqlite3.connect(DB_FILE)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                attacker TEXT,
                target TEXT,
                rssi INTEGER,
                channel INTEGER,
                action TEXT
            )
        """)

    def start(self):
        self.running = True
        sniff(iface=self.interface,
              prn=self.detect_attack,
              store=False,
              monitor=True)

    def detect_attack(self, pkt):
        if not pkt.haslayer(Dot11Deauth):
            return

        # Signalstärke (RSSI) auslesen
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        
        # Angriffsdaten
        attack_data = (
            datetime.now().strftime("%H:%M:%S"),
            pkt.addr2[:12] + "...",  # Angreifer MAC (gekürzt)
            pkt.addr1[:12] + "...",   # Ziel MAC
            f"{rssi} dBm",             # Signalstärke
            self.get_channel(pkt),     # Kanal
            "ERKANNT"                  # Status
        )

        # Datenbank speichern
        self.save_to_db(attack_data)
        
        # GUI aktualisieren
        self.gui_update(attack_data)

    def get_channel(self, pkt):
        if hasattr(pkt, 'channel'):
            return pkt.channel
        return 0

    def save_to_db(self, data):
        self.conn.execute(
            "INSERT INTO attacks (timestamp, attacker, target, rssi, channel, action) VALUES (?, ?, ?, ?, ?, ?)",
            (data[0], data[1], data[2], int(data[3].split()[0]), data[4], data[5])
        )
        self.conn.commit()

    def stop(self):
        self.running = False
        self.conn.close()

# ================= BENUTZEROBERFLÄCHE =================
class PoliceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("POLIZEI DeAuth-Guard PRO")
        self.root.geometry("1000x700")
        
        # Style
        self.setup_style()
        
        # GUI Elemente
        self.create_widgets()
        
        # Monitor-Thread
        self.monitor = None
        
        # Auto-Update
        self.root.after(500, self.update_gui)

    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10, 'bold'))
        style.configure('Red.TLabel', foreground='red')
        style.configure('Green.TLabel', foreground='green')

    def create_widgets(self):
        # Hauptframe
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Steuerung", padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Interface Auswahl
        ttk.Label(control_frame, text="WLAN Interface:").grid(row=0, column=0)
        self.interface = ttk.Combobox(control_frame, values=self.get_interfaces())
        self.interface.grid(row=0, column=1, padx=5)
        
        # Start/Stop Buttons
        self.start_btn = ttk.Button(control_frame, text="Überwachung starten", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=2, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=3, padx=5)
        
        # Signal-Anzeige
        signal_frame = ttk.LabelFrame(main_frame, text="Signalpegel (RSSI)", padding="10")
        signal_frame.pack(fill=tk.X, pady=5)
        
        self.signal_meter = ttk.Progressbar(signal_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.signal_meter.pack(pady=5)
        
        self.signal_label = ttk.Label(signal_frame, text="Kein Signal", style='Red.TLabel')
        self.signal_label.pack()
        
        # Angriffsliste
        attack_frame = ttk.LabelFrame(main_frame, text="Letzte Angriffe", padding="10")
        attack_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Zeit", "Angreifer", "Ziel", "Signal", "Kanal", "Status")
        self.tree = ttk.Treeview(attack_frame, columns=columns, show="headings")
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor=tk.CENTER)
        
        self.tree.column("Zeit", width=80)
        self.tree.column("Signal", width=100)
        
        scrollbar = ttk.Scrollbar(attack_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Statusleiste
        self.status = ttk.Label(main_frame, text="Bereit zur Überwachung", relief=tk.SUNKEN)
        self.status.pack(fill=tk.X, pady=(5,0))

    def get_interfaces(self):
        try:
            output = subprocess.check_output(["iwconfig"], text=True)
            return [line.split()[0] for line in output.split("\n") if "IEEE" in line]
        except:
            return ["wlan0", "wlan1"]

    def start_monitoring(self):
        iface = self.interface.get()
        if not iface:
            messagebox.showerror("Fehler", "Bitte WLAN-Interface auswählen!")
            return
        
        self.monitor = DeauthMonitor(iface, self.add_attack)
        threading.Thread(target=self.monitor.start, daemon=True).start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text=f"Überwache {iface}...")

    def stop_monitoring(self):
        if self.monitor:
            self.monitor.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.config(text="Bereit zur Überwachung")

    def add_attack(self, data):
        self.tree.insert("", 0, values=data)
        
        # Signalstärke visualisieren
        rssi = int(data[3].split()[0])
        self.update_signal_meter(rssi)
        
        # Alte Einträge löschen
        if len(self.tree.get_children()) > MAX_ATTACKS:
            self.tree.delete(self.tree.get_children()[-1])

    def update_signal_meter(self, rssi):
        # RSSI zu Prozent umrechnen (-30dBm = exzellent, -90dBm = schlecht)
        percent = max(0, min(100, int((rssi + 90) * 1.67))
        self.signal_meter["value"] = percent
        
        # Farbe basierend auf Signalstärke
        if rssi > -60:
            color = "green"
            strength = "Stark"
        elif rssi > -75:
            color = "orange"
            strength = "Mittel"
        else:
            color = "red"
            strength = "Schwach"
        
        self.signal_label.config(
            text=f"{rssi} dBm ({strength})",
            style=f'{color.capitalize()}.TLabel'
        )

    def update_gui(self):
        self.root.after(500, self.update_gui)

# ================= HAUPTPROGRAMM =================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als Administrator ausführen: sudo python3 police_deauth_pro.py")
        sys.exit(1)
        
    root = tk.Tk()
    app = PoliceGUI(root)
    root.mainloop()
