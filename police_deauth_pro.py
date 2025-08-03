#!/usr/bin/env python3
"""
POLIZEI DeAuth-Guard PRO mit Live-Adaptererkennung
"""

import os
import sys
import time
import re
import sqlite3
import threading
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11, sendp

# ================= KONFIGURATION =================
DB_FILE = "/var/lib/police/deauth_guard.db"
LOG_FILE = "/var/log/police/deauth_guard.log"
REFRESH_INTERVAL = 5000  # Adapter-Update alle 5 Sekunden

class DeauthMonitor:
    def __init__(self, interface, gui_update_callback):
        self.interface = interface
        self.gui_update = gui_update_callback
        self.running = False
        self.setup_database()

    def setup_database(self):
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
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

        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        
        attack_data = (
            datetime.now().strftime("%H:%M:%S"),
            pkt.addr2[:12] + "...",
            pkt.addr1[:12] + "...",
            f"{rssi} dBm",
            self.get_channel(pkt),
            "ERKANNT"
        )

        self.save_to_db(attack_data)
        self.gui_update(attack_data)

    def get_channel(self, pkt):
        if hasattr(pkt, 'channel'):
            return pkt.channel
        return 0

    def save_to_db(self, data):
        self.conn.execute(
            "INSERT INTO attacks VALUES (?, ?, ?, ?, ?, ?)",
            (data[0], data[1], data[2], int(data[3].split()[0]), data[4], data[5])
        )
        self.conn.commit()

    def stop(self):
        self.running = False
        self.conn.close()

class PoliceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("POLIZEI DeAuth-Guard PRO v2.0")
        self.root.geometry("1000x700")
        
        self.setup_style()
        self.create_widgets()
        
        self.monitor = None
        self.available_interfaces = []
        self.refresh_interfaces()
        
        # Auto-Update für Adapterliste
        self.root.after(REFRESH_INTERVAL, self.auto_refresh)

    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10, 'bold'))
        style.configure('Red.TLabel', foreground='red')
        style.configure('Green.TLabel', foreground='green')

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Adaptersteuerung", padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Interface Auswahl mit Aktualisierungsbutton
        ttk.Label(control_frame, text="WLAN Interface:").grid(row=0, column=0)
        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(control_frame, 
                                         textvariable=self.interface_var,
                                         state="readonly")
        self.interface_menu.grid(row=0, column=1, padx=5, sticky=tk.EW)
        
        self.refresh_btn = ttk.Button(control_frame, 
                                    text="Adapter aktualisieren", 
                                    command=self.refresh_interfaces)
        self.refresh_btn.grid(row=0, column=2, padx=5)
        
        # Start/Stop Buttons
        self.start_btn = ttk.Button(control_frame, 
                                  text="Überwachung starten", 
                                  command=self.start_monitoring)
        self.start_btn.grid(row=0, column=3, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, 
                                 text="Stop", 
                                 command=self.stop_monitoring, 
                                 state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=4, padx=5)
        
        # Signal-Anzeige
        signal_frame = ttk.LabelFrame(main_frame, text="Signalpegel (RSSI)", padding="10")
        signal_frame.pack(fill=tk.X, pady=5)
        
        self.signal_meter = ttk.Progressbar(signal_frame, 
                                          orient=tk.HORIZONTAL, 
                                          length=300, 
                                          mode='determinate')
        self.signal_meter.pack(pady=5)
        
        self.signal_label = ttk.Label(signal_frame, 
                                    text="Kein Signal", 
                                    style='Red.TLabel')
        self.signal_label.pack()
        
        # Angriffsliste
        attack_frame = ttk.LabelFrame(main_frame, text="Letzte Angriffe", padding="10")
        attack_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ("Zeit", "Angreifer", "Ziel", "Signal", "Kanal", "Status")
        self.tree = ttk.Treeview(attack_frame, columns=columns, show="headings")
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor=tk.CENTER)
        
        scrollbar = ttk.Scrollbar(attack_frame, 
                                orient=tk.VERTICAL, 
                                command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Statusleiste
        self.status_var = tk.StringVar(value="Bereit zur Überwachung")
        status_bar = ttk.Label(main_frame, 
                             textvariable=self.status_var, 
                             relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(5,0))

    def get_available_interfaces(self):
        """Erkennt alle verfügbaren WLAN-Adapter mit Monitor-Mode"""
        try:
            # Liste aller Netzwerkinterfaces
            output = subprocess.check_output(["iwconfig"], text=True)
            interfaces = [line.split()[0] for line in output.split('\n') if "IEEE" in line]
            
            # Filtere nur solche mit Monitor-Mode
            monitor_interfaces = []
            for iface in interfaces:
                try:
                    mode = subprocess.check_output(["iw", iface, "info"], text=True)
                    if "monitor" in mode.lower():
                        monitor_interfaces.append(iface)
                except:
                    continue
            
            return monitor_interfaces
            
        except Exception as e:
            print(f"Interface-Erkennungsfehler: {e}")
            return ["wlan0mon", "wlan1mon"]  # Fallback

    def refresh_interfaces(self):
        """Aktualisiert die Interface-Liste"""
        self.available_interfaces = self.get_available_interfaces()
        self.interface_menu['values'] = self.available_interfaces
        
        if self.available_interfaces:
            self.interface_var.set(self.available_interfaces[0])
            self.status_var.set(f"{len(self.available_interfaces)} Adapter gefunden")
        else:
            self.status_var.set("Keine WLAN-Adapter mit Monitor-Mode gefunden!")
            
        return self.available_interfaces

    def auto_refresh(self):
        """Automatische Aktualisierung der Adapterliste"""
        self.refresh_interfaces()
        self.root.after(REFRESH_INTERVAL, self.auto_refresh)

    def start_monitoring(self):
        iface = self.interface_var.get()
        if not iface:
            messagebox.showerror("Fehler", "Bitte WLAN-Interface auswählen!")
            return
        
        self.monitor = DeauthMonitor(iface, self.add_attack)
        threading.Thread(target=self.monitor.start, daemon=True).start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"Überwache {iface}...")

    def stop_monitoring(self):
        if self.monitor:
            self.monitor.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Bereit zur Überwachung")

    def add_attack(self, data):
        self.tree.insert("", 0, values=data)
        rssi = int(data[3].split()[0])
        self.update_signal_meter(rssi)
        
        # Alte Einträge löschen
        if len(self.tree.get_children()) > 100:
            self.tree.delete(self.tree.get_children()[-1])

    def update_signal_meter(self, rssi):
        """Aktualisiert die Signalstärken-Anzeige"""
        percent = max(0, min(100, int((rssi + 90) * 1.67)))
        self.signal_meter["value"] = percent
        
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

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als Administrator ausführen: sudo python3 police_deauth_pro.py")
        sys.exit(1)
        
    root = tk.Tk()
    app = PoliceGUI(root)
    root.mainloop()
