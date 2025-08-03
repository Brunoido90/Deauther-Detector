#!/usr/bin/env python3
"""
POLIZEI DeAuth-Guard PRO mit Signalpegelanzeige
"""

import os
import sys
import time
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import sqlite3
from datetime import datetime
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11

class WifiScanner:
    @staticmethod
    def get_interfaces():
        """Listet WLAN-Adapter ohne Modusänderung"""
        try:
            output = subprocess.check_output(["iw", "dev"], text=True)
            return [line.split()[1] for line in output.split("\n") if "Interface" in line]
        except:
            return ["wlan0"]  # Fallback

    @staticmethod
    def enable_monitor_mode(interface):
        """Aktiviert Monitor-Mode mit Rückmeldung"""
        cmds = [
            ["sudo", "ip", "link", "set", interface, "down"],
            ["sudo", "iw", interface, "set", "monitor", "control"],
            ["sudo", "ip", "link", "set", interface, "up"]
        ]
        
        for cmd in cmds:
            try:
                subprocess.run(cmd, check=True, timeout=10)
                time.sleep(1)
            except subprocess.CalledProcessError:
                return False
        
        return "monitor" in subprocess.getoutput(f"iw {interface} info")

class DeauthDetector:
    def __init__(self, interface, callback):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.setup_db()

    def setup_db(self):
        """Datenbank für forensische Aufzeichnungen"""
        os.makedirs("/var/lib/police", exist_ok=True)
        self.conn = sqlite3.connect("/var/lib/police/deauth_attacks.db")
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

    def start(self):
        """Startet die Überwachung mit RSSI-Erfassung"""
        self.running = True
        sniff(iface=self.interface,
              prn=self.handle_packet,
              store=False,
              monitor=True,
              stop_filter=lambda x: not self.running)

    def handle_packet(self, pkt):
        """Verarbeitet Pakete mit Signalstärke-Messung"""
        if not pkt.haslayer(Dot11Deauth):
            return

        # RSSI aus RadioTap-Header extrahieren
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        
        attack_data = (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            pkt.addr2 or "Unknown",
            pkt.addr1 or "Unknown",
            rssi,
            self.get_channel(pkt)
        )

        self.log_attack(attack_data)
        self.callback(attack_data)

    def get_channel(self, pkt):
        """Ermittelt den Kanal aus der Frequenz"""
        if hasattr(pkt[RadioTap], 'ChannelFrequency'):
            return pkt[RadioTap].ChannelFrequency // 1000
        return 0

    def log_attack(self, data):
        """Speichert Angriffe mit Signalstärke"""
        self.conn.execute("INSERT INTO attacks VALUES (NULL, ?, ?, ?, ?, ?)", data)
        self.conn.commit()

    def stop(self):
        """Stoppt die Überwachung sauber"""
        self.running = False
        self.conn.close()

class PoliceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("POLIZEI DeAuth-Guard v2.0")
        self.root.geometry("1000x700")
        
        self.detector = None
        self.create_widgets()
        self.update_interfaces()

    def create_widgets(self):
        """Erstellt die Benutzeroberfläche mit Signalpegel-Anzeige"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Hauptframe
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Steuerung", padding=10)
        control_frame.pack(fill=tk.X, pady=5)

        # Interface Auswahl
        ttk.Label(control_frame, text="WLAN Adapter:").grid(row=0, column=0)
        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly")
        self.interface_menu.grid(row=0, column=1, padx=5)

        # Signalpegel-Anzeige
        ttk.Label(control_frame, text="Signalstärke:").grid(row=0, column=2)
        self.rssi_var = tk.StringVar(value="--- dBm")
        ttk.Label(control_frame, textvariable=self.rssi_var, width=10).grid(row=0, column=3)

        # Fortschrittsbalken für visuelle Darstellung
        self.signal_meter = ttk.Progressbar(control_frame, length=100, mode='determinate')
        self.signal_meter.grid(row=0, column=4, padx=5)

        # Buttons
        ttk.Button(control_frame, 
                 text="↻ Aktualisieren",
                 command=self.update_interfaces).grid(row=0, column=5, padx=5)
        
        self.start_btn = ttk.Button(control_frame,
                                  text="▶ Start",
                                  command=self.start_monitoring)
        self.start_btn.grid(row=0, column=6, padx=5)
        
        self.stop_btn = ttk.Button(control_frame,
                                 text="■ Stop",
                                 command=self.stop_monitoring,
                                 state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=7, padx=5)

        # Angriffsprotokoll
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
        """Aktualisiert die Adapterliste ohne Modusänderung"""
        ifaces = WifiScanner.get_interfaces()
        self.interface_menu['values'] = ifaces
        if ifaces:
            self.interface_var.set(ifaces[0])

    def start_monitoring(self):
        """Startet die Überwachung nach expliziter Bestätigung"""
        iface = self.interface_var.get()
        if not iface:
            messagebox.showerror("Fehler", "Bitte WLAN-Adapter auswählen!")
            return

        if not WifiScanner.enable_monitor_mode(iface):
            messagebox.showerror("Fehler", 
                               f"Monitor-Mode auf {iface} fehlgeschlagen!\n"
                               "Bitte anderen Adapter wählen.")
            return

        self.detector = DeauthDetector(iface, self.update_display)
        threading.Thread(target=self.detector.start, daemon=True).start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

    def stop_monitoring(self):
        """Stoppt die Überwachung"""
        if self.detector:
            self.detector.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def update_display(self, data):
        """Aktualisiert die Anzeige mit Signalpegel"""
        # RSSI-Anzeige aktualisieren
        rssi = data[3]
        self.rssi_var.set(f"{rssi} dBm")
        
        # Fortschrittsbalken (0 bis -100 dBm)
        self.signal_meter['value'] = max(0, min(100, abs(rssi)))
        
        # Farbliche Kennzeichnung
        if rssi > -60:
            self.signal_meter['style'] = 'green.Horizontal.TProgressbar'
        elif rssi > -75:
            self.signal_meter['style'] = 'yellow.Horizontal.TProgressbar'
        else:
            self.signal_meter['style'] = 'red.Horizontal.TProgressbar'
        
        # Log-Eintrag hinzufügen
        self.log_view.insert("", 0, values=(
            data[0],  # Zeit
            data[1][:8] + "...",  # Angreifer (gekürzt)
            data[2][:8] + "...",  # Ziel (gekürzt)
            f"{rssi} dBm",
            data[4]   # Kanal
        ))
        self.log_view.see("")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als Administrator ausführen: sudo python3 police_deauth_pro.py")
        sys.exit(1)

    root = tk.Tk()
    
    # Style für den Fortschrittsbalken
    style = ttk.Style()
    style.configure('green.Horizontal.TProgressbar', background='#2ecc71')
    style.configure('yellow.Horizontal.TProgressbar', background='#f39c12')
    style.configure('red.Horizontal.TProgressbar', background='#e74c3c')
    
    app = PoliceGUI(root)
    root.mainloop()
