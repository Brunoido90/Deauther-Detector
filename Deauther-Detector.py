#!/usr/bin/env python3
"""
DEAUTH-GUARD MIT GUI
Einsatzversion 3.0 - Optimiert für einfache Bedienung
"""

import os
import sys
import time
import re
import subprocess
import sqlite3
from datetime import datetime
import logging
from queue import Queue
import threading
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11, sendp
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ===================== KONFIGURATION =====================
class Config:
    DB_PATH = "/var/lib/police/deauth_guard.db"
    LOG_FILE = "/var/log/police/deauth_guard.log"
    MAX_COUNTER_ATTACKS = 3  # Juristisch sicher
    CHANNELS = [1, 6, 11]    # Standard-Kanäle

# ===================== HAUPTLOGIK =====================
class DeauthDefender(threading.Thread):
    def __init__(self, interface, gui_queue):
        super().__init__(daemon=True)
        self.interface = interface
        self.gui_queue = gui_queue
        self.running = False
        self.setup_logging()
        self.setup_database()

    def setup_logging(self):
        logging.basicConfig(
            filename=Config.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def setup_database(self):
        os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(Config.DB_PATH)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                attacker TEXT,
                target TEXT,
                channel INTEGER,
                action TEXT
            )
        """)

    def run(self):
        self.running = True
        sniff(iface=self.interface,
              prn=self.handle_packet,
              store=False,
              filter="type mgt subtype deauth",
              stop_filter=lambda x: not self.running)

    def handle_packet(self, pkt):
        if not pkt.haslayer(Dot11Deauth):
            return

        attacker = pkt.addr2
        target = pkt.addr1

        if not self.validate_macs(attacker, target):
            return

        channel = self.get_channel(pkt)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Logge Angriff
        self.log_attack(timestamp, attacker, target, channel)
        
        # Starte Gegenmaßnahme
        self.counter_attack(attacker, target)
        
        # GUI Update
        self.gui_queue.put((
            timestamp,
            attacker,
            target,
            channel,
            "Abgewehrt"
        ))

    def counter_attack(self, attacker, target):
        for _ in range(Config.MAX_COUNTER_ATTACKS):
            pkt = RadioTap() / Dot11(addr1=attacker, addr2=target, addr3=target) / Dot11Deauth()
            sendp(pkt, iface=self.interface, verbose=0)
            time.sleep(0.2)

    def log_attack(self, timestamp, attacker, target, channel):
        self.conn.execute(
            "INSERT INTO attacks (timestamp, attacker, target, channel, action) VALUES (?, ?, ?, ?, ?)",
            (timestamp, attacker, target, channel, "Abgewehrt")
        )
        self.conn.commit()

    def validate_macs(self, *macs):
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return all(mac_pattern.match(mac) for mac in macs if mac)

    def get_channel(self, pkt):
        if hasattr(pkt, 'channel'):
            return int(pkt.channel)
        return -1

    def stop(self):
        self.running = False
        self.conn.close()

# ===================== BENUTZEROBERFLÄCHE =====================
class PoliceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("POLIZEI DeAuth-Guard v3.0")
        self.root.geometry("1200x800")
        self.setup_ui()
        
        self.defender = None
        self.gui_queue = Queue()
        self.update_interval = 500  # ms
        
        # Starte GUI-Updates
        self.root.after(self.update_interval, self.process_queue)

    def setup_ui(self):
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10, 'bold'))
        
        # Hauptframe
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Steuerung", padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Interface Auswahl
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W)
        self.interface_var = tk.StringVar()
        interfaces = self.get_wifi_interfaces()
        self.interface_menu = ttk.Combobox(control_frame, textvariable=self.interface_var, values=interfaces)
        self.interface_menu.grid(row=0, column=1, padx=5, sticky=tk.EW)
        
        # Start/Stop Buttons
        self.start_btn = ttk.Button(control_frame, text="Start", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=2, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=3, padx=5)
        
        # Angriffsanzeige
        attack_frame = ttk.LabelFrame(main_frame, text="Angriffsprotokoll", padding="10")
        attack_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview für Angriffe
        self.tree = ttk.Treeview(attack_frame, columns=('Time', 'Attacker', 'Target', 'Channel', 'Action'), show='headings')
        self.tree.heading('Time', text='Zeit')
        self.tree.heading('Attacker', text='Angreifer MAC')
        self.tree.heading('Target', text='Ziel MAC')
        self.tree.heading('Channel', text='Kanal')
        self.tree.heading('Action', text='Aktion')
        
        self.tree.column('Time', width=150)
        self.tree.column('Attacker', width=200)
        self.tree.column('Target', width=200)
        self.tree.column('Channel', width=80)
        self.tree.column('Action', width=100)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(attack_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Statusleiste
        self.status_var = tk.StringVar(value="Bereit. Wählen Sie ein Interface und klicken Sie auf Start.")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(5,0))

    def get_wifi_interfaces(self):
        try:
            output = subprocess.check_output(['iw', 'dev'], text=True)
            return [line.split(' ')[1] for line in output.split('\n') if 'Interface' in line]
        except:
            return ['wlan0', 'wlan1']  # Fallback

    def start_monitoring(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Fehler", "Bitte wählen Sie ein Interface aus!")
            return
        
        # Starte Defender im Hintergrund
        self.defender = DeauthDefender(interface, self.gui_queue)
        self.defender.start()
        
        # UI Updates
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"Überwache {interface}...")
        
        # Lade vorhandene Angriffe
        self.load_existing_attacks()

    def stop_monitoring(self):
        if self.defender:
            self.defender.stop()
            self.defender.join()
            self.defender = None
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Bereit. Überwachung gestoppt.")

    def process_queue(self):
        try:
            while True:
                data = self.gui_queue.get_nowait()
                self.tree.insert('', tk.END, values=data)
                self.tree.yview_moveto(1)  # Scroll nach unten
        except Empty:
            pass
        
        self.root.after(self.update_interval, self.process_queue)

    def load_existing_attacks(self):
        if not self.defender:
            return
            
        try:
            cursor = self.defender.conn.cursor()
            cursor.execute("SELECT timestamp, attacker, target, channel, action FROM attacks ORDER BY timestamp DESC LIMIT 100")
            
            for row in cursor.fetchall():
                self.tree.insert('', tk.END, values=row)
                
        except sqlite3.Error as e:
            logging.error(f"Datenbankfehler: {str(e)}")

# ===================== HAUPTPROGRAMM =====================
if __name__ == "__main__":
    # Root-Check
    if os.geteuid() != 0:
        print("Bitte als Root ausführen! (sudo erforderlich)")
        sys.exit(1)
        
    # GUI starten
    root = tk.Tk()
    app = PoliceGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        if app.defender:
            app.defender.stop()
        root.destroy()
