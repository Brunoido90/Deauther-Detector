#!/usr/bin/env python3
"""
POLIZEI DeAuth-Guard ELITE - Ultimate Version
Mit erweiterten Funktionen für den professionellen Einsatz
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
from queue import Queue, Empty
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11, sendp, get_if_hwaddr
from scapy.arch import get_if_raw_hwaddr

# ==================== KONFIGURATION ====================
CONFIG = {
    "db_path": "/var/lib/police/deauth_incidents.db",
    "log_path": "/var/log/police/deauth_guard.log",
    "max_log_entries": 1000,
    "auto_refresh_interval": 10,  # Sekunden
    "legal_limit": 3  # Max. erlaubte Gegenpakete
}

# ==================== FORENSIC LOGGER ====================
class ForensicLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(CONFIG["log_path"]), exist_ok=True)
        logging.basicConfig(
            filename=CONFIG["log_path"],
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.console_handler = logging.StreamHandler()
        self.console_handler.setLevel(logging.WARNING)
        logging.getLogger().addHandler(self.console_handler)

    @staticmethod
    def log_incident(incident_data):
        logging.info(f"INCIDENT: {incident_data}")

# ==================== HARDWARE MANAGER ====================
class HardwareManager:
    @staticmethod
    def get_interfaces():
        """Intelligente Adaptererkennung mit Priorisierung"""
        detection_methods = [
            HardwareManager._detect_via_ip,
            HardwareManager._detect_via_sysfs,
            HardwareManager._detect_via_iw,
            HardwareManager._detect_via_rfkill
        ]

        for method in detection_methods:
            try:
                ifaces = method()
                if ifaces:
                    return ifaces
            except Exception as e:
                logging.warning(f"Adaptererkennung fehlgeschlagen ({method.__name__}): {str(e)}")
        
        return ["wlan0"]  # Garantierter Fallback

    @staticmethod
    def _detect_via_ip():
        """Modernste Methode mit iproute2"""
        output = subprocess.run(["ip", "-o", "link", "show"], 
                              capture_output=True, text=True, check=True).stdout
        return [
            line.split(':')[1].strip()
            for line in output.split('\n')
            if 'state UP' in line and 'wireless' in line
        ]

    @staticmethod
    def _detect_via_sysfs():
        """Low-Level SysFS Erkennung"""
        return [
            iface for iface in os.listdir('/sys/class/net')
            if os.path.exists(f'/sys/class/net/{iface}/phy80211')
        ]

    @staticmethod
    def _detect_via_iw():
        """nl80211 Methode"""
        output = subprocess.run(["iw", "dev"], 
                              capture_output=True, text=True, check=True).stdout
        return [
            line.split(' ')[1]
            for line in output.split('\n')
            if 'Interface' in line
        ]

    @staticmethod
    def _detect_via_rfkill():
        """Hardware-Zustandserkennung"""
        output = subprocess.run(["rfkill", "list", "-n", "-o", "device"], 
                              capture_output=True, text=True, check=True).stdout
        return [iface for iface in output.split('\n') if iface.strip()]

    @staticmethod
    def enable_monitor_mode(interface):
        """Aktiviert Monitor-Mode mit automatischer Methode"""
        activation_sequence = [
            (["sudo", "ip", "link", "set", interface, "down"], 1),
            (["sudo", "iw", interface, "set", "monitor", "control"], 2),
            (["sudo", "ip", "link", "set", interface, "up"], 1),
            (["sudo", "airmon-ng", "check", "kill"], 3),
            (["sudo", "airmon-ng", "start", interface], 5)
        ]

        for cmd, wait_time in activation_sequence:
            try:
                subprocess.run(cmd, check=True, timeout=10)
                time.sleep(wait_time)
            except subprocess.CalledProcessError as e:
                logging.error(f"Befehl fehlgeschlagen: {' '.join(cmd)} - {str(e)}")
                continue

        # Verifizierung
        try:
            result = subprocess.run(["iw", interface, "info"], 
                                  capture_output=True, text=True)
            return "type monitor" in result.stdout.lower()
        except:
            return False

# ==================== DEAUTH DETECTOR ====================
class DeauthDetector:
    def __init__(self, interface, gui_callback):
        self.interface = interface
        self.gui_callback = gui_callback
        self.running = False
        self.incident_count = 0
        self.db = self._init_database()
        self.logger = ForensicLogger()

    def _init_database(self):
        """Initialisiert die forensische Datenbank"""
        os.makedirs(os.path.dirname(CONFIG["db_path"]), exist_ok=True)
        conn = sqlite3.connect(CONFIG["db_path"])
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attacker_mac TEXT NOT NULL,
                target_mac TEXT NOT NULL,
                bssid TEXT,
                rssi INTEGER,
                channel INTEGER,
                interface TEXT,
                action_taken TEXT
            )
        """)
        return conn

    def start(self):
        """Startet die Überwachung mit erweiterten Filtern"""
        self.running = True
        sniff(iface=self.interface,
              prn=self._analyze_packet,
              store=False,
              monitor=True,
              filter="type mgt subtype deauth",
              stop_filter=lambda x: not self.running)

    def _analyze_packet(self, packet):
        """Erweiterte Paketanalyse mit forensischer Protokollierung"""
        if not packet.haslayer(Dot11Deauth):
            return

        # Extrahiere Metadaten
        metadata = {
            "timestamp": datetime.utcnow().isoformat(),
            "attacker": packet.addr2 or "00:00:00:00:00:00",
            "target": packet.addr1 or "00:00:00:00:00:00",
            "bssid": packet.addr3 or "00:00:00:00:00:00",
            "rssi": packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None,
            "channel": self._get_channel(packet),
            "interface": self.interface
        }

        # Protokolliere Vorfall
        self._log_incident(metadata)
        
        # Starte legale Gegenmaßnahme
        self._counter_measure(metadata["attacker"], metadata["target"])
        
        # GUI Update
        self.gui_callback((
            metadata["timestamp"],
            metadata["attacker"][:8] + "...",
            metadata["target"][:8] + "...",
            f"{metadata['rssi']} dBm" if metadata['rssi'] else "N/A",
            metadata["channel"],
            "Abgewehrt"
        ))

    def _get_channel(self, packet):
        """Kanalerkennung mit erweiterten Methoden"""
        if hasattr(packet, 'channel'):
            return packet.channel
        try:
            freq = packet[RadioTap].ChannelFrequency
            return (freq - 2407) // 5 if freq else 0
        except:
            return 0

    def _log_incident(self, data):
        """Forensische Protokollierung"""
        self.db.execute(
            """INSERT INTO incidents 
            (timestamp, attacker_mac, target_mac, bssid, rssi, channel, interface, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (data["timestamp"], data["attacker"], data["target"], 
             data["bssid"], data["rssi"], data["channel"], 
             data["interface"], "counter_measure")
        )
        self.db.commit()
        self.logger.log_incident(data)
        self.incident_count += 1

        # Automatische Datenbankwartung
        if self.incident_count % 100 == 0:
            self._cleanup_database()

    def _cleanup_database(self):
        """Automatische Datenbankoptimierung"""
        self.db.execute(
            f"DELETE FROM incidents WHERE id NOT IN "
            f"(SELECT id FROM incidents ORDER BY timestamp DESC LIMIT {CONFIG['max_log_entries']})"
        )
        self.db.commit()

    def _counter_measure(self, attacker, target):
        """Juristisch konforme Gegenmaßnahme"""
        for _ in range(CONFIG["legal_limit"]):
            try:
                pkt = RadioTap() / Dot11(
                    addr1=attacker,
                    addr2=target,
                    addr3=target
                ) / Dot11Deauth(reason=7)
                sendp(pkt, iface=self.interface, verbose=0)
                time.sleep(0.2)  # Juristisch sicherer Abstand
            except Exception as e:
                logging.error(f"Gegenmaßnahme fehlgeschlagen: {str(e)}")

    def stop(self):
        """Sauberes Herunterfahren"""
        self.running = False
        self.db.close()

# ==================== POLICE GUI ====================
class PoliceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"POLIZEI DeAuth-Guard ELITE v2.{os.getpid() % 100}")
        self.root.geometry("1200x800")
        self._setup_styles()
        self._create_ui()
        
        self.detector = None
        self.interface_list = []
        self._auto_refresh()

    def _setup_styles(self):
        """Modernes GUI-Design"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f0f2f5')
        style.configure('TLabel', background='#f0f2f5', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10, 'bold'), padding=5)
        style.configure('Header.TLabel', font=('Helvetica', 14, 'bold'))
        style.configure('Red.TLabel', foreground='#e74c3c')
        style.configure('Green.TLabel', foreground='#2ecc71')
        style.map('Treeview', background=[('selected', '#3498db')])

    def _create_ui(self):
        """Erstellt die Benutzeroberfläche"""
        # Hauptcontainer
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(header, text="POLIZEI DeAuth-Guard ELITE", style='Header.TLabel').pack(side=tk.LEFT)
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Systemsteuerung", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 15))

        # Interface Auswahl
        ttk.Label(control_frame, text="Aktives Interface:").grid(row=0, column=0, sticky="w", padx=5)
        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly")
        self.interface_menu.grid(row=0, column=1, sticky="ew", padx=5)

        # Control Buttons
        self.refresh_btn = ttk.Button(control_frame, text="↻ Aktualisieren", command=self._refresh_interfaces)
        self.refresh_btn.grid(row=0, column=2, padx=5)

        self.start_btn = ttk.Button(control_frame, text="▶ Überwachung starten", command=self._start_monitoring)
        self.start_btn.grid(row=0, column=3, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="■ Stopp", command=self._stop_monitoring, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=4, padx=5)

        # Statusleiste
        self.status_var = tk.StringVar(value="System initialisiert")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(0, 15))

        # Incident Log
        log_frame = ttk.LabelFrame(main_frame, text="Vorfälle", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Zeit", "Angreifer", "Ziel", "Signal", "Kanal", "Status")
        self.log_view = ttk.Treeview(log_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.log_view.heading(col, text=col)
            self.log_view.column(col, width=150, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_view.yview)
        self.log_view.configure(yscroll=scrollbar.set)

        self.log_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Kontextmenü
        self._setup_context_menu()

    def _setup_context_menu(self):
        """Rechtsklick-Menü für erweiterte Funktionen"""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Exportieren als CSV", command=self._export_to_csv)
        self.context_menu.add_command(label="MAC-Info suchen", command=self._lookup_mac)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Protokolle anzeigen", command=self._show_logs)
        
        self.log_view.bind("<Button-3>", self._show_context_menu)

    def _refresh_interfaces(self):
        """Aktualisiert die Interface-Liste"""
        self.interface_list = HardwareManager.get_interfaces()
        self.interface_menu['values'] = self.interface_list
        
        if self.interface_list:
            self.interface_var.set(self.interface_list[0])
            self.status_var.set(f"{len(self.interface_list)} WLAN-Adapter erkannt")
        else:
            self.status_var.set("Keine WLAN-Adapter gefunden!")

    def _auto_refresh(self):
        """Automatische Aktualisierung der Adapterliste"""
        self._refresh_interfaces()
        self.root.after(CONFIG["auto_refresh_interval"] * 1000, self._auto_refresh)

    def _start_monitoring(self):
        """Startet die Überwachung mit automatischer Konfiguration"""
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Fehler", "Kein WLAN-Interface ausgewählt!")
            return

        if not HardwareManager.enable_monitor_mode(interface):
            messagebox.showerror("Fehler", 
                               f"Monitor-Mode konnte auf {interface} nicht aktiviert werden!\n"
                               "Bitte andere Hardware verwenden.")
            return

        self.detector = DeauthDetector(interface, self._add_incident)
        threading.Thread(target=self.detector.start, daemon=True).start()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"Überwachung aktiv auf {interface}")

    def _stop_monitoring(self):
        """Stoppt die Überwachung sauber"""
        if self.detector:
            self.detector.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Überwachung gestoppt")

    def _add_incident(self, data):
        """Fügt einen neuen Vorfall zur Anzeige hinzu"""
        self.log_view.insert("", 0, values=data)
        
        # Automatisches Scrollen und Highlighting
        self.log_view.see("")
        self.log_view.selection_set("")
        
        # Alte Einträge löschen
        if len(self.log_view.get_children()) > 100:
            self.log_view.delete(self.log_view.get_children()[-1])

    def _show_context_menu(self, event):
        """Zeigt das Kontextmenü an"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _export_to_csv(self):
        """Exportiert die Vorfälle als CSV"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Dateien", "*.csv"), ("Alle Dateien", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write("Zeit,Angreifer,Ziel,Signal,Kanal,Status\n")
                    for item in self.log_view.get_children():
                        values = self.log_view.item(item)['values']
                        f.write(','.join(str(v) for v in values) + '\n')
                messagebox.showinfo("Erfolg", f"Daten erfolgreich nach {file_path} exportiert!")
            except Exception as e:
                messagebox.showerror("Fehler", f"Export fehlgeschlagen: {str(e)}")

    def _lookup_mac(self):
        """Sucht MAC-Adressen-Informationen"""
        selected = self.log_view.selection()
        if not selected:
            messagebox.showwarning("Hinweis", "Kein Eintrag ausgewählt!")
            return
        
        mac = self.log_view.item(selected[0])['values'][1]  # Angreifer-MAC
        try:
            subprocess.run(["xdg-open", f"https://macvendors.com/query/{mac}"])
        except:
            messagebox.showerror("Fehler", "Browser konnte nicht geöffnet werden!")

    def _show_logs(self):
        """Zeigt die Systemprotokolle an"""
        try:
            subprocess.run(["xdg-open", CONFIG["log_path"]])
        except:
            messagebox.showerror("Fehler", "Protokolldatei konnte nicht geöffnet werden!")

# ==================== MAIN ====================
if __name__ == "__main__":
    # Root-Check
    if os.geteuid() != 0:
        print("Bitte als Administrator ausführen: sudo python3 police_deauth_elite.py")
        sys.exit(1)

    # GUI starten
    root = tk.Tk()
    try:
        app = PoliceGUI(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Kritischer Fehler: {str(e)}")
        messagebox.showerror("Systemfehler", f"Das Programm muss beendet werden:\n{str(e)}")
        sys.exit(1)
