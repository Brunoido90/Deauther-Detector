#!/usr/bin/env python3
import os
import sys
import time
import threading
import subprocess
import sqlite3
from datetime import datetime
import logging

from scapy.all import sniff, Dot11Deauth, Dot11Beacon

import tkinter as tk
from tkinter import ttk, messagebox

# Konfiguration
DB_PATH = "/var/lib/brunoido/deauth_attacks.db"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class MonitorMode:
    @staticmethod
    def enable(iface):
        try:
            print(f"Versuche, {iface} in den Monitor-Modus zu setzen...")
            subprocess.check_call(["sudo", "ip", "link", "set", iface, "down"])
            result = subprocess.run(["iw", iface, "set", "monitor", "control"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                print(f"Fehler beim Setzen in den Monitor-Modus: {result.stderr.strip()}")
                return False
            subprocess.check_call(["sudo", "ip", "link", "set", iface, "up"])
            time.sleep(1)
            info = subprocess.getoutput(f"iw dev {iface} info")
            if "monitor" in info:
                print(f"{iface} ist jetzt im Monitor-Modus.")
                return True
            else:
                print(f"{iface} konnte nicht in den Monitor-Modus gesetzt werden.")
                return False
        except subprocess.CalledProcessError as e:
            print(f"Fehler bei der Ausführung: {e}")
            return False


class InterfaceScanner:
    @staticmethod
    def list_interfaces():
        interfaces = []

        try:
            output = subprocess.check_output(["iw", "dev"], text=True)
            interfaces += [line.split()[1] for line in output.splitlines() if "Interface" in line]
        except Exception as e:
            print(f"iw dev Fehler: {e}")

        try:
            output = subprocess.check_output(["ip", "link"], text=True)
            for line in output.splitlines():
                if ": " in line:
                    parts = line.split(": ")
                    if len(parts) > 1:
                        name = parts[1].split()[0]
                        if ("wlan" in name or "wl" in name) and "p2p" not in name:
                            if name not in interfaces:
                                interfaces.append(name)
        except Exception as e:
            print(f"ip link Fehler: {e}")

        if not interfaces:
            interfaces.append("wlan0")
        return list(set(interfaces))


class ChannelHopper:
    def __init__(self, iface):
        self.iface = iface
        self.running = False
        self.stop_hopping = False
        self.current_channel = 1
        self.thread = None

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._hop, daemon=True)
            self.thread.start()

    def _hop(self):
        channels = range(1, 13)
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

    def focus_on(self, channel):
        self.stop_hopping = True
        subprocess.run(["sudo", "iwconfig", self.iface, "channel", str(channel)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def resume(self):
        self.stop_hopping = False

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()


class AttackLogger:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._setup_db()

    def _setup_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                attacker TEXT,
                target TEXT,
                ssid TEXT,
                rssi INTEGER,
                channel INTEGER
            )
        """)
        self.conn.commit()

    def log_attack(self, timestamp, attacker, target, ssid, rssi, channel):
        try:
            self.conn.execute(
                "INSERT INTO attacks (timestamp, attacker, target, ssid, rssi, channel) VALUES (?, ?, ?, ?, ?, ?)",
                (timestamp, attacker, target, ssid, rssi, channel)
            )
            self.conn.commit()
        except Exception as e:
            print(f"Log Error: {e}")

    def close(self):
        self.conn.close()


class DeauthSniffer:
    def __init__(self, iface, callback, channel_hopper, logger):
        self.iface = iface
        self.callback = callback
        self.channel_hopper = channel_hopper
        self.logger = logger
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._sniff, daemon=True)
        self.thread.start()

    def _sniff(self):
        sniff(iface=self.iface, prn=self._handle_packet, store=False, stop_filter=lambda x: not self.running)

    def _handle_packet(self, pkt):
        if not pkt.haslayer(Dot11Deauth):
            return
        rssi = getattr(pkt, 'dBm_AntSignal', -100)
        attacker = pkt.addr2 or "Unbekannt"
        target = pkt.addr1 or "Unbekannt"
        ssid = "<Unbekannt>"
        if pkt.haslayer(Dot11Beacon):
            try:
                ssid = pkt.info.decode()
            except:
                ssid = "<Versteckt>"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        channel = self.channel_hopper.current_channel

        # Log attack
        self.logger.log_attack(timestamp, attacker, target, ssid, rssi, channel)

        # UI Update via callback
        self.callback((timestamp, attacker, target, ssid, rssi, channel))
        # Kanal fokussieren
        self.channel_hopper.focus_on(channel)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Brunoido DeAuth-Guard v2.0")
        self.root.geometry("1000x700")
        self._init_widgets()

        self.interfaces = []
        self.adapter_name = None
        self.channel_hopper = None
        self.sniffer = None
        self.logger = AttackLogger()

        self._update_interfaces()

        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _init_widgets(self):
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
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(control_frame, textvariable=self.iface_var, state="readonly")
        self.iface_combo.grid(row=0, column=1, padx=5)

        ttk.Label(control_frame, text="Signalstärke:").grid(row=0, column=2)
        self.rssi_var = tk.StringVar(value="--- dBm")
        ttk.Label(control_frame, textvariable=self.rssi_var, width=10).grid(row=0, column=3)

        self.signal_progress = ttk.Progressbar(control_frame, length=100, mode='determinate')
        self.signal_progress.grid(row=0, column=4, padx=5)

        ttk.Button(control_frame, text="↻ Aktualisieren", command=self._update_interfaces).grid(row=0, column=5, padx=5)

        self.btn_start = ttk.Button(control_frame, text="▶ Start", command=self._start)
        self.btn_start.grid(row=0, column=6, padx=5)

        self.btn_stop = ttk.Button(control_frame, text="■ Stop", command=self._stop, state=tk.DISABLED)
        self.btn_stop.grid(row=0, column=7, padx=5)

        ttk.Button(control_frame, text="Log exportieren", command=self._export_log).grid(row=0, column=8, padx=5)

        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Angriffsprotokoll", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Zeit", "Angreifer", "Ziel", "Signal", "Kanal")
        self.log_tree = ttk.Treeview(log_frame, columns=columns, show="headings", height=20)
        for col in columns:
            self.log_tree.heading(col, text=col)
            self.log_tree.column(col, width=150)

        vsb = ttk.Scrollbar(log_frame, orient='vertical', command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=vsb.set)
        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _update_interfaces(self):
        try:
            import pywifi
            wifi = pywifi.PyWiFi()
            interfaces = [iface.name() for iface in wifi.interfaces()]
        except:
            interfaces = []

        if not interfaces:
            interfaces = InterfaceScanner.list_interfaces()

        self.interfaces = interfaces
        self.iface_combo['values'] = self.interfaces
        if self.interfaces:
            self.iface_var.set(self.interfaces[0])
        else:
            self.iface_var.set("Kein Interface gefunden")

    def _start(self):
        iface = self.iface_var.get()
        if not iface or iface == "Kein Interface gefunden":
            messagebox.showerror("Fehler", "Bitte einen WLAN-Adapter auswählen!")
            return
        self.adapter_name = iface

        # Monitor Mode aktivieren
        if not MonitorMode.enable(self.adapter_name):
            messagebox.showerror("Fehler", f"Monitor-Mode auf {self.adapter_name} fehlgeschlagen!")
            return

        # Kanalhopping starten
        self.channel_hopper = ChannelHopper(self.adapter_name)
        self.channel_hopper.start()

        # Sniffer starten
        self.sniffer = DeauthSniffer(self.adapter_name, self._update_ui, self.channel_hopper, self.logger)
        self.sniffer.start()

        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)

    def _stop(self):
        if self.sniffer:
            self.sniffer.stop()
        if self.channel_hopper:
            self.channel_hopper.stop()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        if self.channel_hopper:
            self.channel_hopper.resume()

    def _update_ui(self, data):
        rssi = data[4]
        try:
            rssi_value = int(rssi)
        except:
            rssi_value = -100
        self.rssi_var.set(f"{rssi_value} dBm")
        val = max(0, min(100, abs(rssi_value)))
        self.signal_progress['value'] = val

        if rssi_value > -60:
            style_name = 'green.Horizontal.TProgressbar'
        elif rssi_value > -75:
            style_name = 'yellow.Horizontal.TProgressbar'
        else:
            style_name = 'red.Horizontal.TProgressbar'
        self.signal_progress['style'] = style_name

        self.log_tree.insert("", 0, values=(
            data[0], data[1], data[2], f"{rssi_value} dBm", data[5]
        ))

    def _export_log(self):
        filename = "brunoido_attack_log.csv"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("Zeit,Angreifer,Ziel,Signal,Kanal\n")
                for item in self.log_tree.get_children():
                    values = self.log_tree.item(item, "values")
                    line = ",".join(f'"{v}"' for v in values)
                    f.write(line + "\n")
            messagebox.showinfo("Erfolg", f"Log wurde exportiert nach {filename}")
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Export: {e}")

    def _on_closing(self):
        print("Programm wird beendet...")
        if hasattr(self, 'sniffer') and self.sniffer:
            self.sniffer.stop()
        if hasattr(self, 'channel_hopper') and self.channel_hopper:
            self.channel_hopper.stop()
        self.root.destroy()


if __name__ == "__main__":
    # Prüfen auf Root-Rechte
    if os.geteuid() != 0:
        print("Bitte das Programm als root ausführen (z.B. sudo).")
        sys.exit(1)

    # Monitor Modus aktivieren auf wlan1
    interface_name = "wlan1"
    if not MonitorMode.enable(interface_name):
        print(f"Fehler: Monitor-Modus auf {interface_name} konnte nicht aktiviert werden.")
        sys.exit(1)

    # GUI starten
    root = tk.Tk()
    app = GUI(root)
    root.protocol("WM_DELETE_WINDOW", app._on_closing)
    root.mainloop()
