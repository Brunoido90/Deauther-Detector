#!/usr/bin/env python3
"""
Brunoido DeAuth-Guard mit verbesserter Interface-Erkennung und Fehlerbehandlung.
"""

import os
import sys
import time
import threading
import subprocess
import sqlite3
from datetime import datetime
import pywifi
from scapy.all import sniff, Dot11Deauth, Dot11Beacon
import tkinter as tk
from tkinter import ttk, messagebox

def list_network_interfaces():
    """Listet alle verfügbaren WLAN-Interfaces auf."""
    interfaces = []

    # Über 'iw dev'
    try:
        output = subprocess.check_output(["iw", "dev"], text=True)
        interfaces += [line.split()[1] for line in output.splitlines() if "Interface" in line]
    except Exception as e:
        print(f"Fehler bei 'iw dev': {e}")

    # Über 'ip link'
    try:
        output = subprocess.check_output(["ip", "link"], text=True)
        for line in output.splitlines():
            if ": " in line:
                parts = line.split(": ")
                if len(parts) > 1:
                    iface_name = parts[1].split()[0]
                    if "wlan" in iface_name or "wl" in iface_name:
                        if iface_name not in interfaces:
                            interfaces.append(iface_name)
    except Exception as e:
        print(f"Fehler bei 'ip link': {e}")

    # Falls keine gefunden, Standard-Interfaces hinzufügen
    if not interfaces:
        interfaces.append("wlan0")

    return list(set(interfaces))

def enable_monitor_mode(interface):
    """Aktiviert den Monitor-Modus auf dem Interface."""
    try:
        subprocess.check_call(["sudo", "ip", "link", "set", interface, "down"])
        subprocess.check_call(["sudo", "iw", interface, "set", "monitor", "control"])
        subprocess.check_call(["sudo", "ip", "link", "set", interface, "up"])
        time.sleep(1)
        info = subprocess.getoutput(f"iw {interface} info")
        return "monitor" in info
    except Exception as e:
        print(f"Fehler beim Aktivieren des Monitor-Modus: {e}")
        return False

class ChannelHopper:
    def __init__(self, iface):
        self.iface = iface
        self.running = False
        self.stop_hopping = False
        self.current_channel = 1

    def start(self):
        self.running = True
        threading.Thread(target=self._hop, daemon=True).start()

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

class DeauthDetector:
    def __init__(self, iface, callback, channel_hopper):
        self.iface = iface
        self.callback = callback
        self.channel_hopper = channel_hopper
        self.running = False
        self._setup_db()

    def _setup_db(self):
        os.makedirs("/var/lib/brunoido", exist_ok=True)
        self.conn = sqlite3.connect("/var/lib/brunoido/deauth_attacks.db")
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

    def start(self):
        self.running = True
        sniff(iface=self.iface, prn=self._handle_packet, store=False,
              stop_filter=lambda x: not self.running)

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

        data = (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attacker,
            target,
            ssid,
            rssi,
            self.channel_hopper.current_channel
        )

        print("Attack erkannt:", data)
        self._log_attack(data)
        self.channel_hopper.focus_on(data[5])
        self.callback(data)

    def _log_attack(self, data):
        try:
            self.conn.execute("INSERT INTO attacks VALUES (NULL, ?, ?, ?, ?, ?, ?)", data)
            self.conn.commit()
        except Exception as e:
            print(f"Fehler beim Loggen: {e}")

    def stop(self):
        self.running = False
        self.conn.close()

class BrunoidoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Brunoido DeAuth-Guard v2.0")
        self.root.geometry("1000x700")
        self._init_widgets()
        self._update_interfaces()

    def _init_widgets(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('green.Horizontal.TProgressbar', background='#2ecc71')
        style.configure('yellow.Horizontal.TProgressbar', background='#f39c12')
        style.configure('red.Horizontal.TProgressbar', background='#e74c3c')

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        control = ttk.LabelFrame(main, text="Steuerung", padding=10)
        control.pack(fill=tk.X, pady=5)

        ttk.Label(control, text="WLAN Adapter:").grid(row=0, column=0)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(control, textvariable=self.iface_var, state="readonly")
        self.iface_combo.grid(row=0, column=1, padx=5)

        ttk.Label(control, text="Signalstärke:").grid(row=0, column=2)
        self.rssi_var = tk.StringVar(value="--- dBm")
        ttk.Label(control, textvariable=self.rssi_var, width=10).grid(row=0, column=3)

        self.signal_progress = ttk.Progressbar(control, length=100, mode='determinate')
        self.signal_progress.grid(row=0, column=4, padx=5)

        ttk.Button(control, text="↻ Aktualisieren", command=self._update_interfaces).grid(row=0, column=5, padx=5)

        self.btn_start = ttk.Button(control, text="▶ Start", command=self._start_monitoring)
        self.btn_start.grid(row=0, column=6, padx=5)

        self.btn_stop = ttk.Button(control, text="■ Stop", command=self._stop_monitoring, state=tk.DISABLED)
        self.btn_stop.grid(row=0, column=7, padx=5)

        ttk.Button(control, text="Log exportieren", command=self._export_log).grid(row=0, column=8, padx=5)

        log_frame = ttk.LabelFrame(main, text="Angriffsprotokoll", padding=10)
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
        # Nutze pywifi, um die echten WLAN-Adapter-Namen zu bekommen
        try:
            adapters = list(set([adapter.name() for adapter in pywifi.PyWiFi().interfaces()]))
        except Exception as e:
            print(f"Fehler bei pywifi: {e}")
            adapters = []

        # Falls keine gefunden, auf 'ip link' zurückgreifen
        if not adapters:
            interfaces = list_network_interfaces()
            self.iface_combo['values'] = interfaces
            if interfaces:
                self.iface_var.set(interfaces[0])
            else:
                self.iface_var.set("Kein Interface gefunden")
        else:
            self.iface_combo['values'] = adapters
            self.iface_var.set(adapters[0])

    def _start_monitoring(self):
        iface_name = self.iface_var.get()
        if not iface_name or iface_name == "Kein Interface gefunden":
            messagebox.showerror("Fehler", "Bitte einen WLAN-Adapter auswählen!")
            return
        self.adapter_name = iface_name

        # Monitor-Mode aktivieren
        if not enable_monitor_mode(self.adapter_name):
            messagebox.showerror("Fehler", f"Monitor-Mode auf {self.adapter_name} fehlgeschlagen!\nBitte anderen Adapter wählen.")
            return

        # Kanalhopping starten
        self.channel_hopper = ChannelHopper(self.adapter_name)
        self.channel_hopper.start()

        # Erkennung starten
        self.detector = DeauthDetector(self.adapter_name, self._update_ui, self.channel_hopper)
        threading.Thread(target=self.detector.start, daemon=True).start()

        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)

    def _stop_monitoring(self):
        if hasattr(self, 'detector'):
            self.detector.stop()
        if hasattr(self, 'channel_hopper'):
            self.channel_hopper.stop()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        if hasattr(self, 'channel_hopper'):
            self.channel_hopper.resume()

    def _update_ui(self, data):
        try:
            rssi_value = int(data[3])
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

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als root/Administrator ausführen.")
        sys.exit(1)
    root = tk.Tk()
    app = BrunoidoGUI(root)
    root.mainloop()
