#!/usr/bin/env python3
"""
GUI: De-Auth-Detektor + HoneyBot
sudo python3 gui.py
"""
import tkinter as tk
from tkinter import ttk
import threading, subprocess, os
from datetime import datetime
import deauth_sniffer as ds   # importiert auch die Sniffer-Logik

MONITOR_IFACE = "wlan0mon"

class DeauthGUI:
    def __init__(self, root):
        self.root = root
        root.title("De-Auth Detektor + HoneyBot")
        self.alerts = []

        frm = ttk.Frame(root, padding=10)
        frm.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(frm, columns=("Time", "MAC", "RSSI"), show="headings")
        self.tree.heading("Time", text="Zeit")
        self.tree.heading("MAC", text="Attacker MAC")
        self.tree.heading("RSSI", text="RSSI (dBm)")
        self.tree.pack(fill="both", expand=True)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="HoneyBot starten", command=self.start_honey).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Beenden", command=self.quit).pack(side="left", padx=5)

        self.honey_status = ttk.Label(frm, text="HoneyBot: Aus")
        self.honey_status.pack()

    def add_alert(self, mac, rssi):
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, str(rssi)))
        self.alerts.append((ts, mac, str(rssi)))

    def start_honey(self):
        def run():
            subprocess.run(["sudo", "python3", "honey_ap.py"])
        threading.Thread(target=run, daemon=True).start()
        self.honey_status.config(text="HoneyBot: An (SSID HoneyWiFi)")

    def quit(self):
        self.root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = DeauthGUI(root)

    # GUI-Callback in Sniffer injizieren
    ds.gui_callback = app.add_alert

    # Sniffer starten (Thread)
    threading.Thread(target=ds.start_sniff, args=(MONITOR_IFACE,), daemon=True).start()

    root.mainloop()
