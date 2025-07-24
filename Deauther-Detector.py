#!/usr/bin/env python3
"""
De-Auth Guard – Adapter-Scan & Monitor-Mode Auto
sudo python3 deauth_auto.py
"""
import os, sys, time, threading, subprocess
from datetime import datetime

try:
    from scapy.all import sniff, Dot11Deauth, RadioTap
except ImportError:
    sys.exit("pip install scapy")

try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    tk = None

# ---------- Utility ----------
def run(cmd, capture=False):
    if capture:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def list_wifi_interfaces():
    """Gibt Liste aller WLAN-Interfaces zurück."""
    return run("iw dev | awk '/Interface/ {print $2}'", capture=True).split()

def can_monitor(iface):
    """Prüft, ob Interface Monitor-Mode unterstützt."""
    info = run(f"iw phy $(iw dev {iface} info | grep wiphy | awk '{{print $2}}') info", capture=True)
    return "monitor" in info.lower()

def enter_monitor_mode(iface):
    """Versucht Interface in Monitor-Mode zu bringen."""
    run(f"airmon-ng check kill")
    run(f"airmon-ng start {iface}")
    possible = [i for i in list_wifi_interfaces() if i.endswith("mon") or i == f"{iface}mon"]
    return possible[0] if possible else None

def auto_choose_adapter():
    """Findet ersten fähigen Adapter und bringt ihn in Monitor-Mode."""
    for iface in list_wifi_interfaces():
        if can_monitor(iface):
            mon = enter_monitor_mode(iface)
            if mon:
                print(f"[AUTO] Adapter {iface} → Monitor-Interface {mon}")
                return mon
    sys.exit("[Fehler] Kein Monitor-fähiger WLAN-Adapter gefunden.")

# ---------- Sniffer ----------
HISTORY = {}
CFG = {"threshold": 3, "window": 1}

def detect(pkt):
    if not pkt.haslayer(Dot11Deauth):
        return
    mac = pkt.addr2
    rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else "?"
    now = time.time()
    HISTORY.setdefault(mac, []).append(now)
    HISTORY[mac] = [t for t in HISTORY[mac] if now - t < CFG["window"]]
    if len(HISTORY[mac]) >= CFG["threshold"]:
        HISTORY[mac] = []
        log(mac, rssi)
        if GUI:
            GUI.add_alert(mac, rssi)

def log(mac, rssi):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[ALERT] {ts}  {mac}  RSSI {rssi} dBm")

def start_sniff(mon):
    sniff(iface=mon, prn=detect, store=False)

# ---------- GUI ----------
class App:
    def __init__(self, root):
        self.root = root
        root.title("De-Auth Guard – Auto Adapter")
        frm = ttk.Frame(root, padding=10)
        frm.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(frm, columns=("Time", "MAC", "RSSI"), show="headings")
        for col in ("Time", "MAC", "RSSI"):
            self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True)

    def add_alert(self, mac, rssi):
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, str(rssi)))

# ---------- Main ----------
def main():
    mon = auto_choose_adapter()
    global GUI
    if tk:
        root = tk.Tk()
        GUI = App(root)
        threading.Thread(target=start_sniff, args=(mon,), daemon=True).start()
        root.mainloop()
    else:
        start_sniff(mon)

if __name__ == "__main__":
    main()
