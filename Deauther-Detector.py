#!/usr/bin/env python3
"""
De-Auth Guard
Live-De-Auth-Detektor + optionaler Honey-AP (GUI)
sudo python3 deauth_guard.py
"""

import os, sys, time, threading, subprocess, json
from datetime import datetime

try:
    from scapy.all import sniff, Dot11Deauth, RadioTap
except ImportError:
    print("Fehler: 'scapy' nicht gefunden.  pip install scapy")
    sys.exit(1)

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except ImportError:
    tk = None  # CLI-Modus, falls kein GUI möglich

# ------------------ CONFIG ------------------
CFG = {
    "monitor_iface": "wlan0mon",
    "honey_iface":   "wlan1",
    "honey_ssid":    "HoneyWiFi",
    "honey_channel": 6,
    "deauth_threshold": 3,       # Frames pro Sekunde
    "history_seconds": 1,
}
# -------------------------------------------

HISTORY = {}          # {mac: [timestamps]}
HONEY_PROC = []       # laufende Prozesse

# ---------- Helper ----------
def run(cmd):
    subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def is_monitor(iface):
    try:
        return "type monitor" in os.popen(f"iw dev {iface} info").read()
    except:
        return False

# ---------- De-Auth Sniffer ----------
def detect(pkt):
    if not pkt.haslayer(Dot11Deauth):
        return
    mac = pkt.addr2
    rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else "?"
    now = time.time()
    HISTORY.setdefault(mac, []).append(now)
    HISTORY[mac] = [t for t in HISTORY[mac] if now - t < CFG["history_seconds"]]
    if len(HISTORY[mac]) >= CFG["deauth_threshold"]:
        HISTORY[mac] = []
        log_event(mac, rssi)
        if GUI:
            GUI.add_alert(mac, rssi)

def log_event(mac, rssi):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[ALERT] {ts}  {mac}  RSSI {rssi} dBm")
    with open("deauth_log.txt", "a") as f:
        f.write(f"{ts} {mac} {rssi}\n")

def start_sniff():
    if not is_monitor(CFG["monitor_iface"]):
        print("Interface nicht im Monitor-Modus – versuche airmon-ng start")
        run(f"airmon-ng start {CFG['monitor_iface'].replace('mon','')}")
        if not is_monitor(CFG["monitor_iface"]):
            print("Abbruch: Monitor-Mode nicht verfügbar")
            sys.exit(1)
    print(f"[INFO] Sniffing auf {CFG['monitor_iface']} …")
    sniff(iface=CFG["monitor_iface"], prn=detect, store=False)

# ---------- Honey-AP ----------
def start_honey():
    iface = CFG["honey_iface"]
    run(f"ip link set {iface} down")
    run(f"ip link set {iface} up")
    run(f"ip addr flush dev {iface}")
    run(f"ip addr add 192.168.66.1/24 dev {iface}")

    # hostapd
    hconf = f"""
interface={iface}
ssid={CFG["honey_ssid"]}
channel={CFG["honey_channel"]}
driver=nl80211
hw_mode=g
ignore_broadcast_ssid=0
auth_algs=1
wpa=0
"""
    with open("/tmp/hostapd.conf", "w") as f:
        f.write(hconf)
    HONEY_PROC.append(subprocess.Popen(["hostapd", "-B", "/tmp/hostapd.conf"]))

    # dnsmasq
    dconf = f"""
interface={iface}
dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h
address=/#/192.168.66.1
"""
    with open("/tmp/dnsmasq.conf", "w") as f:
        f.write(dconf)
    HONEY_PROC.append(subprocess.Popen(["dnsmasq", "-C", "/tmp/dnsmasq.conf"]))
    print("[INFO] Honey-AP läuft – SSID:", CFG["honey_ssid"])

def stop_honey():
    for p in HONEY_PROC:
        p.terminate()
    run("pkill -f hostapd")
    run("pkill -f dnsmasq")
    print("[INFO] Honey-AP gestoppt")

# ---------- GUI ----------
class App:
    def __init__(self, root):
        self.root = root
        root.title("De-Auth Guard")
        frm = ttk.Frame(root, padding=10)
        frm.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(frm, columns=("Time", "MAC", "RSSI"), show="headings")
        for col in ("Time", "MAC", "RSSI"):
            self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True)

        btn = ttk.Button(frm, text="Honey-AP start/stop", command=self.toggle_honey)
        btn.pack(pady=5)
        self.honey_on = False
        self.label = ttk.Label(frm, text="Honey-AP: Aus")
        self.label.pack()

    def add_alert(self, mac, rssi):
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, str(rssi)))

    def toggle_honey(self):
        if not self.honey_on:
            start_honey()
            self.honey_on = True
            self.label.config(text="Honey-AP: An")
        else:
            stop_honey()
            self.honey_on = False
            self.label.config(text="Honey-AP: Aus")

# ---------- Main ----------
def main():
    if not is_monitor(CFG["monitor_iface"]):
        print("Monitor-Interface nicht gefunden – bitte anpassen in CFG")
        sys.exit(1)

    global GUI
    if tk:
        root = tk.Tk()
        GUI = App(root)
        threading.Thread(target=start_sniff, daemon=True).start()
        try:
            root.mainloop()
        finally:
            stop_honey()
    else:
        print("Kein Tkinter – starte CLI-Modus")
        start_sniff()

if __name__ == "__main__":
    main()
