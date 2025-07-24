#!/usr/bin/env python3
"""
De-Auth Guard – vollautomatisch
sudo python3 deauth_guard_auto.py
"""
import os, sys, time, threading, subprocess, json
from datetime import datetime

try:
    from scapy.all import sniff, Dot11Deauth, RadioTap
except ImportError:
    sys.exit("Fehler: pip install scapy")

try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    tk = None

# ------------------ CONFIG ------------------
CFG = {
    "deauth_threshold": 3,
    "history_seconds": 1,
    "honey_ssid": "HoneyWiFi",
    "honey_channel": 6,
}
# -------------------------------------------

HISTORY = {}
HONEY_PROC = []

# ---------- Utility ----------
def run(cmd, capture=False):
    if capture:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def detect_interfaces():
    """Gibt Liste aller physischen WLAN-Interfaces zurück."""
    out = run("iw dev | awk '/Interface/ {print $2}'", capture=True)
    return out.split()

def find_monitor_candidate():
    """Erstes Interface, das AP/Monitor kann."""
    for iface in detect_interfaces():
        info = run(f"iw dev {iface} info", capture=True)
        if "type managed" in info or "type AP" in info:
            return iface
    return None

def enter_monitor_mode(iface):
    """Erzeugt *mon* Interface und gibt Namen zurück."""
    run(f"airmon-ng check kill")
    run(f"airmon-ng start {iface}")
    mon = f"{iface}mon"
    if mon in detect_interfaces():
        return mon
    # fallback falls airmon-ng einfach wlan0mon erzeugt
    for cand in detect_interfaces():
        if cand.endswith("mon"):
            return cand
    return None

# ---------- Sniffer ----------
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
        log(mac, rssi)
        if GUI:
            GUI.add_alert(mac, rssi)

def log(mac, rssi):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[ALERT] {ts}  {mac}  RSSI {rssi}")
    with open("deauth_log.txt", "a") as f:
        f.write(f"{ts} {mac} {rssi}\n")

def start_sniff(mon):
    print(f"[INFO] Starte Sniffer auf {mon}")
    sniff(iface=mon, prn=detect, store=False)

# ---------- Honey-AP ----------
def start_honey(iface):
    run(f"ip link set {iface} down")
    run(f"ip link set {iface} up")
    run(f"ip addr flush dev {iface}")
    run(f"ip addr add 192.168.66.1/24 dev {iface}")

    hostapd_conf = f"""
interface={iface}
ssid={CFG["honey_ssid"]}
channel={CFG["honey_channel"]}
driver=nl80211
hw_mode=g
wpa=0
"""
    dnsmasq_conf = f"""
interface={iface}
dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h
"""
    open("/tmp/hostapd.conf", "w").write(hostapd_conf)
    open("/tmp/dnsmasq.conf", "w").write(dnsmasq_conf)

    HONEY_PROC.extend([
        subprocess.Popen(["hostapd", "-B", "/tmp/hostapd.conf"]),
        subprocess.Popen(["dnsmasq", "-C", "/tmp/dnsmasq.conf"])
    ])
    print(f"[INFO] Honey-AP läuft – SSID: {CFG['honey_ssid']}")

def stop_honey():
    run("pkill -f hostapd")
    run("pkill -f dnsmasq")
    for p in HONEY_PROC:
        p.terminate()

# ---------- GUI ----------
class App:
    def __init__(self, root):
        self.root = root
        root.title("De-Auth Guard – auto")
        frm = ttk.Frame(root, padding=10)
        frm.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(frm, columns=("Time", "MAC", "RSSI"), show="headings")
        for col in ("Time", "MAC", "RSSI"):
            self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True)

        ttk.Button(frm, text="Honey-AP starten", command=self.toggle_honey).pack(pady=5)
        self.lbl = ttk.Label(frm, text="Honey-AP: Aus")
        self.lbl.pack()

    def add_alert(self, mac, rssi):
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, str(rssi)))

    def toggle_honey(self):
        if not hasattr(self, "honey_on") or not self.honey_on:
            start_honey(CFG["honey_iface"])
            self.honey_on = True
            self.lbl.config(text="Honey-AP: An")
        else:
            stop_honey()
            self.honey_on = False
            self.lbl.config(text="Honey-AP: Aus")

# ---------- Main ----------
def main():
    # 1. Monitor-Interface automatisch erzeugen
    base = find_monitor_candidate()
    if not base:
        sys.exit("Kein WLAN-Interface gefunden.")
    mon = enter_monitor_mode(base)
    if not mon:
        sys.exit("Monitor-Mode konnte nicht aktiviert werden.")
    CFG["monitor_iface"] = mon

    # 2. Zweites Interface als Honey-AP (falls vorhanden)
    ifaces = detect_interfaces()
    honey_candidates = [i for i in ifaces if i != mon and not i.endswith("mon")]
    CFG["honey_iface"] = honey_candidates[0] if honey_candidates else None

    # 3. GUI oder CLI starten
    global GUI
    if tk:
        root = tk.Tk()
        GUI = App(root)
        threading.Thread(target=start_sniff, args=(mon,), daemon=True).start()
        try:
            root.mainloop()
        finally:
            stop_honey()
    else:
        print("Kein Tkinter – CLI-Modus")
        start_sniff(mon)

if __name__ == "__main__":
    main()
