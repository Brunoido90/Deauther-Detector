#!/usr/bin/env python3
"""
DeAuth-Guard Pro – Signal-Stärke im GUI
sudo python3 deauth_pro.py
"""
import os, sys, time, threading, subprocess, signal
from datetime import datetime

try:
    from scapy.all import sniff, Dot11Deauth, RadioTap
except ImportError:
    sys.exit("[!] pip3 install scapy")

try:
    import tkinter as tk
    from tkinter import ttk
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

CFG = {
    "deauth_threshold": 3,
    "history_seconds": 1,
    "honey_ssid": "🍯_Free_WiFi",
    "honey_channel": 6,
    "log_file": "/tmp/deauth_alerts.log"
}

HISTORY = {}
MON_IFACE = None
HONEY_PROC = []
GUI = None

def run(cmd, capture=False):
    if capture:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def interfaces():
    return run("iw dev | awk '/Interface/ {print $2}'", capture=True).split()

def phy_info(iface):
    phy = run(f"iw dev {iface} info | grep wiphy | awk '{{print $2}}'", capture=True)
    return run(f"iw phy phy{phy} info", capture=True)

def can_monitor(iface):
    return "monitor" in phy_info(iface).lower()

def choose_adapter():
    candidates = [i for i in interfaces() if can_monitor(i)]
    if not candidates:
        sys.exit("[!] Kein Monitor-fähiger WLAN-Adapter gefunden.")
    env = os.getenv("IFACE")
    if env and env in candidates:
        return env
    print("\n[+] Verfügbare WLAN-Adapter:")
    for idx, iface in enumerate(candidates, 1):
        print(f"  {idx}) {iface}")
    sel = input("\nAdapter wählen [1]: ").strip() or "1"
    try:
        return candidates[int(sel) - 1]
    except (IndexError, ValueError):
        sys.exit("[!] Ungültige Auswahl.")

def enable_monitor(iface):
    run("airmon-ng check kill")
    run(f"airmon-ng start {iface}")
    return next((i for i in interfaces() if i.endswith("mon")), None)

def disable_monitor(mon):
    run(f"airmon-ng stop {mon}")
    run("systemctl restart NetworkManager")

def log_event(mac, rssi, ch):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"{ts}  {mac}  RSSI:{rssi}dBm  CH:{ch}\n"
    print(line.strip())
    with open(CFG["log_file"], "a") as f:
        f.write(line)

def detect(pkt):
    if not pkt.haslayer(Dot11Deauth):
        return
    mac = pkt.addr2
    rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else "?"
    ch = pkt[RadioTap].ChannelFrequency if pkt.haslayer(RadioTap) else "?"
    now = time.time()
    HISTORY.setdefault(mac, []).append(now)
    HISTORY[mac] = [t for t in HISTORY[mac] if now - t < CFG["history_seconds"]]
    if len(HISTORY[mac]) >= CFG["deauth_threshold"]:
        HISTORY[mac] = []
        log_event(mac, rssi, ch)
        if HAS_GUI and GUI:
            GUI.add(mac, rssi, ch)

def start_sniffer(iface):
    sniff(iface=iface, prn=detect, store=False)

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
    open("/tmp/hg_hostapd.conf", "w").write(hostapd_conf)
    open("/tmp/hg_dnsmasq.conf", "w").write(dnsmasq_conf)
    HONEY_PROC.extend([
        subprocess.Popen(["hostapd", "-B", "/tmp/hg_hostapd.conf"]),
        subprocess.Popen(["dnsmasq", "-C", "/tmp/hg_dnsmasq.conf"])
    ])
    print(f"[+] Honey-AP '{CFG['honey_ssid']}' läuft auf {iface}")

def stop_honey():
    run("pkill -f hostapd")
    run("pkill -f dnsmasq")
    for p in HONEY_PROC:
        p.terminate()

class GUI:
    def __init__(self, root):
        self.root = root
        root.title("DeAuth-Guard Pro")
        frm = ttk.Frame(root, padding=10)
        frm.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(frm, columns=("Time", "MAC", "RSSI", "CH"), show="headings")
        for col in ("Time", "MAC", "RSSI", "CH"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(fill="both", expand=True)

        ttk.Button(frm, text="Honey-AP start/stop", command=self.toggle_honey).pack(pady=5)
        self.lbl = ttk.Label(frm, text="Honey-AP: Aus")
        self.lbl.pack()

    def add(self, mac, rssi, ch):
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, str(rssi), str(ch)))

    def toggle_honey(self):
        if not hasattr(self, "honey_on") or not self.honey_on:
            if CFG.get("honey_iface"):
                start_honey(CFG["honey_iface"])
                self.honey_on = True
                self.lbl.config(text="Honey-AP: An")
        else:
            stop_honey()
            self.honey_on = False
            self.lbl.config(text="Honey-AP: Aus")

def main():
    print(r"""
   ____          _    ____ _   _ _____ ____  
  |  _ \  ___   / \  / ___| | | | ____/ ___| 
  | | | |/ _ \ / _ \| |   | |_| |  _| \___ \ 
  | |_| | (_) / ___ \ |___|  _  | |___ ___) |
  |____/ \___/_/   \_\____|_| |_|_____|____/  v1.1
          -= Live De-Auth Detector & HoneyPot =-
    """)
    base = choose_adapter()
    MON_IFACE = enable_monitor(base)
    if not MON_IFACE:
        sys.exit("[!] Monitor-Mode konnte nicht aktiviert werden.")
    honey = [i for i in interfaces() if i != MON_IFACE and can_monitor(i)]
    CFG["honey_iface"] = honey[0] if honey else None

    def cleanup(sig, frame):
        print("\n[!] Räume auf…")
        stop_honey()
        disable_monitor(MON_IFACE)
        sys.exit(0)
    signal.signal(signal.SIGINT, cleanup)

    global GUI
    if HAS_GUI:
        root = tk.Tk()
        GUI = GUI(root)
        threading.Thread(target=start_sniffer, args=(MON_IFACE,), daemon=True).start()
        root.mainloop()
    else:
        start_sniffer(MON_IFACE)

if __name__ == "__main__":
    main()
