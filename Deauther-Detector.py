#!/usr/bin/env python3
"""
DeAuth-Guard Elite – vollständiger, getesteter One-Shot
sudo python3 deauth_elite.py
"""
import os, sys, time, threading, subprocess, signal, traceback
from datetime import datetime

# ---------- Scapy ----------
try:
    from scapy.all import sniff, Dot11Deauth, RadioTap
except ImportError:
    sys.exit("[!] pip3 install scapy")

# ---------- Tkinter ----------
try:
    import tkinter as tk
    from tkinter import ttk
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

# ---------- Config ----------
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

# ---------- Utility ----------
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
    env = os.getenv("IFACE")
    if env and env in interfaces() and can_monitor(env):
        return env
    candidates = [i for i in interfaces() if can_monitor(i)]
    if not candidates:
        sys.exit("[!] Kein Monitor-fähiger WLAN-Adapter.")
    print("\n[+] Adapter:")
    for idx, iface in enumerate(candidates, 1):
        print(f"  {idx}) {iface}")
    sel = input("\nWählen [1]: ").strip() or "1"
    try:
        return candidates[int(sel) - 1]
    except (IndexError, ValueError):
        sys.exit("[!] Ungültig.")

def enable_monitor(iface):
    run("airmon-ng check kill")
    run(f"airmon-ng start {iface}")
    return next((i for i in interfaces() if i.endswith("mon")), None)

def disable_monitor(mon):
    run(f"airmon-ng stop {mon}")
    run("systemctl restart NetworkManager")

def log_event(mac, rssi, ch):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"{ts}  {mac}  RSSI:{rssi} dBm  CH:{ch}\n"
    print(line.strip())
    with open(CFG["log_file"], "a") as f:
        f.write(line)

# ---------- Sniffer ----------
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
    try:
        sniff(iface=iface, prn=detect, store=False)
    except Exception as e:
        print("[!] Sniffer-Fehler:", e)

# ---------- Honey ----------
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

# ---------- Elite GUI ----------
class EliteGUI:
    def __init__(self, root):
        self.root = root
        root.title("DeAuth-Guard Elite")
        root.configure(bg="black")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background="black",
                        foreground="#00FF00",
                        fieldbackground="black",
                        font=("Consolas", 11))
        style.map("Treeview", background=[("selected", "#003300")])
        style.configure("Treeview.Heading",
                        background="#111",
                        foreground="#00FF00",
                        font=("Consolas", 11, "bold"))

        frm = tk.Frame(root, bg="black")
        frm.pack(fill="both", expand=True, padx=10, pady=10)

        self.tree = ttk.Treeview(frm, columns=("Time", "MAC", "RSSI", "CH"), show="headings", height=15)
        for col in ("Time", "MAC", "RSSI", "CH"):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=120, anchor="center")
        self.tree.pack(fill="both", expand=True)

        self.lbl = tk.Label(frm, text="Honey-AP: OFF", fg="#00FF00", bg="black", font=("Consolas", 12))
        self.lbl.pack(pady=5)

        btn = tk.Button(frm, text="🍯 Toggle Honey-AP", command=self.toggle_honey,
                        bg="#111", fg="#00FF00", font=("Consolas", 11), relief="flat", overrelief="groove")
        btn.pack(pady=5)

    def add(self, mac, rssi, ch):
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, f"{rssi} dBm", ch))
        self.tree.yview_moveto(1)

    def toggle_honey(self):
        if not hasattr(self, "honey_on") or not self.honey_on:
            if CFG.get("honey_iface"):
                start_honey(CFG["honey_iface"])
                self.honey_on = True
                self.lbl.config(text="Honey-AP: ON 🍯")
        else:
            stop_honey()
            self.honey_on = False
            self.lbl.config(text="Honey-AP: OFF")

# ---------- MAIN ----------
def main():
    print(r"""
   ____          _    ____ _   _ _____ ____  
  |  _ \  ___   / \  / ___| | | | ____/ ___| 
  | | | |/ _ \ / _ \| |   | |_| |  _| \___ \ 
  | |_| | (_) / ___ \ |___|  _  | |___ ___) |
  |____/ \___/_/   \_\____|_| |_|_____|____/  v1.2
          -= Live De-Auth Detector & HoneyPot =-
    """)
    base = choose_adapter()
    MON_IFACE = enable_monitor(base)
    if not MON_IFACE:
        sys.exit("[!] Monitor-Mode Fehler.")
    honey = [i for i in interfaces() if i != MON_IFACE and can_monitor(i)]
    CFG["honey_iface"] = honey[0] if honey else None

    def cleanup(sig, frame):
        print("\n[!] Cleanup…")
        stop_honey()
        disable_monitor(MON_IFACE)
        sys.exit(0)
    signal.signal(signal.SIGINT, cleanup)

    root = tk.Tk()
    global GUI
    GUI = EliteGUI(root)
    threading.Thread(target=start_sniffer, args=(MON_IFACE,), daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    main()
