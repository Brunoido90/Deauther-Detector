#!/usr/bin/env python3
"""
DeAuth-Guard Complete
- Stop-Knopf
- WLAN nach Beenden wiederherstellen
sudo python3 deauth_complete.py
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
    HAS_TK = True
except ImportError:
    HAS_TK = False

CFG = {
    "thr": 3,
    "hist": 1,
    "ssid": "🍯_Free_WiFi",
    "chan": 6,
    "log": "/tmp/deauth.log"
}

HISTORY   = {}
MON_IFACE = None
SNIFF_TH  = None
H_PROC    = []

# ---------- UTIL ----------
def run(cmd, cap=False):
    return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip() if cap else subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ifs():
    return run("iw dev | awk '/Interface/ {print $2}'", cap=True).split()

def can_mon(iface):
    phy = run(f"iw dev {iface} info | grep wiphy | awk '{{print $2}}'", cap=True)
    return "monitor" in run(f"iw phy phy{phy} info", cap=True).lower()

def choose():
    env = os.getenv("IFACE")
    if env and env in ifs() and can_mon(env):
        return env
    cand = [i for i in ifs() if can_mon(i)]
    if not cand:
        sys.exit("[!] Kein Monitor-Adapter.")
    for idx, i in enumerate(cand, 1):
        print(f"  {idx}) {i}")
    sel = input("Wählen [1]: ").strip() or "1"
    return cand[int(sel) - 1]

def mon_up(iface):
    run("airmon-ng check kill")
    run(f"airmon-ng start {iface}")
    mon = next((x for x in ifs() if x.endswith("mon")), None)
    run(f"ip link set {mon} up")
    return mon

def mon_down(mon):
    run(f"airmon-ng stop {mon}")
    run("systemctl restart NetworkManager")

def log(mac, rssi, ch):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"{ts} {mac} {rssi} dBm CH:{ch}\n"
    print(line.strip())
    with open(CFG["log"], "a") as f:
        f.write(line)

# ---------- SNIFF ----------
def detect(pkt):
    if not pkt.haslayer(Dot11Deauth):
        return
    mac  = pkt.addr2
    rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else "?"
    ch   = pkt[RadioTap].ChannelFrequency if pkt.haslayer(RadioTap) else "?"
    now  = time.time()
    HISTORY.setdefault(mac, []).append(now)
    HISTORY[mac] = [t for t in HISTORY[mac] if now - t < CFG["hist"]]
    if len(HISTORY[mac]) >= CFG["thr"]:
        HISTORY[mac] = []
        log(mac, rssi, ch)
        GUI.add(mac, rssi, ch)

def sniff_start(iface):
    global SNIFF_TH
    SNIFF_TH = threading.Thread(target=lambda: sniff(iface=iface, prn=detect, store=False, monitor=True), daemon=True)
    SNIFF_TH.start()

def sniff_stop():
    global SNIFF_TH
    if SNIFF_TH and SNIFF_TH.is_alive():
        os._exit(0)   # hart beenden – tkinter & sniff sauber trennen

# ---------- HONEY ----------
def honey_start(iface):
    run(f"ip link set {iface} down && ip link set {iface} up")
    run(f"ip addr flush dev {iface} && ip addr add 192.168.66.1/24 dev {iface}")
    open("/tmp/hg_hostapd.conf", "w").write(f"""
interface={iface}
ssid={CFG["ssid"]}
channel={CFG["chan"]}
driver=nl80211
hw_mode=g
wpa=0
""")
    open("/tmp/hg_dnsmasq.conf", "w").write(f"""
interface={iface}
dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h
""")
    H_PROC.extend([
        subprocess.Popen(["hostapd", "-B", "/tmp/hg_hostapd.conf"]),
        subprocess.Popen(["dnsmasq", "-C", "/tmp/hg_dnsmasq.conf"])
    ])
    print("[+] Honey-AP ON")

def honey_stop():
    run("pkill -f hostapd; pkill -f dnsmasq")
    for p in H_PROC:
        p.terminate()

# ---------- GUI ----------
GUI = None

class MainGUI:
    def __init__(self, root):
        self.root = root
        root.title("DeAuth-Guard Complete")
        root.configure(bg="black")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="black", foreground="#00FF00", fieldbackground="black", font=("Consolas", 11))
        style.map("Treeview", background=[("selected", "#003300")])

        frm = tk.Frame(root, bg="black")
        frm.pack(fill="both", expand=True, padx=10, pady=10)

        self.tree = ttk.Treeview(frm, columns=("Time", "MAC", "RSSI", "CH"), show="headings", height=15)
        for col in ("Time", "MAC", "RSSI", "CH"):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=120, anchor="center")
        self.tree.pack(fill="both", expand=True)

        btn_frm = tk.Frame(frm, bg="black")
        btn_frm.pack(pady=5)

        tk.Button(btn_frm, text="🛑 Stop & Restore WiFi", command=self.stop_all,
                  bg="#AA0000", fg="white", font=("Consolas", 11), width=20).pack(side="left", padx=5)

        tk.Button(btn_frm, text="🍯 Toggle Honey-AP", command=self.toggle_honey,
                  bg="#111", fg="#00FF00", font=("Consolas", 11)).pack(side="left", padx=5)

        self.lbl = tk.Label(frm, text="Ready – waiting for frames …", fg="#00FF00", bg="black", font=("Consolas", 12))
        self.lbl.pack(pady=5)

    def add(self, mac, rssi, ch):
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, f"{rssi} dBm", ch))
        self.lbl.config(text="Live – frames incoming …")

    def toggle_honey(self):
        if not getattr(self, "honey_on", False):
            if CFG.get("honey_iface"):
                honey_start(CFG["honey_iface"])
                self.honey_on = True
                self.lbl.config(text="Honey-AP: ON 🍯")
        else:
            honey_stop()
            self.honey_on = False
            self.lbl.config(text="Honey-AP: OFF")

    def stop_all(self):
        honey_stop()
        mon_down(MON_IFACE)
        self.lbl.config(text="WiFi restored – exiting …")
        self.root.after(1000, lambda: os._exit(0))

# ---------- MAIN ----------
def main():
    base = choose()
    global MON_IFACE
    MON_IFACE = mon_up(base)
    if not MON_IFACE:
        sys.exit("[!] Monitor-Mode Fehler.")

    honey = [i for i in ifs() if i != MON_IFACE and can_mon(i)]
    CFG["honey_iface"] = honey[0] if honey else None

    def cleanup(sig, frame):
        print("\n[!] Restore WiFi & exit …")
        honey_stop()
        mon_down(MON_IFACE)
        sys.exit(0)
    signal.signal(signal.SIGINT, cleanup)

    root = tk.Tk()
    global GUI
    GUI = MainGUI(root)
    sniff_start(MON_IFACE)
    root.mainloop()

if __name__ == "__main__":
    main()
