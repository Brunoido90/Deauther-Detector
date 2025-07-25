#!/usr/bin/env python3
"""
DeAuth-Guard FINAL – komplett, stabil, RSSI garantiert
sudo python3 deauth_final.py
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
    GUI_READY = True
except ImportError:
    GUI_READY = False

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
    print("\n[+] Adapter:")
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
    line = f"{ts} {mac} {rssi} dBm CH:{ch}"
    print(line)
    with open(CFG["log"], "a") as f:
        f.write(line + "\n")

# ---------- SNIFF ----------
def detect(pkt):
    if not pkt.haslayer(Dot11Deauth):
        return
    mac  = pkt.addr2
    rssi = "N/A"
    ch   = "N/A"
    if pkt.haslayer(RadioTap):
        rssi = str(pkt[RadioTap].dBm_AntSignal) if pkt[RadioTap].dBm_AntSignal is not None else "N/A"
        freq = pkt[RadioTap].ChannelFrequency if pkt[RadioTap].ChannelFrequency else 0
        if 2412 <= freq <= 2484:
            ch = str((freq - 2412) // 5 + 1)
        else:
            ch = str(freq)
    log(mac, rssi, ch)
    if GUI:
        GUI.add(mac, rssi, ch)

def sniff_start(iface):
    global SNIFF_TH
    SNIFF_TH = threading.Thread(target=lambda: sniff(iface=iface, prn=detect, store=False, monitor=True), daemon=True)
    SNIFF_TH.start()

def sniff_stop():
    global SNIFF_TH
    if SNIFF_TH and SNIFF_TH.is_alive():
        os._exit(0)

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
    subprocess.run(["hostapd", "-B", "/tmp/hg_hostapd.conf"])
    subprocess.run(["dnsmasq", "-C", "/tmp/hg_dnsmasq.conf"])
    print("[+] Honey-AP ON")

def honey_stop():
    run("pkill -f hostapd; pkill -f dnsmasq")
    for p in H_PROC:
        p.terminate()

# ---------- GUI ----------
GUI = None

class EliteGUI:
    def __init__(self, root):
        self.root = root
        root.title("DeAuth-Guard FINAL")
        root.configure(bg="black")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", bg="black", fg="#00FF00", fieldbg="black", font=("Consolas", 11))
        style.map("Treeview", bg=[("selected", "#003300")])

        frm = tk.Frame(root, bg="black")
        frm.pack(fill="both", expand=True, padx=10, pady=10)

        # Adapter-Auswahl im GUI
        self.adapters = [i for i in ifs() if can_mon(i)]
        if not self.adapters:
            tk.Label(frm, text="Kein Monitor-Adapter!", fg="red", bg="black", font=("Consolas", 14)).pack()
            return

        self.var = tk.StringVar(value=self.adapters[0])
        tk.Label(frm, text="WLAN-Adapter:", fg="#00FF00", bg="black", font=("Consolas", 12)).pack()
        tk.OptionMenu(frm, self.var, *self.adapters).pack(pady=5)

        tk.Button(frm, text="Start Monitor & Sniffer", command=self.start_monitor,
                  bg="#005000", fg="white", font=("Consolas", 11)).pack(pady=5)

        # TreeView
        self.tree = ttk.Treeview(frm, columns=("Time", "MAC", "RSSI", "CH"), show="headings", height=15)
        for col in ("Time", "MAC", "RSSI", "CH"):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=120, anchor="center")
        self.tree.pack(fill="both", expand=True, pady=5)

        self.lbl = tk.Label(frm, text="Wähle Adapter → Start", fg="#00FF00", bg="black", font=("Consolas", 12))
        self.lbl.pack()

        btn_frm = tk.Frame(frm, bg="black")
        btn_frm.pack(pady=5)

        tk.Button(btn_frm, text="🛑 Stop & Restore WiFi", command=self.stop_all,
                  bg="#AA0000", fg="white", font=("Consolas", 11)).pack(side="left", padx=5)

        tk.Button(btn_frm, text="🍯 Toggle Honey-AP", command=self.toggle_honey,
                  bg="#111", fg="#00FF00", font=("Consolas", 11)).pack(side="left", padx=5)

    def start_monitor(self):
        iface = self.var.get()
        global MON_IFACE
        MON_IFACE = mon_up(iface)
        if not MON_IFACE:
            tk.messagebox.showerror("Fehler", "Monitor-Mode fehlgeschlagen.")
            return
        self.lbl.config(text=f"Live – {MON_IFACE}")
        honey = [i for i in ifs() if i != MON_IFACE and can_mon(i)]
        CFG["honey_iface"] = honey[0] if honey else None
        sniff_start(MON_IFACE)

    def add(self, mac, rssi, ch):
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, rssi, ch))
        self.tree.yview_moveto(1)

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
        if MON_IFACE:
            mon_down(MON_IFACE)
        self.lbl.config(text="WLAN wiederhergestellt – beende …")
        self.root.after(1000, lambda: os._exit(0))

# ---------- MAIN ----------
def main():
    root = tk.Tk()
    app = EliteGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
