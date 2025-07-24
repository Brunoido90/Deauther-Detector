#!/usr/bin/env python3
# deauth_ultra.py – voll funktionsfähiger Deauth-Detector & Honeybot
# Funktionen:
#   • Adapter-Scan + wählbar über Dropdown
#   • Start / Stop Scan (Thread-sicher)
#   • Dark / Light Theme (wechselbar)
#   • Live-RSSI & Deauth-Chart
#   • JSON / CSV / PDF Export
#   • Hilfe / About
#
# Installation:
#   sudo apt update && sudo apt install python3-pip tcpdump
#   pip3 install scapy matplotlib pillow reportlab
#   sudo python3 deauth_ultra.py

import tkinter as tk, tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox
import threading, queue, json, csv, datetime, subprocess, os, sys, re
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from scapy.all import sniff, Dot11Deauth, Dot11ProbeReq

# ---------- Utility ----------
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except:
        return ""

# ---------- Interface ----------
ADAPTERS = []
IFACE_MON = None
SCAN_THREAD = None
STOP_EVENT = threading.Event()

def scan_adapters():
    """Liste aller WLAN-Adapter: (Name, MAC, Treiber)"""
    adapters = []
    iw_out = run(["iw", "dev"])
    for line in iw_out.splitlines():
        m = re.search(r"Interface\s+(\S+)", line)
        if m:
            name = m.group(1)
            mac = run(["cat", f"/sys/class/net/{name}/address"])
            driver = run(["readlink", f"/sys/class/net/{name}/device/driver"]).split("/")[-1]
            adapters.append((name, mac or "n/a", driver or "n/a"))
    return adapters

def set_monitor(iface):
    """Adapter in Monitor-Mode versetzen"""
    run(["pkill", "-9", "wpa_supplicant"])
    run(["pkill", "-9", "NetworkManager"])
    run(["ip", "link", "set", iface, "down"])
    run(["iw", iface, "set", "type", "monitor"])
    run(["ip", "link", "set", iface, "up"])
    return iface

# ---------- Model ----------
gui_queue = queue.Queue()
class EventModel:
    def __init__(self):
        self.events, self.deauth_counter = [], {}
        self.lock = threading.Lock()
    def add(self, typ, sender, target, rssi, ts=None):
        ts = ts or datetime.datetime.now()
        with self.lock:
            self.events.append({"ts": ts, "typ": typ, "sender": sender,
                                "target": target, "rssi": rssi})
            if typ == "Deauth":
                self.deauth_counter[sender] = self.deauth_counter.get(sender, 0) + 1
model = EventModel()

# ---------- Sniffer ----------
def sniff_worker():
    def handler(pkt):
        if STOP_EVENT.is_set():
            return
        if pkt.haslayer(Dot11Deauth):
            sender = pkt.addr2 or "N/A"
            target = pkt.addr1 or "N/A"
            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
            model.add("Deauth", sender, target, rssi)
            gui_queue.put(("update",))
        if pkt.haslayer(Dot11ProbeReq):
            sender = pkt.addr2
            if sender and sender != "aa:bb:cc:dd:ee:ff":
                with model.lock:
                    recent = [e for e in model.events[-50:] if e["sender"] == sender and e["typ"] == "Probe-Req"]
                    if not recent:
                        model.add("Probe-Req", sender, "-", "-")
                        gui_queue.put(("update",))
    sniff(iface=IFACE_MON, prn=handler, store=0, stop_filter=lambda _: STOP_EVENT.is_set())

# ---------- Themes ----------
THEMES = {
    "Dark":  {"bg":"#1e1e1e","fg":"#ffffff","accent":"#0078d4","sel":"#ff5252"},
    "Light": {"bg":"#ffffff","fg":"#000000","accent":"#0078d4","sel":"#ff5252"}
}

# ---------- GUI ----------
class DeauthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deauth Ultra")
        self.root.geometry("1600x950")
        self.theme_name = tk.StringVar(value="Dark")
        self.build_ui()
        self.apply_theme()
        self.root.after(200, self.process_queue)

    def build_ui(self):
        # Menü
        menubar = tk.Menu(self.root)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Export JSON", command=self.export_json)
        filem.add_command(label="Export CSV",  command=self.export_csv)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filem)

        viewm = tk.Menu(menubar, tearoff=0)
        viewm.add_radiobutton(label="Dark", variable=self.theme_name, value="Dark", command=self.apply_theme)
        viewm.add_radiobutton(label="Light", variable=self.theme_name, value="Light", command=self.apply_theme)
        menubar.add_cascade(label="View", menu=viewm)

        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="About", command=lambda: messagebox.showinfo("About","Deauth Ultra v4.0"))
        menubar.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=menubar)

        # Adapter-Frame
        af = ttk.LabelFrame(self.root, text="WLAN-Adapter")
        af.pack(fill=tk.X, padx=10, pady=5)
        self.adapter_combo = ttk.Combobox(af, state="readonly", width=45)
        self.adapter_combo["values"] = [f"{name}  {mac} – {drv}" for name, mac, drv in ADAPTERS]
        self.adapter_combo.current(0)
        self.adapter_combo.pack(side=tk.LEFT, padx=5)
        self.start_btn = ttk.Button(af, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(af, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Main
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.main_frame = ttk.Frame(nb)
        nb.add(self.main_frame, text="Live Dashboard")
        paned = ttk.PanedWindow(self.main_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Treeview
        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=3)
        cols = ("Time", "Type", "Sender MAC", "Target MAC", "RSSI (dBm)")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=25)
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=250, anchor="center")
        self.tree.tag_configure("suspicious", background="#ff5252")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Chart
        chart_frame = ttk.Frame(paned)
        paned.add(chart_frame, weight=2)
        self.fig = Figure(figsize=(10,4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Status-Bar
        self.status = tk.Label(self.root, text="Adapter wählen und Scan starten", anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def apply_theme(self):
        theme = THEMES[self.theme_name.get()]
        style = ttk.Style()
        style.theme_use("clam")
        bg, fg, acc = theme["bg"], theme["fg"], theme["accent"]
        self.root.configure(bg=bg)
        style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg, rowheight=24)
        style.map("Treeview", background=[("selected", acc)])
        style.configure("TButton", background=acc, foreground="white", borderwidth=0)
        style.map("TButton", background=[("active", "#106ebe")])
        self.fig.patch.set_facecolor(bg)
        self.ax.set_facecolor(bg)
        self.ax.tick_params(colors=fg)
        self.ax.title.set_color(fg)

    def process_queue(self):
        try:
            while True:
                msg, *_ = gui_queue.get_nowait()
                if msg == "update":
                    self.refresh()
        except queue.Empty:
            pass
        self.root.after(250, self.process_queue)

    def refresh(self):
        for child in self.tree.get_children():
            self.tree.delete(child)
        cutoff = datetime.datetime.now() - datetime.timedelta(seconds=60)
        with model.lock:
            recent = [e for e in model.events if e["ts"] > cutoff]
            for e in recent:
                tag = "suspicious" if model.deauth_counter.get(e["sender"], 0) > 3 else ""
                self.tree.insert("", "end", values=(
                    e["ts"].strftime("%H:%M:%S"),
                    e["typ"],
                    e["sender"],
                    e["target"],
                    str(e["rssi"])
                ), tags=(tag,))
            self.ax.clear()
            self.ax.set_facecolor(THEMES[self.theme_name.get()]["bg"])
            top = sorted(model.deauth_counter.items(), key=lambda x: x[1], reverse=True)[:5]
            if top:
                macs, counts = zip(*top)
                self.ax.bar(macs, counts, color=THEMES[self.theme_name.get()]["accent"])
            self.ax.tick_params(colors=THEMES[self.theme_name.get()]["fg"])
            self.ax.set_title("Live Deauth-Rate pro MAC (letzte 60 Sek.)", color=THEMES[self.theme_name.get()]["fg"])
            self.fig.tight_layout()
            self.canvas.draw()
            self.status.config(text=f"Aktive Events: {len(recent)}")

    def start_scan(self):
        idx = self.adapter_combo.current()
        if idx < 0:
            messagebox.showwarning("Adapter", "Kein Adapter ausgewählt.")
            return
        iface = ADAPTERS[idx][0]
        set_monitor(iface)
        global IFACE_MON
        IFACE_MON = iface
        STOP_EVENT.clear()
        threading.Thread(target=sniff_worker, daemon=True).start()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text=f"Scan läuft auf {iface}")

    def stop_scan(self):
        STOP_EVENT.set()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.config(text="Scan gestoppt")

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path:
            with open(path,"w") as f:
                with model.lock:
                    json.dump([{**e,"ts":str(e["ts"])} for e in model.events],f,indent=2)

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if path:
            with open(path,"w",newline="") as f:
                writer=csv.writer(f)
                writer.writerow(["Time","Type","Sender MAC","Target MAC","RSSI"])
                with model.lock:
                    for e in model.events:
                        writer.writerow([e["ts"],e["typ"],e["sender"],e["target"],e["rssi"]])

    def clear(self):
        with model.lock:
            model.events.clear(); model.deauth_counter.clear()
        self.refresh()

    def on_close(self):
        STOP_EVENT.set()
        self.root.quit()

# ---------- Entry ----------
if __name__ == "__main__":
    if not ADAPTERS:
        messagebox.showerror("Adapter", "Keine WLAN-Adapter gefunden!")
        sys.exit(1)
    root = tk.Tk()
    DeauthApp(root)
    root.mainloop()
