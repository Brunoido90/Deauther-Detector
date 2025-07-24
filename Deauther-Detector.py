#!/usr/bin/env python3
# deauth_pro_fixed.py – vollautomatischer Deauth-Detector mit robuster Interface-Erkennung
# Scannt alle WLAN-Adapter → Dropdown → Monitor-Mode → Live-RSSI → Export

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, queue, json, csv, datetime, subprocess, os, sys, re
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from scapy.all import sniff, Dot11Deauth, Dot11ProbeReq

# ---------- Robustes Interface-Handling ----------
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except:
        return ""

def scan_adapters():
    """Gibt Liste mit (Name, Mac, Treiber) zurück"""
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

def kill_processes():
    """airmon-ng check kill light-weight"""
    for proc in ["wpa_supplicant", "NetworkManager"]:
        subprocess.run(["pkill", proc], check=False)

def set_monitor(iface):
    """Stellt Monitor-Mode sicher"""
    kill_processes()
    run(["ip", "link", "set", iface, "down"])
    run(["iw", iface, "set", "type", "monitor"])
    run(["ip", "link", "set", iface, "up"])
    return iface

# ---------- Adapter-Scan ----------
ADAPTERS = scan_adapters()
if not ADAPTERS:
    messagebox.showerror("Adapter", "Kein WLAN-Adapter gefunden!")
    sys.exit(1)

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
IFACE_MON = None
def sniff_worker():
    def handler(pkt):
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
                    if not any(e["sender"] == sender and e["typ"] == "Probe-Req" for e in model.events[-50:]):
                        model.add("Probe-Req", sender, "-", "-")
                        gui_queue.put(("update",))
    sniff(iface=IFACE_MON, prn=handler, store=0)

# ---------- Themes ----------
THEMES = {
    "Dark":  {"bg":"#1e1e1e","fg":"#ffffff","accent":"#0078d4","sel":"#ff5252"},
    "Light": {"bg":"#ffffff","fg":"#000000","accent":"#0078d4","sel":"#ff5252"}
}
class ThemeEngine:
    def __init__(self, root, theme="Dark"):
        self.root, self.colors = root, THEMES[theme]
    def apply(self, tree, fig, ax):
        style = ttk.Style()
        style.theme_use("clam")
        bg, fg, acc = self.colors["bg"], self.colors["fg"], self.colors["accent"]
        self.root.configure(bg=bg)
        style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg, rowheight=24)
        style.map("Treeview", background=[("selected", acc)])
        style.configure("TButton", background=acc, foreground="white", borderwidth=0)
        style.map("TButton", background=[("active", "#106ebe")])
        fig.patch.set_facecolor(bg)
        ax.set_facecolor(bg)
        ax.tick_params(colors=fg)
        ax.title.set_color(fg)

# ---------- GUI ----------
class DeauthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deauth Pro Detector")
        self.root.geometry("1500x900")
        self.theme = ThemeEngine(root,"Dark")
        self.build_ui()
        self.theme.apply(self.tree, self.fig, self.ax)
        self.root.after(200, self.process_queue)

    def build_ui(self):
        # Menü
        menubar = tk.Menu(self.root)
        filem = tk.Menu(menubar,tearoff=0)
        filem.add_command(label="Export JSON", command=self.export_json)
        filem.add_command(label="Export CSV",  command=self.export_csv)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filem)
        helpm = tk.Menu(menubar,tearoff=0)
        helpm.add_command(label="About", command=lambda: messagebox.showinfo("About","Deauth Pro v3.2"))
        menubar.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=menubar)

        # Adapter-Auswahl
        af = ttk.LabelFrame(self.root, text="WLAN-Adapter")
        af.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(af, text="Adapter wählen:").pack(side=tk.LEFT, padx=5)
        self.adapter_combo = ttk.Combobox(af, state="readonly", width=40)
        self.adapter_combo["values"] = [f"{n}  ({m}) – {d}" for n,m,d in ADAPTERS]
        self.adapter_combo.current(0)
        self.adapter_combo.pack(side=tk.LEFT, padx=5)
        ttk.Button(af, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)

        # Main
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.main_frame = ttk.Frame(nb)
        nb.add(self.main_frame, text="Dashboard")
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

    # ---------- Queue ----------
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
            self.ax.set_facecolor(self.theme.colors["bg"])
            top = sorted(model.deauth_counter.items(), key=lambda x: x[1], reverse=True)[:5]
            if top:
                macs, counts = zip(*top)
                self.ax.bar(macs, counts, color=self.theme.colors["accent"])
            self.ax.tick_params(colors=self.theme.colors["fg"])
            self.ax.set_title("Live Deauth-Rate pro MAC (letzte 60 Sek.)", color=self.theme.colors["fg"])
            self.fig.tight_layout()
            self.canvas.draw()

    def start_scan(self):
        idx = self.adapter_combo.current()
        if idx < 0:
            messagebox.showwarning("Adapter", "Kein Adapter ausgewählt.")
            return
        iface = ADAPTERS[idx][0]
        set_monitor(iface)
        global IFACE_MON
        IFACE_MON = iface
        self.root.title(f"Deauth Pro – {iface}")
        threading.Thread(target=sniff_worker, daemon=True).start()

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
        self.root.quit()

# ---------- Main ----------
if __name__ == "__main__":
    root = tk.Tk()
    DeauthApp(root)
    root.mainloop()
