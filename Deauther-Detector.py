#!/usr/bin/env python3
# deauth_pro_full.py – Deauth-Detector + Wi-Fi-Adapter-Scan + Live-RSSI

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, queue, json, csv, datetime, subprocess, os, sys, re
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from scapy.all import sniff, Dot11Deauth, Dot11ProbeReq

# -------------------------------------------------
# Interface-Scan
# -------------------------------------------------
def scan_adapters():
    """Gibt Liste mit (Name, Mac, Driver) zurück"""
    adapters = []
    try:
        out = subprocess.check_output(["iw", "dev"], text=True)
        for line in out.splitlines():
            m = re.search(r"Interface\s+(\S+)", line)
            if m:
                name = m.group(1)
                # MAC & Driver
                try:
                    mac = subprocess.check_output(["cat", f"/sys/class/net/{name}/address"], text=True).strip()
                except:
                    mac = "unknown"
                try:
                    driver = subprocess.check_output(["readlink", f"/sys/class/net/{name}/device/driver"], text=True).strip().split("/")[-1]
                except:
                    driver = "unknown"
                adapters.append((name, mac, driver))
    except:
        pass
    return adapters

ADAPTERS = scan_adapters()
if not ADAPTERS:
    messagebox.showerror("Adapter", "Keine WLAN-Adapter gefunden!")
    sys.exit(1)

# -------------------------------------------------
# Monitor-Mode
# -------------------------------------------------
def set_monitor(iface):
    subprocess.run(["ip", "link", "set", iface, "down"], check=False)
    subprocess.run(["iw", iface, "set", "monitor", "none"], check=False)
    subprocess.run(["ip", "link", "set", iface, "up"], check=False)

# -------------------------------------------------
# Model
# -------------------------------------------------
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

# -------------------------------------------------
# Sniffer
# -------------------------------------------------
IFACE_MON = None
def sniff_worker():
    def handler(p):
        if p.haslayer(Dot11Deauth):
            sender = p.addr2 or "N/A"
            target = p.addr1 or "N/A"
            rssi = p.dBm_AntSignal if hasattr(p, 'dBm_AntSignal') else "N/A"
            model.add("Deauth", sender, target, rssi)
            gui_queue.put(("update",))
        if p.haslayer(Dot11ProbeReq):
            sender = p.addr2
            if sender and sender != "aa:bb:cc:dd:ee:ff":
                with model.lock:
                    if not any(e["sender"] == sender and e["typ"] == "Probe-Req" for e in model.events[-50:]):
                        model.add("Probe-Req", sender, "-", "-")
                        gui_queue.put(("update",))
    sniff(iface=IFACE_MON, prn=handler, store=0)

# -------------------------------------------------
# Themes
# -------------------------------------------------
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
        bg, fg, acc, sel = self.colors["bg"], self.colors["fg"], self.colors["accent"], self.colors["sel"]
        self.root.configure(bg=bg)
        style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg, rowheight=24)
        style.map("Treeview", background=[("selected", acc)])
        style.configure("TButton", background=acc, foreground="white", borderwidth=0)
        style.map("TButton", background=[("active", "#106ebe")])
        fig.patch.set_facecolor(bg)
        ax.set_facecolor(bg)
        ax.tick_params(colors=fg)
        ax.title.set_color(fg)

# -------------------------------------------------
# GUI
# -------------------------------------------------
class DeauthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deauth Pro Detector")
        self.root.geometry("1500x900")
        self.theme = ThemeEngine(root,"Dark")
        self.build_menu()
        self.build_adapter_frame()
        self.build_main()
        self.theme.apply(self.tree, self.fig, self.ax)
        self.root.after(200,self.process_queue)
    # ---------- Menü ----------
    def build_menu(self):
        menubar = tk.Menu(self.root)
        filem = tk.Menu(menubar,tearoff=0)
        filem.add_command(label="Export JSON", command=self.export_json)
        filem.add_command(label="Export CSV",  command=self.export_csv)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filem)
        helpm = tk.Menu(menubar,tearoff=0)
        helpm.add_command(label="About", command=lambda: messagebox.showinfo("About","Deauth Pro v3.0"))
        menubar.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=menubar)
    # ---------- Adapter-Wähler ----------
    def build_adapter_frame(self):
        af = ttk.LabelFrame(self.root, text="WLAN-Adapter")
        af.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(af, text="Adapter wählen:").pack(side=tk.LEFT, padx=5)
        self.adapter_combo = ttk.Combobox(af, state="readonly", width=25)
        self.adapter_combo["values"] = [f"{n}  ({m}) – {d}" for n,m,d in ADAPTERS]
        self.adapter_combo.current(0)
        self.adapter_combo.pack(side=tk.LEFT, padx=5)
        ttk.Button(af, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
    # ---------- Main ----------
    def build_main(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.main_frame = ttk.Frame(nb)
        nb.add(self.main_frame, text="Dashboard")
        paned = ttk.PanedWindow(self.main_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)
        # Oben: Tree
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
        # Unten: Chart
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
    # ---------- Refresh ----------
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
    # ---------- Start ----------
    def start_scan(self):
        idx = self.adapter_combo.current()
        if idx < 0:
            messagebox.showwarning("Adapter", "Kein Adapter ausgewählt.")
            return
        iface = ADAPTERS[idx][0]
        set_monitor(iface)
        self.root.title(f"Deauth Pro – {iface}")
        threading.Thread(target=sniff_worker, daemon=True).start()
    # ---------- Export ----------
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
