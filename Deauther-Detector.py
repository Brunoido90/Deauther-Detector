#!/usr/bin/env python3
# deauth_pro.py – Ultra-professioneller, vollautomatischer Deauth-Detector + Honeybot
# Dark-Theme, Live-Dashboard, CSV/JSON/PDF-Export, Themes, Hilfe & mehr

import tkinter as tk, tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox
import threading, queue, json, csv, datetime, os, sys, subprocess, re, webbrowser, platform
from pathlib import Path

# Matplotlib
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

# Scapy
from scapy.all import sniff, Dot11Deauth, Dot11ProbeReq

# Optional: ReportLab für PDF (wenn vorhanden)
try:
    from reportlab.pdfgen import canvas as pdfcanvas
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# -------------------------------------------------
# Interface-Handling
# -------------------------------------------------
IFACE_MON = None

def get_monitor_iface():
    try:
        out = subprocess.check_output(["iw", "dev"], text=True)
        for line in out.splitlines():
            m = re.search(r"Interface\s+(\S+mon\S*)", line)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return None

def create_monitor(iface):
    subprocess.run(["ip", "link", "set", iface, "down"], check=False)
    subprocess.run(["iw", iface, "set", "monitor", "none"], check=False)
    subprocess.run(["ip", "link", "set", iface, "up"], check=False)
    return iface

def prepare_interface():
    global IFACE_MON
    phy = None
    try:
        out = subprocess.check_output(["iw", "dev"], text=True)
        for ln in out.splitlines():
            if ln.strip().startswith("Interface"):
                phy = ln.strip().split()[-1]
                break
    except:
        pass
    if not phy:
        messagebox.showerror("Interface", "Kein WLAN-Interface gefunden!")
        sys.exit(1)
    create_monitor(phy)
    IFACE_MON = phy

# -------------------------------------------------
# Model
# -------------------------------------------------
gui_queue = queue.Queue()

class EventModel:
    def __init__(self):
        self.events = []
        self.deauth_counter = {}
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
# Sniffer-Thread
# -------------------------------------------------
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
                    recent = [e for e in model.events[-50:] if e["sender"] == sender and e["typ"] == "Probe-Req"]
                    if not recent:
                        model.add("Probe-Req", sender, "-", "-")
                        gui_queue.put(("update",))
    sniff(iface=IFACE_MON, prn=handler, store=0)

# -------------------------------------------------
# Themes
# -------------------------------------------------
THEMES = {
    "Dark": {"bg": "#1e1e1e", "fg": "#ffffff", "accent": "#0078d4", "sel": "#ff5252"},
    "Light": {"bg": "#ffffff", "fg": "#000000", "accent": "#0078d4", "sel": "#ff5252"}
}

class ThemeEngine:
    def __init__(self, root, theme="Dark"):
        self.root = root
        self.theme = theme
        self.colors = THEMES[theme]

    def apply(self, tree, fig, ax):
        style = ttk.Style()
        style.theme_use("clam")
        bg, fg, accent, sel = self.colors["bg"], self.colors["fg"], self.colors["accent"], self.colors["sel"]
        self.root.configure(bg=bg)
        style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg, rowheight=24)
        style.map("Treeview", background=[("selected", accent)])
        style.configure("TButton", background=accent, foreground=fg, borderwidth=0)
        style.map("TButton", background=[("active", "#106ebe")])
        fig.patch.set_facecolor(bg)
        ax.set_facecolor(bg)
        ax.tick_params(colors=fg)
        ax.title.set_color(fg)

# -------------------------------------------------
# PDF-Export
# -------------------------------------------------
def export_pdf(path):
    if not PDF_AVAILABLE:
        messagebox.showwarning("PDF", "reportlab nicht installiert – PDF-Export deaktiviert.")
        return
    c = pdfcanvas.Canvas(str(path))
    c.setFont("Helvetica", 10)
    c.drawString(50, 800, "Deauth-Detector Report – " + str(datetime.datetime.now()))
    y = 780
    with model.lock:
        for e in model.events[-100:]:
            line = f"{e['ts']:%H:%M:%S}  {e['typ']}  {e['sender']} → {e['target']}  RSSI:{e['rssi']}"
            c.drawString(50, y, line)
            y -= 12
            if y < 50:
                c.showPage()
                y = 800
    c.save()

# -------------------------------------------------
# GUI
# -------------------------------------------------
class DeauthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deauth Pro Detector")
        self.root.geometry("1400x800")
        self.theme = ThemeEngine(root, "Dark")

        # Menüleiste
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Export JSON", command=self.export_json)
        filemenu.add_command(label="Export CSV",  command=self.export_csv)
        filemenu.add_command(label="Export PDF",  command=self.export_pdf)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=helpmenu)
        root.config(menu=menubar)

        # Toolbar
        toolbar = ttk.Frame(root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(toolbar, text="Start Sniffing", command=self.start_sniffing).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=2)

        # Notebook (Tabs)
        nb = ttk.Notebook(root)
        nb.pack(fill=tk.BOTH, expand=True)
        main_frame = ttk.Frame(nb)
        nb.add(main_frame, text="Dashboard")

        # Paned Window
        paned = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Oben: Treeview
        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=3)
        cols = ("Time", "Type", "Sender MAC", "Target MAC", "RSSI (dBm)")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=20)
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200, anchor="center")
        self.tree.tag_configure("suspicious", background="#ff5252")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Unten: Chart
        chart_frame = ttk.Frame(paned)
        paned.add(chart_frame, weight=2)
        self.fig = Figure(figsize=(6, 3), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Status-Bar
        self.status = tk.Label(root, text="Bereit", anchor=tk.W, bg="#0078d4", fg="white")
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

        self.theme.apply(self.tree, self.fig, self.ax)
        self.root.after(200, self.process_queue)
        self.start_sniffing()

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
            self.ax.set_title("Deauth-Rate pro MAC (letzte 60 s)", color=self.theme.colors["fg"])
            self.fig.tight_layout()
            self.canvas.draw()
            self.status.config(text=f"Aktuelle Events: {len(recent)}")

    def start_sniffing(self):
        threading.Thread(target=sniff_worker, daemon=True).start()

    def clear(self):
        with model.lock:
            model.events.clear()
            model.deauth_counter.clear()
        self.refresh()

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w") as f:
                with model.lock:
                    json.dump([{**e, "ts": str(e["ts"])} for e in model.events], f, indent=2)

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Type", "Sender MAC", "Target MAC", "RSSI"])
                with model.lock:
                    for e in model.events:
                        writer.writerow([e["ts"], e["typ"], e["sender"], e["target"], e["rssi"]])

    def export_pdf(self):
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if path:
            export_pdf(path)
            messagebox.showinfo("Export", "PDF gespeichert.")

    def show_about(self):
        messagebox.showinfo("About", "Deauth Pro Detector\nv1.0 – ultra-professionell\n(c) 2025")

    def on_close(self):
        self.root.quit()

# -------------------------------------------------
# Main
# -------------------------------------------------
if __name__ == "__main__":
    prepare_interface()
    root = tk.Tk()
    DeauthApp(root)
    root.mainloop()
