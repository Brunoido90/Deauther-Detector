#!/usr/bin/env python3
# main.py – kompletter Deauth-Detector + Honeybot (kein Tray-Code)
# passt das iface automatisch an das erste gefundene Monitor-Interface an

import tkinter as tk
from tkinter import ttk, filedialog
import threading, queue, os, json, csv, datetime
from scapy.all import *
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import subprocess, re

# -------------------------------------------------
# Automatisches Interface-Detection
# -------------------------------------------------
def find_monitor_interface():
    try:
        out = subprocess.check_output(["iw", "dev"], stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            m = re.search(r"Interface\s+(\S+mon\S*)", line)
            if m:
                return m.group(1).strip()
    except:
        pass
    return None

IFACE = find_monitor_interface()
if not IFACE:
    print("Kein Monitor-Interface gefunden! Bitte vorher 'sudo airmon-ng start wlan0' ausführen.")
    exit(1)

HONEY_MAC = "aa:bb:cc:dd:ee:ff"

# -------------------------------------------------
# Queue & Model
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
    def pkt_handler(p):
        if p.haslayer(Dot11Deauth):
            sender = p.addr2 or "N/A"
            target = p.addr1 or "N/A"
            rssi = p.dBm_AntSignal if hasattr(p, 'dBm_AntSignal') else "N/A"
            model.add("Deauth", sender, target, rssi)
            gui_queue.put(("update",))
        if p.haslayer(Dot11ProbeReq):
            sender = p.addr2
            if sender and sender != HONEY_MAC:
                with model.lock:
                    recent = [e for e in model.events[-50:] if e["sender"] == sender and e["typ"] == "Probe-Req"]
                    if not recent:
                        model.add("Probe-Req", sender, "-", "-")
                        gui_queue.put(("update",))
    sniff(iface=IFACE, prn=pkt_handler, store=0)

# -------------------------------------------------
# GUI
# -------------------------------------------------
class DeauthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deauth Detector – Interface: " + IFACE)
        self.root.geometry("1200x700")
        self.root.configure(bg="#1e1e1e")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2e2e2e", foreground="white",
                        fieldbackground="#2e2e2e", rowheight=22)
        style.map("Treeview", background=[("selected", "#0078d4")])
        style.configure("TButton", background="#0078d4", foreground="white", borderwidth=0)
        style.map("TButton", background=[("active", "#106ebe")])

        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Treeview
        frame_top = ttk.Frame(paned)
        paned.add(frame_top, weight=3)
        cols = ("Time", "Type", "Sender MAC", "Target MAC", "RSSI (dBm)")
        self.tree = ttk.Treeview(frame_top, columns=cols, show="headings", height=15)
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor="center")
        self.tree.tag_configure("suspicious", background="#ff5252")
        vsb = ttk.Scrollbar(frame_top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Chart
        frame_chart = ttk.Frame(paned)
        paned.add(frame_chart, weight=2)
        self.fig, self.ax = plt.subplots(figsize=(5, 2), facecolor="#1e1e1e")
        self.ax.set_facecolor("#1e1e1e")
        self.ax.tick_params(colors="white")
        self.ax.set_title("Deauth-Rate pro MAC (letzte 60 s)", color="white")
        self.line_canvas = FigureCanvasTkAgg(self.fig, frame_chart)
        self.line_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Toolbar
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Start Sniffing", command=self.start_sniffing).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(toolbar, text="Export JSON", command=self.export_json).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(toolbar, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(toolbar, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5, pady=5)

        self.root.after(200, self.process_queue)

    def process_queue(self):
        try:
            while True:
                msg, *_ = gui_queue.get_nowait()
                if msg == "update":
                    self.refresh()
        except queue.Empty:
            pass
        self.root.after(200, self.process_queue)

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
            self.ax.set_facecolor("#1e1e1e")
            top = sorted(model.deauth_counter.items(), key=lambda x: x[1], reverse=True)[:5]
            if top:
                macs, counts = zip(*top)
                self.ax.bar(macs, counts, color="#0078d4")
            self.ax.tick_params(colors="white")
            self.ax.set_title("Deauth-Rate pro MAC (letzte 60 s)", color="white")
            self.fig.tight_layout()
            self.line_canvas.draw()

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

    def on_close(self):
        self.root.quit()

# -------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    DeauthApp(root)
    root.mainloop()
