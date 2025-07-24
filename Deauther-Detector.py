#!/usr/bin/env python3
# main.py – professioneller Deauth-Detector + Honeybot

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, queue, signal, os, json, csv, datetime, time
from scapy.all import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from PIL import Image, ImageTk
import pystray

IFACE = "wlan0mon"
HONEY_MAC = "aa:bb:cc:dd:ee:ff"  # Nicht existent, nur als Marker

# -------------------------------------------------
# Queue für Thread-sichere GUI-Updates
# -------------------------------------------------
gui_queue = queue.Queue()

# -------------------------------------------------
# Model
# -------------------------------------------------
class EventModel:
    def __init__(self):
        self.events = []
        self.deauth_counter = {}
    def add(self, typ, sender, target, rssi, ts=None):
        ts = ts or datetime.datetime.now()
        self.events.append({"ts": ts, "typ": typ, "sender": sender, "target": target, "rssi": rssi})
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
            if sender and sender != HONEY_MAC and not any(e["sender"] == sender and e["typ"] == "Probe-Req" for e in model.events[-50:]):
                model.add("Probe-Req", sender, "-", "-")
                gui_queue.put(("update",))
    sniff(iface=IFACE, prn=pkt_handler, store=0)

# -------------------------------------------------
# GUI
# -------------------------------------------------
class DeauthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Professional Deauth Detector")
        self.root.geometry("1200x700")
        self.root.configure(bg="#1e1e1e")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Styles
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e")
        style.map("Treeview", background=[("selected", "#0078d4")])
        style.configure("TButton", background="#0078d4", foreground="white", borderwidth=0)
        style.map("TButton", background=[("active", "#106ebe")])

        # Paned Window
        paned = ttk.PanedWindow(root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Oben: Tree + Scrollbars
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

        # Unten: Matplotlib Live-Chart
        frame_chart = ttk.Frame(paned)
        paned.add(frame_chart, weight=2)
        self.fig, self.ax = plt.subplots(figsize=(5, 2), facecolor="#1e1e1e")
        self.ax.set_facecolor("#1e1e1e")
        self.ax.tick_params(colors="white")
        self.ax.set_title("Deauth-Rate pro MAC (letzte 60 s)", color="white")
        self.line_canvas = FigureCanvasTkAgg(self.fig, frame_chart)
        self.line_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Toolbar
        toolbar = ttk.Frame(root)
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Export JSON", command=self.export_json).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(toolbar, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(toolbar, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5, pady=5)

        # Tray
        self.tray_icon = None
        self.setup_tray()

        # Queue polling
        self.root.after(200, self.process_queue)

    # -------------------------------------------------
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
        # Tree
        for child in self.tree.get_children():
            self.tree.delete(child)
        recent = [e for e in model.events if datetime.datetime.now() - e["ts"] < datetime.timedelta(seconds=60)]
        for e in recent:
            tag = "suspicious" if model.deauth_counter.get(e["sender"], 0) > 3 else ""
            self.tree.insert("", "end", values=(
                e["ts"].strftime("%H:%M:%S"),
                e["typ"],
                e["sender"],
                e["target"],
                str(e["rssi"])
            ), tags=(tag,))

        # Chart
        self.ax.clear()
        self.ax.set_facecolor("#1e1e1e")
        top_macs = sorted(model.deauth_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        macs, counts = zip(*top_macs) if top_macs else ([], [])
        self.ax.bar(macs, counts, color="#0078d4")
        self.ax.tick_params(colors="white")
        self.ax.set_title("Deauth-Rate pro MAC (letzte 60 s)", color="white")
        self.fig.tight_layout()
        self.line_canvas.draw()

    # -------------------------------------------------
    def clear(self):
        model.events.clear()
        model.deauth_counter.clear()
        self.refresh()

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w") as f:
                json.dump([{**e, "ts": str(e["ts"])} for e in model.events], f, indent=2)

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Type", "Sender MAC", "Target MAC", "RSSI"])
                for e in model.events:
                    writer.writerow([e["ts"], e["typ"], e["sender"], e["target"], e["rssi"]])

    # -------------------------------------------------
    def setup_tray(self):
        def show(icon, item):
            icon.stop()
            self.root.after(0, self.root.deiconify)
        def quit_app(icon, item):
            icon.stop()
            self.root.quit()
        image = Image.open("icons/icon.png")
        self.tray_icon = pystray.Icon("DeauthDetector", image, menu=pystray.Menu(
            pystray.MenuItem("Show", show),
            pystray.MenuItem("Quit", quit_app)
        ))

    def on_close(self):
        self.root.withdraw()
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

# -------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = DeauthApp(root)
    threading.Thread(target=sniff_worker, daemon=True).start()
    root.mainloop()
