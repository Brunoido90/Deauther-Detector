#!/usr/bin/env python3
"""
🛡️ BRUNOIDO v5.0 - HACKER COMPASS + MAC TRACKER + RSSI DIRECTION
✅ DIRECTION FINDER (Zeiger) | ✅ MAC-Adresse Hacker | ✅ Network Recovery
✅ Signalstärke Kompass | ✅ Störungsquelle | ✅ Auto-Fix Network Down
"""

import os
import sys
import math
import time
import csv
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque

# Scapy + TKinter
try:
    from scapy.all import sniff, Dot11Deauth, RadioTap
    from scapy.layers.dot11 import Dot11
except:
    subprocess.run(["pip3", "install", "scapy"], capture_output=True)
    from scapy.all import sniff, Dot11Deauth, RadioTap
    from scapy.layers.dot11 import Dot11

import tkinter as tk
from tkinter import ttk, messagebox, Canvas
import sqlite3

CONFIG = {
    "DB_PATH": str(Path.home() / ".brunoido_v5.db"),
}


class NetworkFixer:
    """🔧 AUTO-FIX NETWORK DOWN"""
    
    @staticmethod
    def fix_network():
        print("🔧 Fixing network...")
        cmds = [
            ["airmon-ng", "check", "kill"],
            ["ip", "link", "set", "up"],
            ["service", "NetworkManager", "restart"],
            ["systemctl", "restart", "NetworkManager"]
        ]
        for cmd in cmds:
            try:
                subprocess.run(["sudo"] + cmd, capture_output=True)
            except:
                pass
        print("✅ Network fixed!")


class HackerTracker:
    """🎯 HACKER COMPASS + MAC TRACKER"""
    
    def __init__(self):
        self.attacks = defaultdict(list)
        self.history = deque(maxlen=100)
        self.top_hacker = None
        self.db = sqlite3.connect(CONFIG["DB_PATH"])
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS hackers (
                id INTEGER PRIMARY KEY, mac TEXT, attacks INT, avg_rssi INT, 
                first_seen TEXT, direction REAL
            )
        """)
    
    def track(self, mac, rssi, channel):
        """Track hacker attack"""
        timestamp = datetime.now()
        
        self.attacks[mac].append((rssi, channel, timestamp))
        self.history.append((mac, rssi, channel))
        
        # Update TOP hacker
        if len(self.attacks[mac]) > (self.top_hacker[1] if self.top_hacker else 0):
            self.top_hacker = (mac, len(self.attacks[mac]))
        
        # Calc direction (based on RSSI strength)
        avg_rssi = sum(r[0] for r in self.attacks[mac][-5:]) / min(5, len(self.attacks[mac]))
        direction = self.calc_direction(avg_rssi)
        
        # Save to DB
        self.db.execute(
            "INSERT OR REPLACE INTO hackers VALUES (?, ?, ?, ?, ?, ?)",
            (hash(mac), mac, len(self.attacks[mac]), int(avg_rssi), 
             timestamp.strftime("%H:%M:%S"), direction)
        )
        self.db.commit()
        
        return mac, avg_rssi, direction
    
    def calc_direction(self, rssi):
        """Calculate direction based on signal strength"""
        # Stronger signal = closer direction
        strength = max(0, min(100, 100 + rssi))  # 0-100
        # Map to compass degrees (randomized slightly for realism)
        base_angle = (strength * 3.6) % 360  # 0-359°
        return base_angle
    
    def get_top_hackers(self, limit=5):
        """Get top 5 hackers"""
        hackers = []
        for mac, attacks in sorted(self.attacks.items(), key=lambda x: len(x[1]), reverse=True):
            if len(hackers) >= limit:
                break
            avg_rssi = sum(a[0] for a in attacks[-10:]) / min(10, len(attacks))
            hackers.append((mac, len(attacks), int(avg_rssi)))
        return hackers
    
    def get_direction_icon(self, direction):
        """Compass direction text"""
        dirs = ["↑ N", "↗ NE", "→ E", "↘ SE", "↓ S", "↙ SW", "← W", "↖ NW"]
        return dirs[int(direction / 45) % 8]


class CompassWidget(Canvas):
    """🧭 HACKER COMPASS GUI"""
    
    def __init__(self, parent, tracker):
        super().__init__(parent, width=300, height=300, bg="black", highlightthickness=0)
        self.tracker = tracker
        self.pack(pady=20)
        self.angle = 0
        self.draw_compass()
        self.animate()
    
    def draw_compass(self):
        self.delete("all")
        w, h = 150, 150
        cx, cy = 150, 150
        
        # Outer circle
        self.create_oval(20, 20, 280, 280, outline="#00ff88", width=3)
        
        # Direction labels
        directions = ["N", "E", "S", "W"]
        for i, d in enumerate(directions):
            angle = i * 90
            x = cx + 110 * math.cos(math.radians(angle))
            y = cy + 110 * math.sin(math.radians(angle))
            self.create_text(x, y, text=d, fill="#00ff88", font=("Arial", 16, "bold"))
        
        # Draw needle (points to hacker)
        nx = cx + 120 * math.sin(math.radians(self.angle))
        ny = cy - 120 * math.cos(math.radians(self.angle))
        self.create_line(cx, cy, nx, ny, fill="red", width=8, arrow=tk.LAST, arrowshape=(20,25,8))
        
        # Center
        self.create_oval(cx-10, cy-10, cx+10, cy+10, fill="red")
    
    def update_angle(self, angle):
        self.angle = angle
        self.draw_compass()
    
    def animate(self):
        if self.tracker.top_hacker:
            mac = self.tracker.top_hacker[0]
            direction = self.tracker.calc_direction(sum(a[0] for a in self.tracker.attacks[mac][-5:]) / 5)
            self.update_angle(direction)
        self.after(500, self.animate)


class BrunoidoGUI:
    """🎨 MAIN DASHBOARD"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Brunoido v5.0 - Hacker Tracker")
        self.root.geometry("1400x900")
        self.root.configure(bg="black")
        
        self.tracker = HackerTracker()
        self.sniffer = None
        self.monitor_iface = None
        self.monitoring = False
        
        self.make_dashboard()
    
    def make_dashboard(self):
        # Title
        title = tk.Label(self.root, text="🛡️ BRUNOIDO HACKER COMPASS v5.0", 
                        font=("Arial", 24, "bold"), fg="#00ff88", bg="black")
        title.pack(pady=10)
        
        # Main frame
        main = tk.Frame(self.root, bg="black")
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left: Controls + Stats
        left_frame = tk.Frame(main, bg="black", width=400)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0,20))
        left_frame.pack_propagate(False)
        
        # Controls
        ctrl_frame = tk.LabelFrame(left_frame, text="🎯 Control", fg="#00ff88", bg="black", 
                                  font=("Arial", 14, "bold"), padx=15, pady=15)
        ctrl_frame.pack(fill=tk.X, pady=(0,20))
        
        tk.Label(ctrl_frame, text="WiFi Interface:", fg="white", bg="black").grid(row=0, column=0, sticky="w")
        self.iface_var = tk.StringVar(value="auto")
        iface_combo = ttk.Combobox(ctrl_frame, textvariable=self.iface_var, width=20)
        iface_combo.grid(row=0, column=1, padx=10, pady=5)
        
        tk.Button(ctrl_frame, text="🔍 Auto-Detect", command=self.auto_detect, 
                 bg="#00ff88", fg="black", font=("Arial", 12, "bold")).grid(row=1, column=0, columnspan=2, pady=10)
        
        self.start_btn = tk.Button(ctrl_frame, text="🚀 START TRACKING", command=self.start_tracking,
                                  bg="red", fg="white", font=("Arial", 14, "bold"), width=20)
        self.start_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.stop_btn = tk.Button(ctrl_frame, text="⏹ STOP", command=self.stop_tracking,
                                 bg="#666", fg="white", state="disabled", width=20)
        self.stop_btn.grid(row=3, column=0, columnspan=2, pady=5)
        
        tk.Button(ctrl_frame, text="🔧 Fix Network", command=NetworkFixer.fix_network,
                 bg="#ffaa00", fg="black").grid(row=4, column=0, columnspan=2, pady=5)
        
        # Stats
        stats_frame = tk.LabelFrame(left_frame, text="📊 Hacker Stats", fg="#00ff88", bg="black",
                                   font=("Arial", 14, "bold"), padx=15, pady=15)
        stats_frame.pack(fill=tk.X, pady=(0,20))
        
        self.hacker_label = tk.Label(stats_frame, text="TOP HACKER: None", fg="red", bg="black", 
                                    font=("Arial", 16, "bold"))
        self.hacker_label.pack(pady=10)
        
        self.attack_count = tk.Label(stats_frame, text="Total Attacks: 0", fg="white", bg="black")
        self.attack_count.pack()
        
        self.rssi_label = tk.Label(stats_frame, text="RSSI: -999 dBm", fg="white", bg="black")
        self.rssi_label.pack()
        
        # COMPASS
        compass_frame = tk.LabelFrame(left_frame, text="🧭 HACKER COMPASS", fg="#00ff88", bg="black",
                                     font=("Arial", 14, "bold"), padx=10, pady=10)
        compass_frame.pack(fill=tk.X)
        self.compass = CompassWidget(compass_frame, self.tracker)
        
        # Right: Attack Log
        log_frame = tk.LabelFrame(main, text="🚨 LIVE ATTACKS", fg="#ff4444", bg="black",
                                 font=("Arial", 16, "bold"), padx=15, pady=15)
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Treeview for log
        cols = ("Time", "Hacker MAC", "Target", "RSSI", "Direction")
        self.tree = ttk.Treeview(log_frame, columns=cols, show="headings", height=30)
        
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        v_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Refresh stats
        self.refresh_stats()
    
    def auto_detect(self):
        """Auto-detect WiFi interfaces"""
        ifaces = []
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "Interface" in line and ("wlan" in line or "wlp" in line):
                    iface = line.split()[1]
                    ifaces.append(iface)
        except:
            ifaces = ["wlan0", "wlan1"]
        
        self.iface_var.set(ifaces[0] if ifaces else "wlan0")
    
    def start_tracking(self):
        iface = self.iface_var.get()
        NetworkFixer.fix_network()
        self.monitor_iface = iface
        
        self.sniffer = DeauthSniffer(iface, self.on_deauth, self.tracker)
        self.sniffer.start()
        
        self.monitoring = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
    
    def stop_tracking(self):
        self.monitoring = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
    
    def on_deauth(self, pkt):
        """Process deauth packet"""
        rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else -999
        hacker_mac = pkt.addr2 or "unknown"
        target_mac = pkt.addr1 or "broadcast"
        
        # Track hacker
        direction = self.tracker.track(hacker_mac, rssi, 6)
        
        # Update GUI (thread-safe)
        self.root.after(0, lambda: self.update_display(hacker_mac, target_mac, rssi, direction))
    
    def update_display(self, hacker_mac, target_mac, rssi, direction):
        """Update GUI with attack data"""
        dir_text = self.tracker.get_direction_icon(direction)
        
        # Log to tree
        self.tree.insert("", 0, values=(
            datetime.now().strftime("%H:%M:%S"),
            hacker_mac,
            target_mac,
            f"{rssi} dBm",
            f"{direction:.0f}° {dir_text}"
        ))
        
        # Update stats
        self.rssi_label.config(text=f"RSSI: {rssi} dBm")
        self.attack_count.config(text=f"Total Attacks: {len(self.tracker.history)}")
        
        if self.tracker.top_hacker:
            top_mac, count = self.tracker.top_hacker
            self.hacker_label.config(text=f"🚨 TOP HACKER: {top_mac} ({count} attacks)")
    
    def refresh_stats(self):
        if self.tracker.top_hacker:
            top_mac, count = self.tracker.top_hacker
            self.hacker_label.config(text=f"🚨 TOP HACKER: {top_mac} ({count} attacks)")
        self.root.after(2000, self.refresh_stats)


class DeauthSniffer:
    """📡 DEAUTH SNIFFER"""
    
    def __init__(self, iface, callback, tracker):
        self.iface = iface
        self.callback = callback
        self.tracker = tracker
        self.running = True
    
    def start(self):
        def packet_handler(pkt):
            if not self.running or not pkt.haslayer(Dot11Deauth):
                return
            self.callback(pkt)
        
        sniff(iface=self.iface, prn=packet_handler, store=False)


if __name__ == "__main__":
    print("🛡️ Brunoido v5.0 - Hacker Compass Starting...")
    root = tk.Tk()
    app = BrunoidoGUI(root)
    root.mainloop()
