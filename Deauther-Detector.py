#!/usr/bin/env python3
"""
DeAuth-Guard: Verbessert und stabil mit automatischer Gegenmaßnahme
Verwendung: sudo python3 deauth_final.py
"""
import os, sys, time, threading, subprocess, signal, sqlite3
from datetime import datetime
from queue import Queue, Empty

# Wichtige Abhängigkeiten:
# sudo apt-get update
# sudo apt-get install python3-scapy python3-tk hostapd dnsmasq aircrack-ng iw
# pip3 install scapy

try:
    from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11, RadioTap, Dot11, sendp
except ImportError:
    sys.exit("[!] Scapy wurde nicht gefunden. Bitte mit 'pip3 install scapy' installieren.")

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    GUI_READY = True
except ImportError:
    print("[!] Tkinter wurde nicht gefunden. Der Code wird ohne GUI ausgeführt.")
    GUI_READY = False

# Konfiguration
CFG = {
    "ssid": "🍯_Free_WiFi",
    "chan": 6,
    "db": "/tmp/deauth.db",
    "ignore_mac": None # MAC-Adresse, die ignoriert werden soll
}

# ----------------- UTIL FÜR EXTERNE BEFEHLE -----------------
def run_command(cmd_list, capture_output=False, check=True):
    """
    Führt einen Befehl sicher aus und fängt Ausnahmen ab.
    Ersetzt `subprocess.run(..., shell=True)` durch einen sichereren Ansatz.
    """
    try:
        if capture_output:
            return subprocess.check_output(cmd_list, stderr=subprocess.DEVNULL, text=True).strip()
        else:
            return subprocess.run(cmd_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=check)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] Fehler bei der Ausführung von Befehl: {' '.join(cmd_list)}")
        print(f"    Fehler: {e}")
        return None

def get_interfaces():
    """Gibt eine Liste aller WLAN-Interfaces zurück."""
    output = run_command(["iw", "dev"], capture_output=True)
    if not output:
        return []
    interfaces = [line.split()[1] for line in output.split('\n') if 'Interface' in line]
    return interfaces

def get_monitor_interfaces():
    """Findet alle WLAN-Interfaces, die den Monitor-Mode unterstützen."""
    interfaces = get_interfaces()
    monitor_interfaces = []
    for iface in interfaces:
        phy_output = run_command(["iw", "dev", iface, "info"], capture_output=True)
        if not phy_output:
            continue
        phy_name = next((line.split()[1] for line in phy_output.split('\n') if "wiphy" in line), None)
        if phy_name:
            cap_output = run_command(["iw", "phy", phy_name, "info"], capture_output=True)
            if cap_output and "monitor" in cap_output:
                monitor_interfaces.append(iface)
    return monitor_interfaces

def enable_monitor_mode(iface):
    """Aktiviert den Monitor-Mode für ein Interface und gibt den neuen Namen zurück."""
    print(f"[+] Versuche, Monitor-Mode für {iface} zu aktivieren...")
    run_command(["airmon-ng", "check", "kill"]) # Stoppt störende Prozesse
    result = run_command(["airmon-ng", "start", iface])
    if result and result.returncode == 0:
        # Finde den neuen Monitor-Namen (z.B. wlan0mon)
        mon_iface = next((x for x in get_interfaces() if x.startswith(iface) and x.endswith("mon")), None)
        if mon_iface:
            run_command(["ip", "link", "set", mon_iface, "up"])
            return mon_iface
    return None

def disable_monitor_mode(mon_iface):
    """Deaktiviert den Monitor-Mode und stellt das Netzwerk wieder her."""
    print(f"[+] Deaktiviere Monitor-Mode für {mon_iface}...")
    run_command(["airmon-ng", "stop", mon_iface])
    # Stelle den Netzwerkmanager wieder her
    run_command(["systemctl", "restart", "NetworkManager"])

def set_channel(iface, channel):
    """Setzt den Kanal des Interfaces."""
    print(f"[+] Wechsle Kanal auf {iface} zu {channel}...")
    run_command(["iw", "dev", iface, "set", "channel", str(channel)])

# ----------------- DATENBANK-VERWALTUNG -----------------
class DBManager:
    """Verwaltet die SQLite-Datenbank für die Protokollierung von Angriffen."""
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.init_db()

    def init_db(self):
        """Erstellt die Tabelle, falls sie nicht existiert."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS deauth_events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                attacker_mac TEXT,
                receiver_mac TEXT,
                bssid TEXT,
                rssi INTEGER,
                channel INTEGER,
                counter_attack TEXT
            )
        """)
        self.conn.commit()

    def add_event(self, timestamp, attacker_mac, receiver_mac, bssid, rssi, channel, counter_attack):
        """Fügt ein neues Deauth-Ereignis zur Datenbank hinzu."""
        self.cursor.execute("""
            INSERT INTO deauth_events (timestamp, attacker_mac, receiver_mac, bssid, rssi, channel, counter_attack)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, attacker_mac, receiver_mac, bssid, rssi, channel, counter_attack))
        self.conn.commit()

    def get_all_events(self):
        """Gibt alle gespeicherten Ereignisse zurück."""
        self.cursor.execute("SELECT * FROM deauth_events ORDER BY id DESC")
        return self.cursor.fetchall()

    def clear_events(self):
        """Löscht alle Ereignisse aus der Datenbank."""
        self.cursor.execute("DELETE FROM deauth_events")
        self.conn.commit()

    def close(self):
        """Schließt die Datenbankverbindung."""
        self.conn.close()

# ----------------- HAUPTKLASSE -----------------
class DeauthGuard:
    def __init__(self, iface_mon=None, iface_honey=None, gui_queue=None, auto_counter=False):
        self.iface_mon = iface_mon
        self.iface_honey = iface_honey
        self.gui_queue = gui_queue
        self.honey_on = False
        self.auto_counter_enabled = auto_counter
        self.sniff_thread = None
        self.sniff_stop_flag = threading.Event()
        self.honey_procs = []
        self.db = DBManager(CFG["db"])
        
    def start_sniffer(self):
        """Startet den Scapy-Sniffer-Thread."""
        if not self.iface_mon:
            return
        
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.iface_mon,
                prn=self._detect_packet,
                store=False,
                stop_filter=lambda x: self.sniff_stop_flag.is_set(),
                monitor=True
            ), 
            daemon=True
        )
        self.sniff_thread.start()
        print(f"[+] Sniffer auf Interface '{self.iface_mon}' gestartet.")

    def stop_sniffer(self):
        """Stoppt den Sniffer-Thread elegant."""
        if self.sniff_thread and self.sniff_thread.is_alive():
            print("[+] Stoppe Sniffer...")
            self.sniff_stop_flag.set()
            self.sniff_thread.join(timeout=2)
        self.db.close()

    def _detect_packet(self, pkt):
        """Callback-Funktion für Scapy, die Deauth-Pakete erkennt."""
        if not pkt.haslayer(Dot11Deauth):
            return

        # MAC-Adresse ignorieren, falls konfiguriert
        attacker_mac = pkt.addr2
        if CFG["ignore_mac"] and attacker_mac and attacker_mac.lower() == CFG["ignore_mac"].lower():
            return
        
        rssi = -1000 # Standardwert für RSSI
        ch = -1
        
        if pkt.haslayer(RadioTap):
            rssi_val = pkt[RadioTap].dBm_AntSignal
            if rssi_val is not None:
                rssi = rssi_val

            freq = pkt[RadioTap].ChannelFrequency
            if freq:
                if 2412 <= freq <= 2484:
                    ch = (freq - 2407) // 5
                elif 5180 <= freq <= 5825:
                    ch = (freq - 5000) // 5

        # Zusätzliche Informationen für die erweiterte Protokollierung
        receiver_mac = pkt.addr1 if pkt.haslayer(Dot11) else None
        bssid = pkt.addr3 if pkt.haslayer(Dot11) else None
        
        counter_attack_status = "Nein"
        if self.auto_counter_enabled:
            # Sende Gegenangriff an den Angreifer
            self._counter_attack(attacker_mac, receiver_mac)
            counter_attack_status = "Ja"

        ts = datetime.now().strftime("%H:%M:%S")
        self.db.add_event(ts, attacker_mac, receiver_mac, bssid, rssi, ch, counter_attack_status)
        
        if self.gui_queue:
            self.gui_queue.put((ts, attacker_mac, receiver_mac, bssid, rssi, ch, counter_attack_status))

    def _counter_attack(self, attacker_mac, receiver_mac):
        """Startet einen Deauth-Gegenangriff gegen den Angreifer."""
        print(f"[!] Gegenangriff gestartet gegen: {attacker_mac}")
        
        # Sende Deauth-Pakete an den Angreifer
        for _ in range(5):  # Sende 5 Pakete als Beispiel
            deauth_pkt = RadioTap() / Dot11(addr1=attacker_mac, addr2=receiver_mac, addr3=receiver_mac) / Dot11Deauth(reason=7)
            sendp(deauth_pkt, iface=self.iface_mon, verbose=0)
            time.sleep(0.1)

    def start_honey_ap(self):
        """Startet den Honey-AP auf dem zweiten Interface."""
        if not self.iface_honey:
            print("[!] Kein Honey-AP Interface verfügbar.")
            return

        print(f"[+] Starte Honey-AP auf {self.iface_honey}...")
        
        hostapd_conf = f"""
interface={self.iface_honey}
ssid={CFG["ssid"]}
channel={CFG["chan"]}
driver=nl80211
hw_mode=g
wpa=0
"""
        dnsmasq_conf = f"""
interface={self.iface_honey}
dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h
"""
        try:
            with open("/tmp/hg_hostapd.conf", "w") as f:
                f.write(hostapd_conf)
            with open("/tmp/hg_dnsmasq.conf", "w") as f:
                f.write(dnsmasq_conf)
        except IOError as e:
            print(f"[!] Fehler beim Erstellen der Konfigurationsdateien: {e}")
            return
        
        run_command(["ip", "addr", "flush", "dev", self.iface_honey])
        run_command(["ip", "addr", "add", "192.168.66.1/24", "dev", self.iface_honey])
        
        self.honey_procs.append(subprocess.Popen(["hostapd", "/tmp/hg_hostapd.conf"]))
        self.honey_procs.append(subprocess.Popen(["dnsmasq", "-C", "/tmp/hg_dnsmasq.conf"]))
        
        self.honey_on = True
        print("[+] Honey-AP ist AKTIV.")

    def stop_honey_ap(self):
        """Stoppt alle Honey-AP-Prozesse."""
        if not self.honey_on:
            return
            
        print("[+] Stoppe Honey-AP...")
        for p in self.honey_procs:
            if p.poll() is None:
                p.terminate()
        self.honey_procs = []
        
        run_command(["pkill", "-f", "dnsmasq"])
        run_command(["pkill", "-f", "hostapd"])

        self.honey_on = False
        print("[+] Honey-AP ist GESTOPPT.")

# ----------------- GUI -----------------
class EliteGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DeAuth-Guard: Verbesserte Version")
        self.root.geometry("1000x700") # Vergrößere das Fenster
        self.root.configure(bg="#2c3e50")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.guard = None
        self.mon_iface_name = None
        self.honey_iface_name = None
        self.message_queue = Queue()
        self.channel_hopper = None
        self.rssi_tracker = {}
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#34495e", foreground="#ecf0f1", fieldbackground="#34495e", font=("Consolas", 10))
        style.map("Treeview", background=[("selected", "#3498db")])
        style.configure("TButton", font=("Consolas", 11), padding=6, background="#3498db", foreground="white")
        style.map("TButton", background=[("active", "#2980b9")])
        style.configure("TEntry", font=("Consolas", 11))
        style.configure("Highlight.Treeview", background="#c0392b", foreground="white") # rot
        style.configure("Counter.Treeview", background="#2ecc71", foreground="white") # grün für Gegenmaßnahme

        self.setup_ui()
        self.root.after(100, self.process_queue)

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#2c3e50", padx=10, pady=10)
        main_frame.pack(fill="both", expand=True)

        monitor_adapters = get_monitor_interfaces()
        if not monitor_adapters:
            tk.Label(main_frame, text="Kein Monitor-Adapter gefunden!", fg="#e74c3c", bg="#2c3e50", font=("Consolas", 14)).pack()
            self.start_btn = tk.Button(main_frame, text="Starten", state="disabled")
            self.start_btn.pack(pady=10)
            return

        config_frame = tk.LabelFrame(main_frame, text="Konfiguration", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12), padx=10, pady=10)
        config_frame.pack(fill="x", pady=10)

        tk.Label(config_frame, text="Sniffer-Adapter:", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12)).grid(row=0, column=0, sticky="w", pady=2, padx=5)
        self.mon_var = tk.StringVar(value=monitor_adapters[0])
        tk.OptionMenu(config_frame, self.mon_var, *monitor_adapters).grid(row=0, column=1, sticky="ew", pady=2, padx=5)

        tk.Label(config_frame, text="MAC ignorieren:", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12)).grid(row=1, column=0, sticky="w", pady=2, padx=5)
        self.ignore_mac_var = tk.StringVar(value="")
        tk.Entry(config_frame, textvariable=self.ignore_mac_var, font=("Consolas", 11)).grid(row=1, column=1, sticky="ew", pady=2, padx=5)
        
        self.channel_hopping_var = tk.IntVar(value=0)
        tk.Checkbutton(config_frame, text="Kanalwechsel aktivieren (1, 6, 11)", variable=self.channel_hopping_var, bg="#2c3e50", fg="#ecf0f1", font=("Consolas", 11), selectcolor="#34495e").grid(row=2, column=0, columnspan=2, sticky="w", pady=5, padx=5)
        
        self.auto_counter_var = tk.IntVar(value=0)
        tk.Checkbutton(config_frame, text="Automatische Gegenmaßnahme aktivieren", variable=self.auto_counter_var, bg="#2c3e50", fg="#ecf0f1", font=("Consolas", 11), selectcolor="#34495e").grid(row=3, column=0, columnspan=2, sticky="w", pady=5, padx=5)
        
        honey_adapters = [i for i in monitor_adapters if i != self.mon_var.get()]
        if honey_adapters:
            self.honey_var = tk.StringVar(value=honey_adapters[0])
            tk.Label(config_frame, text="Honey-AP-Adapter:", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12)).grid(row=4, column=0, sticky="w", pady=2, padx=5)
            tk.OptionMenu(config_frame, self.honey_var, *honey_adapters).grid(row=4, column=1, sticky="ew", pady=2, padx=5)
        else:
            self.honey_var = tk.StringVar(value=None)
            tk.Label(config_frame, text="Kein zweiter Adapter für Honey-AP verfügbar.", fg="#e74c3c", bg="#2c3e50", font=("Consolas", 10)).grid(row=4, column=0, columnspan=2, sticky="ew", pady=2, padx=5)

        config_frame.grid_columnconfigure(1, weight=1)

        self.start_btn = tk.Button(main_frame, text="▶️ Starte Sniffer", command=self.start_all, bg="#27ae60", fg="white", font=("Consolas", 11))
        self.start_btn.pack(pady=10, ipadx=10, ipady=5)

        self.tree = ttk.Treeview(main_frame, columns=("Time", "Attacker MAC", "Receiver MAC", "BSSID", "RSSI", "CH", "Counter-Attack"), show="headings", height=15)
        self.tree.tag_configure("highlight", background="#c0392b", foreground="white") # Rot für höchste RSSI
        self.tree.tag_configure("counter", background="#27ae60", foreground="white") # Grün für Gegenmaßnahme
        
        for col in ("Time", "Attacker MAC", "Receiver MAC", "BSSID", "RSSI", "CH", "Counter-Attack"):
            self.tree.heading(col, text=col.upper())
        self.tree.column("Time", width=80, anchor="center")
        self.tree.column("Attacker MAC", width=120, anchor="center")
        self.tree.column("Receiver MAC", width=120, anchor="center")
        self.tree.column("BSSID", width=120, anchor="center")
        self.tree.column("RSSI", width=60, anchor="center")
        self.tree.column("CH", width=40, anchor="center")
        self.tree.column("Counter-Attack", width=100, anchor="center")

        self.tree.pack(fill="both", expand=True, pady=10)
        
        self.status_lbl = tk.Label(main_frame, text="Wähle Adapter und drücke Start", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12))
        self.status_lbl.pack(pady=5)

        btn_frame = tk.Frame(main_frame, bg="#2c3e50")
        btn_frame.pack(pady=10)

        self.stop_btn = tk.Button(btn_frame, text="🛑 Stopp & Wiederherstellen", command=self.on_close, bg="#c0392b", fg="white", font=("Consolas", 11))
        self.stop_btn.pack(side="left", padx=5)

        self.honey_btn = tk.Button(btn_frame, text="🍯 Honey-AP ON", command=self.toggle_honey, bg="#f39c12", fg="white", font=("Consolas", 11))
        self.honey_btn.pack(side="left", padx=5)

        self.clear_btn = tk.Button(btn_frame, text="🧹 DB löschen", command=self.clear_database, bg="#3498db", fg="white", font=("Consolas", 11))
        self.clear_btn.pack(side="left", padx=5)

    def start_all(self):
        """Startet den Monitor-Mode, den Sniffer und den Kanalwechsel."""
        iface = self.mon_var.get()
        ignore_mac = self.ignore_mac_var.get()
        channel_hopping_enabled = self.channel_hopping_var.get()
        auto_counter_enabled = self.auto_counter_var.get()

        self.mon_iface_name = enable_monitor_mode(iface)
        if not self.mon_iface_name:
            messagebox.showerror("Fehler", "Monitor-Mode konnte nicht aktiviert werden.")
            return
        
        # Initialer Kanal setzen
        set_channel(self.mon_iface_name, CFG["chan"])
        
        # Setze die globalen Konfigurationswerte
        CFG["ignore_mac"] = ignore_mac if ignore_mac else None
        
        self.honey_iface_name = self.honey_var.get() if self.honey_var.get() != "None" else None

        self.guard = DeauthGuard(
            iface_mon=self.mon_iface_name,
            iface_honey=self.honey_iface_name,
            gui_queue=self.message_queue,
            auto_counter=bool(auto_counter_enabled)
        )
        self.guard.start_sniffer()
        self.load_events_from_db()

        if channel_hopping_enabled:
            self.channel_hopper = ChannelHopper(self.mon_iface_name)
            self.channel_hopper.start()

        self.status_lbl.config(text=f"Sniffer läuft auf: {self.mon_iface_name} (Kanalwechsel: {'Aktiv' if channel_hopping_enabled else 'Inaktiv'})")
        self.start_btn.config(state="disabled", text="Läuft...")

    def load_events_from_db(self):
        """Lädt alle Events aus der DB und füllt das Treeview."""
        self.clear_treeview()
        events = self.guard.db.get_all_events()
        for event in events:
            _, ts, attacker_mac, receiver_mac, bssid, rssi, ch, counter_attack = event
            self.add_to_treeview(ts, attacker_mac, receiver_mac, bssid, rssi, ch, counter_attack)
    
    def add_to_treeview(self, ts, attacker_mac, receiver_mac, bssid, rssi, ch, counter_attack):
        """Fügt einen Eintrag zum T
