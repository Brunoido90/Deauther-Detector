#!/usr/bin/env python3
"""
DeAuth-Guard: Verbessert und stabil
Verwendung: sudo python3 deauth_final.py
"""
import os, sys, time, threading, subprocess, signal
from datetime import datetime
from queue import Queue, Empty

# Wichtige Abhängigkeiten:
# sudo apt-get update
# sudo apt-get install python3-scapy python3-tk hostapd dnsmasq aircrack-ng iw
# pip3 install scapy

try:
    from scapy.all import sniff, Dot11Deauth, RadioTap
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
    "log": "/tmp/deauth.log",
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

def log_event(mac, rssi, ch):
    """Protokolliert das Ereignis in der Konsole und in einer Datei."""
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"{ts} {mac} {rssi} dBm CH:{ch}"
    print(line)
    try:
        with open(CFG["log"], "a") as f:
            f.write(line + "\n")
    except IOError as e:
        print(f"[!] Fehler beim Schreiben der Log-Datei: {e}")

# ----------------- HAUPTKLASSE -----------------
class DeauthGuard:
    def __init__(self, iface_mon=None, iface_honey=None, gui_queue=None):
        self.iface_mon = iface_mon
        self.iface_honey = iface_honey
        self.gui_queue = gui_queue
        self.honey_on = False
        self.sniff_thread = None
        self.sniff_stop_flag = threading.Event()
        self.honey_procs = []

    def start_sniffer(self):
        """Startet den Scapy-Sniffer-Thread."""
        if not self.iface_mon:
            return
        
        # Die `sniff`-Funktion blockiert, also muss sie in einem eigenen Thread laufen.
        # Wir verwenden ein `stop_flag`, um den Thread sauber zu beenden.
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
            self.sniff_thread.join(timeout=2) # Warte auf den Thread

    def _detect_packet(self, pkt):
        """Callback-Funktion für Scapy, die Deauth-Pakete erkennt."""
        # MAC-Adresse ignorieren, falls konfiguriert
        if CFG["ignore_mac"] and pkt.addr2 and pkt.addr2.lower() == CFG["ignore_mac"].lower():
            return

        if not pkt.haslayer(Dot11Deauth):
            return
        
        mac = pkt.addr2
        rssi = "N/A"
        ch = "N/A"
        
        if pkt.haslayer(RadioTap):
            rssi_val = pkt[RadioTap].dBm_AntSignal
            if rssi_val is not None:
                rssi = str(rssi_val)

            # Korrekte Konvertierung der Frequenz in den Kanal
            freq = pkt[RadioTap].ChannelFrequency
            if freq:
                if 2412 <= freq <= 2484:
                    ch = str((freq - 2407) // 5)
                elif 5180 <= freq <= 5825:
                    ch = str((freq - 5000) // 5)

        log_event(mac, rssi, ch)
        if self.gui_queue:
            self.gui_queue.put((mac, rssi, ch))

    def start_honey_ap(self):
        """Startet den Honey-AP auf dem zweiten Interface."""
        if not self.iface_honey:
            print("[!] Kein Honey-AP Interface verfügbar.")
            return

        print(f"[+] Starte Honey-AP auf {self.iface_honey}...")
        
        # Konfigurationen für hostapd und dnsmasq in /tmp schreiben
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
        
        # IP-Adresse zuweisen
        run_command(["ip", "addr", "flush", "dev", self.iface_honey])
        run_command(["ip", "addr", "add", "192.168.66.1/24", "dev", self.iface_honey])
        
        # Hostapd und Dnsmasq starten
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
            if p.poll() is None: # Prüfe, ob der Prozess noch läuft
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
        self.root.title("DeAuth-Guard Final")
        self.root.geometry("600x650") # Fenstergröße angepasst
        self.root.configure(bg="#2c3e50") # Dunkles, cooles Thema
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.guard = None
        self.mon_iface_name = None
        self.honey_iface_name = None
        self.message_queue = Queue()

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#34495e", foreground="#ecf0f1", fieldbackground="#34495e", font=("Consolas", 11))
        style.map("Treeview", background=[("selected", "#3498db")])
        style.configure("TButton", font=("Consolas", 11), padding=6, background="#3498db", foreground="white")
        style.map("TButton", background=[("active", "#2980b9")])
        style.configure("TEntry", font=("Consolas", 11))

        self.setup_ui()
        self.root.after(100, self.process_queue) # Startet die Warteschlangenverarbeitung

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#2c3e50", padx=10, pady=10)
        main_frame.pack(fill="both", expand=True)

        # Adapter-Auswahl
        monitor_adapters = get_monitor_interfaces()
        if not monitor_adapters:
            tk.Label(main_frame, text="Kein Monitor-Adapter gefunden!", fg="#e74c3c", bg="#2c3e50", font=("Consolas", 14)).pack()
            self.start_btn = tk.Button(main_frame, text="Starten", state="disabled")
            self.start_btn.pack(pady=10)
            return

        # UI-Elemente für die Konfiguration
        config_frame = tk.LabelFrame(main_frame, text="Konfiguration", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12), padx=10, pady=10)
        config_frame.pack(fill="x", pady=10)

        # Sniffer-Adapter
        tk.Label(config_frame, text="Sniffer-Adapter:", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12)).grid(row=0, column=0, sticky="w", pady=2, padx=5)
        self.mon_var = tk.StringVar(value=monitor_adapters[0])
        tk.OptionMenu(config_frame, self.mon_var, *monitor_adapters).grid(row=0, column=1, sticky="ew", pady=2, padx=5)

        # Kanal
        tk.Label(config_frame, text="Kanal:", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12)).grid(row=1, column=0, sticky="w", pady=2, padx=5)
        self.chan_var = tk.StringVar(value="6")
        tk.Entry(config_frame, textvariable=self.chan_var, font=("Consolas", 11)).grid(row=1, column=1, sticky="ew", pady=2, padx=5)

        # MAC-Adresse ignorieren
        tk.Label(config_frame, text="MAC ignorieren:", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12)).grid(row=2, column=0, sticky="w", pady=2, padx=5)
        self.ignore_mac_var = tk.StringVar(value="")
        tk.Entry(config_frame, textvariable=self.ignore_mac_var, font=("Consolas", 11)).grid(row=2, column=1, sticky="ew", pady=2, padx=5)

        # Honey-AP Adapter
        honey_adapters = [i for i in monitor_adapters if i != self.mon_var.get()]
        if honey_adapters:
            self.honey_var = tk.StringVar(value=honey_adapters[0])
            tk.Label(config_frame, text="Honey-AP-Adapter:", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12)).grid(row=3, column=0, sticky="w", pady=2, padx=5)
            tk.OptionMenu(config_frame, self.honey_var, *honey_adapters).grid(row=3, column=1, sticky="ew", pady=2, padx=5)
        else:
            self.honey_var = tk.StringVar(value=None)
            tk.Label(config_frame, text="Kein zweiter Adapter für Honey-AP verfügbar.", fg="#e74c3c", bg="#2c3e50", font=("Consolas", 10)).grid(row=3, column=0, columnspan=2, sticky="ew", pady=2, padx=5)

        config_frame.grid_columnconfigure(1, weight=1)

        # Start-Button
        self.start_btn = tk.Button(main_frame, text="▶️ Starte Sniffer", command=self.start_all, bg="#27ae60", fg="white", font=("Consolas", 11))
        self.start_btn.pack(pady=10, ipadx=10, ipady=5)

        # TreeView für Ergebnisse
        self.tree = ttk.Treeview(main_frame, columns=("Time", "MAC", "RSSI", "CH"), show="headings", height=15)
        for col in ("Time", "MAC", "RSSI", "CH"):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=120, anchor="center")
        self.tree.pack(fill="both", expand=True, pady=10)

        # Status-Label
        self.status_lbl = tk.Label(main_frame, text="Wähle Adapter und drücke Start", fg="#ecf0f1", bg="#2c3e50", font=("Consolas", 12))
        self.status_lbl.pack(pady=5)

        # Kontroll-Buttons
        btn_frame = tk.Frame(main_frame, bg="#2c3e50")
        btn_frame.pack(pady=10)

        self.stop_btn = tk.Button(btn_frame, text="🛑 Stopp & Wiederherstellen", command=self.on_close, bg="#c0392b", fg="white", font=("Consolas", 11))
        self.stop_btn.pack(side="left", padx=5)

        self.honey_btn = tk.Button(btn_frame, text="🍯 Honey-AP ON", command=self.toggle_honey, bg="#f39c12", fg="white", font=("Consolas", 11))
        self.honey_btn.pack(side="left", padx=5)

        self.clear_btn = tk.Button(btn_frame, text="🧹 Log löschen", command=self.clear_treeview, bg="#3498db", fg="white", font=("Consolas", 11))
        self.clear_btn.pack(side="left", padx=5)


    def start_all(self):
        """Startet den Monitor-Mode und den Sniffer."""
        iface = self.mon_var.get()
        channel = self.chan_var.get()
        ignore_mac = self.ignore_mac_var.get()

        self.mon_iface_name = enable_monitor_mode(iface)
        if not self.mon_iface_name:
            messagebox.showerror("Fehler", "Monitor-Mode konnte nicht aktiviert werden.")
            return
        
        # Setze den Kanal
        set_channel(self.mon_iface_name, channel)

        # Setze die globalen Konfigurationswerte
        CFG["chan"] = channel
        CFG["ignore_mac"] = ignore_mac if ignore_mac else None

        self.honey_iface_name = self.honey_var.get() if self.honey_var.get() != "None" else None

        self.guard = DeauthGuard(
            iface_mon=self.mon_iface_name,
            iface_honey=self.honey_iface_name,
            gui_queue=self.message_queue
        )
        self.guard.start_sniffer()
        
        self.status_lbl.config(text=f"Sniffer läuft auf: {self.mon_iface_name} (Kanal: {channel})")
        self.start_btn.config(state="disabled", text="Läuft...")
        
    def add_to_treeview(self, mac, rssi, ch):
        """Fügt einen Eintrag zum Treeview hinzu."""
        ts = datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(ts, mac, rssi, ch))
        self.tree.yview_moveto(1)
        
    def process_queue(self):
        """Verarbeitet Nachrichten aus dem Sniffer-Thread."""
        try:
            while True:
                mac, rssi, ch = self.message_queue.get_nowait()
                self.add_to_treeview(mac, rssi, ch)
                self.root.update_idletasks() # Aktualisiert die GUI
        except Empty:
            pass # Keine Nachrichten mehr in der Warteschlange
        finally:
            self.root.after(100, self.process_queue) # Plant den nächsten Aufruf
            
    def toggle_honey(self):
        """Schaltet den Honey-AP ein und aus."""
        if not self.guard: return
        
        if not self.guard.honey_on:
            self.guard.start_honey_ap()
            self.honey_btn.config(text="🍯 Honey-AP OFF", bg="#e67e22")
            self.status_lbl.config(text=f"Sniffer & Honey-AP auf {self.honey_iface_name}")
        else:
            self.guard.stop_honey_ap()
            self.honey_btn.config(text="🍯 Honey-AP ON", bg="#f39c12")
            self.status_lbl.config(text=f"Sniffer läuft auf: {self.mon_iface_name}")

    def clear_treeview(self):
        """Löscht alle Einträge im Treeview."""
        for item in self.tree.get_children():
            self.tree.delete(item)

    def on_close(self):
        """Führt eine saubere Beendigung durch."""
        print("[+] Saubere Beendigung wird gestartet...")
        if self.guard:
            self.guard.stop_sniffer()
            self.guard.stop_honey_ap()
        if self.mon_iface_name:
            disable_monitor_mode(self.mon_iface_name)
        
        print("[+] Alle Dienste wurden gestoppt. Das Programm wird beendet.")
        self.root.destroy() # Schließt das Fenster

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[!] Dieses Skript muss mit root-Rechten ausgeführt werden. (sudo python3 ...)")
    
    if GUI_READY:
        root = tk.Tk()
        app = EliteGUI(root)
        root.mainloop()
    else:
        # Fallback ohne GUI, falls tkinter fehlt
        print("[+] Führe im Konsolen-Modus aus.")
        mon_ifaces = get_monitor_interfaces()
        if not mon_ifaces:
            sys.exit("[!] Kein Monitor-Adapter verfügbar.")
            
        print("\n[+] WLAN-Adapter mit Monitor-Unterstützung:")
        for idx, iface in enumerate(mon_ifaces, 1):
            print(f"  {idx}) {iface}")
        
        try:
            selection = input("Wählen Sie einen Adapter für den Sniffer [1]: ") or "1"
            iface_mon = enable_monitor_mode(mon_ifaces[int(selection) - 1])
        except (ValueError, IndexError):
            sys.exit("[!] Ungültige Auswahl.")
        
        iface_honey = next((i for i in mon_ifaces if i != iface_mon), None)
        
        guard = DeauthGuard(iface_mon=iface_mon, iface_honey=iface_honey)
        guard.start_sniffer()
        
        def signal_handler(sig, frame):
            guard.stop_sniffer()
            if iface_mon:
                disable_monitor_mode(iface_mon)
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        print("\n[+] Drücken Sie Strg+C, um zu beenden.")
        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                break
        
        signal_handler(None, None)
