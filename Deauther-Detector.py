import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import queue
import random
from datetime import datetime, timedelta

# --- WICHTIGE VORAUSSETZUNGEN FÜR ECHTE FUNKTIONALITÄT ---
# 1. Scapy installieren: pip install scapy
# 2. WLAN-Adapter in den Monitor-Modus versetzen (Betriebssystemabhängig!)
#    - Linux Beispiel: sudo airmon-ng start wlan0; sudo ifconfig wlan0mon up
#    - Windows: Installieren Sie Npcap mit aktivierter Option "Support raw 802.11 traffic (and monitor mode) for wireless adapters".
#               Nicht alle WLAN-Adapter unterstützen den Monitor-Modus unter Windows.
#               Möglicherweise müssen Sie den Adapter manuell in den Monitor-Modus versetzen, falls dies nicht automatisch geschieht.
# 3. Skript mit Administrator-/Root-Rechten ausführen (z.B. sudo python IhrSkriptname.py unter Linux/macOS,
#    als Administrator unter Windows).
# -----------------------------------------------------------

try:
    from scapy.all import Dot11, Dot11Deauth, sniff, RadioTap # Import Scapy für echte Paketanalyse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNUNG: Scapy wurde nicht gefunden. Der Detektor läuft im Simulationsmodus.")
    print("Bitte installieren Sie Scapy (pip install scapy) für echte Funktionalität.")

# --- Honeypot-Simulation & Erweiterte Funktionen ---
class HoneypotSimulator:
    def __init__(self, data_queue):
        self.data_queue = data_queue
        self.honeypot_active = False
        self.attacker_macs = set()  # Gespeicherte Angreifer-MACs

    def simulate_attacker_response(self, src_mac):
        """Simuliert eine automatische Reaktion auf Angreifer (z.B. Gegenmaßnahmen)."""
        if src_mac not in self.attacker_macs:
            self.attacker_macs.add(src_mac)
            self.data_queue.put({
                "type": "honeypot",
                "message": f"⚠️ HONEYPOT TRIGGERED! Angreifer {src_mac} isoliert.",
                "severity": "critical"
            })
            return f"Gegenmaßnahme: Fake-AP für {src_mac} gestartet"
        return None

# --- GUI mit Honeypot-Integration ---
class DeauthDetectorGUI:
    def __init__(self, master):
        self.master = master
        master.title("Deauth Detektor + Honeypot")
        master.geometry("1000x700")

        self.data_queue = queue.Queue()
        self.detection_active = False
        self.honeypot = HoneypotSimulator(self.data_queue)
        self.running = True # Flag für das sichere Beenden des Threads
        self.sniff_thread = None # Referenz auf den Sniffing-Thread
        self.deauth_timestamps = [] # Speichert Zeitstempel von Deauth-Paketen für die Fensterlogik

        # --- Styles ---
        self.setup_styles()

        # --- Frames ---
        self.setup_frames()

        # --- Widgets ---
        self.setup_status_frame()
        self.setup_interface_frame() # Neues Frame für die Schnittstelle
        self.setup_alert_frame()
        self.setup_rssi_frame()
        self.setup_honeypot_frame()
        self.setup_log_frame()

        # --- Starte GUI Update-Loop ---
        self.master.after(100, self.update_gui)

        # --- Protokoll für das Schließen des Fensters ---
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        # Progressbar-Farben
        self.style.configure("Red.Horizontal.TProgressbar", background='#FF0000', troughcolor='white')
        self.style.configure("Orange.Horizontal.TProgressbar", background='#FF8C00', troughcolor='white')
        self.style.configure("Yellow.Horizontal.TProgressbar", background='#FFFF00', troughcolor='white')
        self.style.configure("Green.Horizontal.TProgressbar", background='#00FF00', troughcolor='white')
        # Alarm-Label
        self.style.configure("Critical.TLabel", foreground="red", font=('Arial', 16, 'bold'))
        self.style.configure("Warning.TLabel", foreground="orange", font=('Arial', 14))
        self.style.configure("Normal.TLabel", foreground="green", font=('Arial', 12))

    def setup_frames(self):
        self.status_frame = ttk.LabelFrame(self.master, text="Status", padding=10)
        self.interface_frame = ttk.LabelFrame(self.master, text="Netzwerkschnittstelle", padding=10) # Neues Frame
        self.alert_frame = ttk.LabelFrame(self.master, text="Alarm", padding=10)
        self.rssi_frame = ttk.LabelFrame(self.master, text="Signalstärke (RSSI)", padding=10)
        self.honeypot_frame = ttk.LabelFrame(self.master, text="Honeypot Control", padding=10)
        self.log_frame = ttk.LabelFrame(self.master, text="Ereignis-Log", padding=10)
        
        for frame in [self.status_frame, self.interface_frame, self.alert_frame, self.rssi_frame, self.honeypot_frame, self.log_frame]:
            frame.pack(fill="x", padx=10, pady=5)

    def setup_status_frame(self):
        self.status_label = ttk.Label(self.status_frame, text="Detektor: Inaktiv", style="Normal.TLabel")
        self.status_label.pack()
        
        self.start_btn = ttk.Button(self.status_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_btn.pack(pady=5)

    def setup_interface_frame(self):
        self.interface_label = ttk.Label(self.interface_frame, text="Schnittstelle (z.B. wlan0mon, Wi-Fi):")
        self.interface_label.pack(side=tk.LEFT, padx=(0, 5))
        self.interface_entry = ttk.Entry(self.interface_frame, width=30)
        self.interface_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # Standardwert für Linux/Windows, anpassen bei Bedarf
        self.interface_entry.insert(0, "wlan0mon" if SCAPY_AVAILABLE else "simuliert") 
        if not SCAPY_AVAILABLE:
            self.interface_entry.config(state="disabled") # Deaktivieren, wenn Scapy nicht da ist

    def setup_alert_frame(self):
        self.alert_label = ttk.Label(self.alert_frame, text="KEIN ANGRIFF AKTIV", style="Normal.TLabel")
        self.alert_label.pack(pady=10)

    def setup_rssi_frame(self):
        self.rssi_progress = ttk.Progressbar(self.rssi_frame, orient="horizontal", length=400, 
                                             style="Green.Horizontal.TProgressbar")
        self.rssi_progress.pack(pady=5)
        self.rssi_value_label = ttk.Label(self.rssi_frame, text="Aktueller RSSI: N/A")
        self.rssi_value_label.pack()

    def setup_honeypot_frame(self):
        self.honeypot_toggle = ttk.Checkbutton(self.honeypot_frame, text="Honeypot aktivieren",
                                               command=self.toggle_honeypot)
        self.honeypot_toggle.pack(pady=5)
        
        self.countermeasure_label = ttk.Label(self.honeypot_frame, text="Bereit für Gegenmaßnahmen...")
        self.countermeasure_label.pack()

    def setup_log_frame(self):
        self.log_text = tk.Text(self.log_frame, wrap="word", state="disabled", height=15, font=('Consolas', 10))
        self.log_text.pack(fill="both", expand=True, pady=5)
        
        # Log-Tags für Farben
        self.log_text.tag_configure("critical", foreground="red", font=('Consolas', 10, 'bold'))
        self.log_text.tag_configure("warning", foreground="orange")
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("normal", foreground="black")

    def toggle_monitoring(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Fehler", "Scapy ist nicht installiert. Der Detektor kann nur simulieren.")
            return

        self.detection_active = not self.detection_active
        status = "AKTIV" if self.detection_active else "Inaktiv"
        self.status_label.config(text=f"Detektor: {status}")
        self.start_btn.config(text="Stop Monitoring" if self.detection_active else "Start Monitoring")

        if self.detection_active:
            interface = self.interface_entry.get().strip()
            if not interface:
                messagebox.showerror("Fehler", "Bitte geben Sie eine Netzwerkschnittstelle ein.")
                self.detection_active = False
                self.status_label.config(text="Detektor: Inaktiv")
                self.start_btn.config(text="Start Monitoring")
                return

            self.deauth_timestamps = [] # Zurücksetzen bei Start
            self.sniff_thread = threading.Thread(target=self.start_sniffing, args=(interface,))
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
            self.add_log_entry(f"Starte Überwachung auf Schnittstelle: {interface}...", "info")
        else:
            if self.sniff_thread and self.sniff_thread.is_alive():
                # Sniff-Thread wird durch `stop_filter` in sniff_packets beendet
                self.add_log_entry("Beende Überwachung...", "info")
            else:
                self.add_log_entry("Überwachung gestoppt.", "info")


    def toggle_honeypot(self):
        self.honeypot.honeypot_active = not self.honeypot.honeypot_active
        status = "AKTIV" if self.honeypot.honeypot_active else "Inaktiv"
        messagebox.showinfo("Honeypot", f"Honeypot-Modus ist jetzt {status}!")
        self.add_log_entry(f"Honeypot-Modus: {status}", "info")


    def start_sniffing(self, interface):
        """Startet den Scapy-Sniffing-Prozess."""
        try:
            # filter='type management subtype deauth' ist der Filter für Deauth-Pakete
            sniff(iface=interface, prn=self.packet_callback, stop_filter=lambda x: not self.detection_active, store=0)
        except PermissionError:
            messagebox.showerror("Fehler", "Keine Berechtigung zum Sniffing. Führen Sie das Skript als Administrator/Root aus.")
            self.data_queue.put({"type": "error", "message": "Keine Berechtigung zum Sniffing."})
            self.detection_active = False
            self.master.after(0, lambda: self.status_label.config(text="Detektor: Inaktiv"))
            self.master.after(0, lambda: self.start_btn.config(text="Start Monitoring"))
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Sniffing auf {interface}: {str(e)}")
            self.data_queue.put({"type": "error", "message": f"Sniffing-Fehler: {str(e)}"})
            self.detection_active = False
            self.master.after(0, lambda: self.status_label.config(text="Detektor: Inaktiv"))
            self.master.after(0, lambda: self.start_btn.config(text="Start Monitoring"))


    def packet_callback(self, packet):
        """Wird für jedes gesniffte Paket aufgerufen."""
        if not self.detection_active:
            return # Stoppt die Verarbeitung, wenn der Detektor inaktiv ist

        if packet.haslayer(Dot11Deauth):
            try:
                src_mac = packet[Dot11].addr2 if packet[Dot11].addr2 else "N/A"
                dst_mac = packet[Dot11].addr1 if packet[Dot11].addr1 else "N/A"
                bssid = packet[Dot11].addr3 if packet[Dot11].addr3 else "N/A"

                rssi = "N/A"
                if packet.haslayer(RadioTap):
                    # RSSI kann in RadioTap als 'dbm_antsignal' oder 'power' sein
                    if hasattr(packet[RadioTap], 'dbm_antsignal'):
                        rssi = packet[RadioTap].dbm_antsignal
                    elif hasattr(packet[RadioTap], 'power'): # Manchmal auch 'power'
                        rssi = packet[RadioTap].power

                current_time = datetime.now()
                self.deauth_timestamps.append(current_time)

                # Entferne alte Zeitstempel (z.B. älter als 5 Sekunden)
                window_start_time = current_time - timedelta(seconds=5)
                self.deauth_timestamps = [ts for ts in self.deauth_timestamps if ts >= window_start_time]
                
                num_deauth_in_window = len(self.deauth_timestamps)

                severity = "normal"
                if num_deauth_in_window >= 10:
                    severity = "critical"
                elif num_deauth_in_window >= 5:
                    severity = "warning"

                self.data_queue.put({
                    "type": "deauth",
                    "timestamp": current_time.strftime('%H:%M:%S'),
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "bssid": bssid,
                    "rssi": rssi,
                    "num_deauth_in_window": num_deauth_in_window,
                    "severity": severity
                })

                # Honeypot-Reaktion wenn aktiv
                if self.honeypot.honeypot_active and severity == "critical":
                    countermeasure = self.honeypot.simulate_attacker_response(src_mac)
                    if countermeasure:
                        self.data_queue.put({
                            "type": "countermeasure",
                            "message": countermeasure,
                            "severity": "info"
                        })

            except Exception as e:
                # Fehler beim Parsen des Pakets oder bei der Datenverarbeitung
                self.data_queue.put({"type": "error", "message": f"Fehler beim Verarbeiten des Deauth-Pakets: {str(e)}"})

    def update_gui(self):
        try:
            while True:
                data = self.data_queue.get_nowait()
                self.process_data(data)
        except queue.Empty:
            pass
        except Exception as e:
            messagebox.showerror("Fehler", f"Ein Fehler ist aufgetreten: {str(e)}")
            self.add_log_entry(f"GUI-Update-Fehler: {str(e)}", "critical")
            
        self.master.after(100, self.update_gui)

    def process_data(self, data):
        if data["type"] == "deauth":
            self.process_deauth_packet(data)
        elif data["type"] == "honeypot":
            self.add_log_entry(data["message"], data["severity"])
        elif data["type"] == "countermeasure":
            self.countermeasure_label.config(text=data["message"])
            self.add_log_entry(data["message"], data["severity"])
        elif data["type"] == "error":
            messagebox.showerror("Fehler", data["message"])
            self.add_log_entry(f"FEHLER: {data['message']}", "critical")

    def process_deauth_packet(self, data):
        # RSSI-Anzeige
        rssi = data["rssi"]
        if isinstance(rssi, (int, float)):
            # Skaliere RSSI von -90 (0%) bis -30 (100%) für die Progressbar
            # RSSI-Bereich ist 60 (-30 - -90)
            progress_value = max(0, min(100, (rssi + 90) / 60 * 100))
            self.rssi_progress["value"] = progress_value
            self.rssi_value_label.config(text=f"Aktueller RSSI: {rssi} dBm")
            
            # Progressbar-Farbe anpassen basierend auf RSSI-Wert
            if rssi >= -40: # Sehr gut
                self.rssi_progress.config(style="Green.Horizontal.TProgressbar")
            elif rssi >= -60: # Gut
                self.rssi_progress.config(style="Yellow.Horizontal.TProgressbar")
            elif rssi >= -80: # Mittel
                self.rssi_progress.config(style="Orange.Horizontal.TProgressbar")
            else: # Schwach
                self.rssi_progress.config(style="Red.Horizontal.TProgressbar")
        else:
            self.rssi_progress["value"] = 0
            self.rssi_progress.config(style="Red.Horizontal.TProgressbar")
            self.rssi_value_label.config(text=f"Aktueller RSSI: {rssi} (Nicht verfügbar)")


        # Alarm-Logik
        if data["num_deauth_in_window"] >= 10 and self.detection_active:
            self.alert_label.config(text="!!! DEAUTH-ANGRIFF !!!", style="Critical.TLabel")
            self.master.bell()
        elif data["num_deauth_in_window"] >= 5:
            self.alert_label.config(text="Möglicher Angriff", style="Warning.TLabel")
        else:
            self.alert_label.config(text="Kein Angriff", style="Normal.TLabel")

        # Log-Eintrag
        log_msg = (
            f"[{data['timestamp']}] {data['src_mac']} → {data['dst_mac']} | "
            f"BSSID: {data['bssid']} | RSSI: {rssi} dBm | Pakete (5s): {data['num_deauth_in_window']}"
        )
        self.add_log_entry(log_msg, data["severity"])

    def add_log_entry(self, message, severity="normal"):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n", severity)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def on_closing(self):
        """Wird aufgerufen, wenn das Fenster geschlossen wird, um Threads sicher zu beenden."""
        self.running = False # Setzt das Flag, um den GUI-Update-Loop zu beenden
        self.detection_active = False # Stoppt den Sniffing-Thread
        if self.sniff_thread and self.sniff_thread.is_alive():
            # Geben Sie dem Sniffing-Thread etwas Zeit zum Beenden
            # Da stop_filter verwendet wird, sollte er sich bald beenden.
            # Ein join() hier könnte die GUI blockieren, wenn der Thread nicht schnell genug reagiert.
            pass 
        self.master.destroy() # Schließt das Tkinter-Fenster

if __name__ == "__main__":
    root = tk.Tk()
    app = DeauthDetectorGUI(root)
    root.mainloop()
