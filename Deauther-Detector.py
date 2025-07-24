import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import queue
import random
from datetime import datetime, timedelta
import subprocess # Für die Ausführung von Shell-Befehlen

# --- WICHTIGE VORAUSSETZUNGEN FÜR ECHTE FUNKTIONALITÄT ---
# 1. Scapy installieren: pip install scapy
# 2. WLAN-Adapter in den Monitor-Modus versetzen (Betriebssystemabhängig!)
#    - Linux: Installation von 'aircrack-ng' (beinhaltet airmon-ng) ist SEHR EMPFOHLEN: sudo apt install aircrack-ng
#      Das Skript versucht, airmon-ng zu verwenden, um den Monitor-Modus automatisch zu aktivieren.
#    - Windows: Installieren Sie Npcap mit aktivierter Option "Support raw 802.11 traffic (and monitor mode) for wireless adapters".
#               Nicht alle WLAN-Adapter unterstützen den Monitor-Modus unter Windows.
#               Die automatische Umschaltung ist unter Windows sehr schwierig und wird hier nicht direkt unterstützt.
#               Sie müssen den Adapter manuell in den Monitor-Modus versetzen, falls dies unter Windows möglich ist.
# 3. Skript mit Administrator-/Root-Rechten ausführen (z.B. sudo python IhrSkriptname.py unter Linux/macOS,
#    als Administrator unter Windows).
# -----------------------------------------------------------

try:
    from scapy.all import Dot11, Dot11Deauth, sniff, RadioTap, get_if_list # get_if_list für Schnittstellen-Scan
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
        self.original_interface = None # Speichert den Namen der ursprünglichen Schnittstelle
        self.monitor_interface = None # Speichert den Namen der Monitor-Schnittstelle

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
        self.interface_label = ttk.Label(self.interface_frame, text="Wähle Schnittstelle:")
        self.interface_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.interface_combobox = ttk.Combobox(self.interface_frame, width=30, state="readonly")
        self.interface_combobox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.scan_btn = ttk.Button(self.interface_frame, text="Schnittstellen scannen", command=self.scan_interfaces)
        self.scan_btn.pack(side=tk.LEFT)

        if not SCAPY_AVAILABLE:
            self.interface_combobox.config(state="disabled")
            self.scan_btn.config(state="disabled")
            self.interface_combobox.set("Scapy nicht verfügbar (Simulation)")
        else:
            self.scan_interfaces() # Schnittstellen beim Start scannen

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

    def scan_interfaces(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Fehler", "Scapy ist nicht installiert.")
            return

        try:
            # Versuche, alle Schnittstellen zu bekommen
            all_interfaces = get_if_list()

            # Filtern, um nur WLAN-ähnliche Schnittstellen anzuzeigen (heuristisch)
            wifi_interfaces_filtered = [
                iface for iface in all_interfaces
                if "wlan" in iface.lower() or "mon" in iface.lower() or "wi-fi" in iface.lower() or "wireless" in iface.lower()
            ]

            if not wifi_interfaces_filtered:
                # Wenn keine gefilterten WLAN-Schnittstellen gefunden wurden, zeige alle an
                messagebox.showwarning("WLAN-Schnittstellen nicht direkt gefunden",
                                       "Es wurden keine offensichtlichen WLAN-Schnittstellen mit Standardnamen gefunden. "
                                       "Bitte überprüfen Sie die Liste aller erkannten Schnittstellen in der Dropdown-Liste. "
                                       "Stellen Sie sicher, dass Ihr Adapter angeschlossen und die Treiber installiert sind, "
                                       "und dass das Skript mit Administrator-/Root-Rechten läuft.")
                interfaces_to_display = all_interfaces
                self.add_log_entry(f"Keine gefilterten WLAN-Schnittstellen gefunden. Zeige alle erkannten Schnittstellen: {', '.join(all_interfaces)}", "warning")
            else:
                interfaces_to_display = wifi_interfaces_filtered
                self.add_log_entry(f"Gefilterte WLAN-Schnittstellen gefunden: {', '.join(wifi_interfaces_filtered)}", "info")

            if not interfaces_to_display:
                messagebox.showwarning("Keine Schnittstellen gefunden",
                                       "Scapy konnte überhaupt keine Netzwerkschnittstellen finden. "
                                       "Stellen Sie sicher, dass Scapy korrekt installiert ist und das Skript mit Administrator-/Root-Rechten läuft.")
                self.interface_combobox['values'] = []
                self.interface_combobox.set("")
                return

            self.interface_combobox['values'] = interfaces_to_display
            if interfaces_to_display:
                self.interface_combobox.set(interfaces_to_display[0]) # Ersten als Standard auswählen

        except PermissionError:
            messagebox.showerror("Fehler", "Berechtigungsfehler beim Scannen der Schnittstellen. "
                                           "Bitte stellen Sie sicher, dass Sie das Skript mit Administrator-/Root-Rechten ausführen (z.B. mit 'sudo').")
            self.interface_combobox['values'] = []
            self.interface_combobox.set("")
            self.add_log_entry("Fehler: Berechtigungsfehler beim Scannen der Schnittstellen.", "critical")
        except Exception as e:
            messagebox.showerror("Fehler", f"Ein unerwarteter Fehler ist beim Scannen der Schnittstellen aufgetreten: {str(e)}")
            self.interface_combobox['values'] = []
            self.interface_combobox.set("")
            self.add_log_entry(f"Unerwarteter Fehler beim Scannen der Schnittstellen: {str(e)}", "critical")

    def toggle_monitoring(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Fehler", "Scapy ist nicht installiert. Der Detektor kann nur simulieren.")
            return

        if not self.detection_active: # Start Monitoring
            selected_interface = self.interface_combobox.get().strip()
            if not selected_interface:
                messagebox.showerror("Fehler", "Bitte wählen Sie eine Netzwerkschnittstelle aus.")
                return

            self.original_interface = selected_interface # Speichern für spätere Rücksetzung
            self.add_log_entry(f"Versuche, Schnittstelle {self.original_interface} in den Monitor-Modus zu versetzen...", "info")
            
            # Versuche, den Monitor-Modus zu aktivieren (Linux-spezifisch mit airmon-ng)
            try:
                # airmon-ng check kill beendet störende Prozesse
                check_kill_result = subprocess.run(["airmon-ng", "check", "kill"], check=True, capture_output=True, text=True)
                self.add_log_entry(f"airmon-ng check kill Output: {check_kill_result.stdout.strip()}", "info")
                if check_kill_result.stderr:
                    self.add_log_entry(f"airmon-ng check kill Stderr: {check_kill_result.stderr.strip()}", "warning")
                self.add_log_entry("Störende Prozesse beendet.", "info")

                # airmon-ng start versetzt die Schnittstelle in den Monitor-Modus
                start_monitor_result = subprocess.run(["airmon-ng", "start", self.original_interface], check=True, capture_output=True, text=True)
                self.add_log_entry(f"airmon-ng start Output: {start_monitor_result.stdout.strip()}", "info")
                if start_monitor_result.stderr:
                    self.add_log_entry(f"airmon-ng start Stderr: {start_monitor_result.stderr.strip()}", "warning")

                output_lines = []
                # Überprüfen, ob die Ausgabe ein String ist, um den Fehler "not text attribute" zu vermeiden
                if isinstance(start_monitor_result.stdout, str):
                    output_lines = start_monitor_result.stdout.splitlines()
                else:
                    self.add_log_entry(f"FEHLER: airmon-ng start hat unerwarteten Output-Typ geliefert: {type(start_monitor_result.stdout)}. Erwartet wurde String.", "critical")
                    messagebox.showerror("Fehler", "Unerwarteter Output von airmon-ng. Bitte überprüfen Sie Ihre airmon-ng Installation.")
                    # Force stop monitoring if unexpected output
                    self.detection_active = False
                    self.master.after(0, lambda: self.status_label.config(text="Detektor: Inaktiv"))
                    self.master.after(0, lambda: self.start_btn.config(text="Start Monitoring"))
                    self.master.after(0, lambda: self.interface_combobox.config(state="readonly"))
                    self.master.after(0, lambda: self.scan_btn.config(state="normal"))
                    return # Funktion frühzeitig beenden

                # Versuche, den Namen der neuen Monitor-Schnittstelle zu finden
                self.monitor_interface = None
                for line in output_lines:
                    if "monitor mode enabled on" in line:
                        # Beispiel: (monitor mode enabled on wlan0mon)
                        parts = line.split()
                        if len(parts) > 4 and parts[3] == "on":
                            self.monitor_interface = parts[4].strip(')')
                            break
                    elif "Monitor mode enabled for" in line:
                        # Beispiel: Monitor mode enabled for wlan0mon
                        parts = line.split()
                        if len(parts) > 3 and parts[3] == "for":
                            self.monitor_interface = parts[4].strip()
                            break
                
                if not self.monitor_interface:
                    # Fallback, falls airmon-ng den Namen nicht klar ausgibt, 
                    # oder wenn die Schnittstelle bereits im Monitor-Modus war und der Name gleich blieb.
                    # Dies ist eine Heuristik und kann fehlschlagen.
                    if "mon" in self.original_interface:
                        self.monitor_interface = self.original_interface
                    else:
                        # Versuch, den Namen mit 'mon' anzuhängen
                        self.monitor_interface = self.original_interface + "mon" 
                    self.add_log_entry(f"Konnte Monitor-Schnittstelle nicht eindeutig aus airmon-ng Output extrahieren. Versuche: {self.monitor_interface}", "warning")

                self.add_log_entry(f"Schnittstelle {self.original_interface} erfolgreich in Monitor-Modus versetzt. Neue Schnittstelle: {self.monitor_interface}", "info")
                
                # Aktualisiere die GUI, um die Monitor-Schnittstelle anzuzeigen
                self.interface_combobox.set(self.monitor_interface)
                self.interface_combobox.config(state="disabled") # Deaktivieren während der Überwachung
                self.scan_btn.config(state="disabled")

                self.detection_active = True
                self.status_label.config(text=f"Detektor: AKTIV (Schnittstelle: {self.monitor_interface})")
                self.start_btn.config(text="Stop Monitoring")
                self.deauth_timestamps = [] # Zurücksetzen bei Start
                self.sniff_thread = threading.Thread(target=self.start_sniffing, args=(self.monitor_interface,))
                self.sniff_thread.daemon = True
                self.sniff_thread.start()

            except FileNotFoundError:
                messagebox.showerror("Fehler", "airmon-ng nicht gefunden. Bitte installieren Sie aircrack-ng (sudo apt install aircrack-ng).")
                self.add_log_entry("Fehler: airmon-ng nicht gefunden.", "critical")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Fehler", f"Fehler beim Ausführen von airmon-ng: {e.stderr}\n"
                                               "Stellen Sie sicher, dass Sie das Skript mit Administrator-/Root-Rechten ausführen.")
                self.add_log_entry(f"Fehler bei airmon-ng: {e.stderr}", "critical")
            except Exception as e:
                messagebox.showerror("Fehler", f"Ein unerwarteter Fehler ist aufgetreten: {str(e)}")
                self.add_log_entry(f"Unerwarteter Fehler: {str(e)}", "critical")
            
        else: # Stop Monitoring
            self.detection_active = False
            self.status_label.config(text="Detektor: Inaktiv")
            self.start_btn.config(text="Start Monitoring")
            self.interface_combobox.config(state="readonly") # Wieder aktivieren
            self.scan_btn.config(state="normal")
            
            self.add_log_entry("Beende Überwachung...", "info")
            if self.sniff_thread and self.sniff_thread.is_alive():
                # Der sniff_thread wird durch `stop_filter` beendet
                pass 
            
            # Versuche, den Monitor-Modus zu deaktivieren (Linux-spezifisch)
            if self.monitor_interface and self.original_interface:
                try:
                    self.add_log_entry(f"Setze Schnittstelle {self.original_interface} zurück in den Managed-Modus...", "info")
                    subprocess.run(["airmon-ng", "stop", self.monitor_interface], check=True, capture_output=True, text=True)
                    # NetworkManager neu starten, um die Konnektivität wiederherzustellen
                    subprocess.run(["systemctl", "start", "NetworkManager"], check=False, capture_output=True, text=True)
                    self.add_log_entry(f"Schnittstelle {self.original_interface} erfolgreich zurückgesetzt. NetworkManager neu gestartet.", "info")
                    self.monitor_interface = None
                    self.original_interface = None
                    self.scan_interfaces() # Schnittstellenliste aktualisieren
                except FileNotFoundError:
                    self.add_log_entry("airmon-ng nicht gefunden, konnte Monitor-Modus nicht deaktivieren.", "warning")
                except subprocess.CalledProcessError as e:
                    self.add_log_entry(f"Fehler beim Deaktivieren des Monitor-Modus: {e.stderr}", "warning")
                except Exception as e:
                    self.add_log_entry(f"Unerwarteter Fehler beim Zurücksetzen des Monitor-Modus: {str(e)}", "warning")


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
            self.master.after(0, lambda: self.interface_combobox.config(state="readonly"))
            self.master.after(0, lambda: self.scan_btn.config(state="normal"))
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Sniffing auf {interface}: {str(e)}")
            self.data_queue.put({"type": "error", "message": f"Sniffing-Fehler: {str(e)}"})
            self.detection_active = False
            self.master.after(0, lambda: self.status_label.config(text="Detektor: Inaktiv"))
            self.master.after(0, lambda: self.start_btn.config(text="Start Monitoring"))
            self.master.after(0, lambda: self.interface_combobox.config(state="readonly"))
            self.master.after(0, lambda: self.scan_btn.config(state="normal"))


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
        
        # Versuche, den Monitor-Modus zu deaktivieren, wenn er aktiv war
        if self.monitor_interface and self.original_interface:
            try:
                self.add_log_entry(f"Setze Schnittstelle {self.original_interface} zurück in den Managed-Modus...", "info")
                subprocess.run(["airmon-ng", "stop", self.monitor_interface], check=True, capture_output=True, text=True)
                # NetworkManager neu starten, um die Konnektivität wiederherzustellen
                subprocess.run(["systemctl", "start", "NetworkManager"], check=False, capture_output=True, text=True)
                self.add_log_entry(f"Schnittstelle {self.original_interface} erfolgreich zurückgesetzt. NetworkManager neu gestartet.", "info")
            except FileNotFoundError:
                self.add_log_entry("airmon-ng nicht gefunden, konnte Monitor-Modus nicht deaktivieren beim Schließen.", "warning")
            except subprocess.CalledProcessError as e:
                self.add_log_entry(f"Fehler beim Deaktivieren des Monitor-Modus beim Schließen: {e.stderr}", "warning")
            except Exception as e:
                self.add_log_entry(f"Unerwarteter Fehler beim Zurücksetzen des Monitor-Modus beim Schließen: {str(e)}", "warning")

        if self.sniff_thread and self.sniff_thread.is_alive():
            # Geben Sie dem Sniffing-Thread etwas Zeit zum Beenden
            # Da stop_filter verwendet wird, sollte er sich bald beenden.
            pass 
        self.master.destroy() # Schließt das Tkinter-Fenster

if __name__ == "__main__":
    root = tk.Tk()
    app = DeauthDetectorGUI(root)
    root.mainloop()
