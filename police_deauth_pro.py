#!/usr/bin/env python3
"""
POLIZEI DeAuth-Guard ULTIMATIVE
Automatisierte Erkennung + Monitor-Mode Aktivierung
Für technisch weniger versierte Kollegen
"""

import os
import sys
import time
import subprocess
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11

class AutoDeauthDetector:
    def __init__(self):
        # Automatische Konfiguration beim Start
        self.interface = self.auto_setup()
        self.running = False
        
        if not self.interface:
            messagebox.showerror(
                "Kritischer Fehler",
                "Kein kompatibler WLAN-Adapter gefunden!\n\n"
                "Bitte:\n"
                "1. WLAN-Adapter einstecken\n"
                "2. Treiber installieren\n"
                "3. System neustarten"
            )
            sys.exit(1)

    def auto_setup(self):
        """Automatische Adaptererkennung und Konfiguration"""
        # 1. Verfügbare Adapter finden
        ifaces = self.detect_interfaces()
        
        # 2. Monitor-Mode aktivieren
        for iface in ifaces:
            if self.force_monitor_mode(iface):
                return iface
        return None

    def detect_interfaces(self):
        """Erkennt alle WLAN-Adapter mit 3 Methoden"""
        methods = [
            self._detect_via_ip_link,  # Modernste Methode
            self._detect_via_sysfs,    # Universell
            self._detect_via_iwconfig  # Legacy
        ]
        
        for method in methods:
            try:
                ifaces = method()
                if ifaces:
                    return ifaces
            except:
                continue
        return []

    @staticmethod
    def _detect_via_ip_link():
        """Erkennung mit ip-Befehl (modern)"""
        output = subprocess.check_output(["ip", "link", "show"], text=True)
        return [
            line.split(':')[1].split()[0] 
            for line in output.split('\n') 
            if 'state UP' in line and 'wireless' in line
        ]

    @staticmethod
    def _detect_via_sysfs():
        """SysFS Methode (Linux Kernel)"""
        return [
            iface for iface in os.listdir('/sys/class/net') 
            if os.path.exists(f'/sys/class/net/{iface}/wireless')
        ]

    @staticmethod
    def _detect_via_iwconfig():
        """Wireless Extensions (Legacy)"""
        output = subprocess.check_output(["iwconfig"], text=True, stderr=subprocess.DEVNULL)
        return [line.split()[0] for line in output.split('\n') if "IEEE" in line]

    def force_monitor_mode(self, interface):
        """Aktiviert Monitor-Mode mit allen verfügbaren Methoden"""
        methods = [
            f"ip link set {interface} down && iw {interface} set monitor control && ip link set {interface} up",
            f"airmon-ng check kill && airmon-ng start {interface}",
            f"ifconfig {interface} down && iwconfig {interface} mode monitor && ifconfig {interface} up"
        ]
        
        for cmd in methods:
            try:
                subprocess.run(cmd, shell=True, check=True, timeout=30)
                time.sleep(2)  # Wartezeit für Interface-Aktivierung
                
                # Erfolgsprüfung
                result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
                if "Mode:Monitor" in result.stdout:
                    return True
            except:
                continue
        return False

    def start_detection(self):
        """Startet die automatische DeAuth-Erkennung"""
        self.running = True
        sniff(iface=self.interface,
              prn=self.handle_packet,
              store=False,
              monitor=True)

    def handle_packet(self, pkt):
        """Verarbeitet erkannte DeAuth-Pakete"""
        if pkt.haslayer(Dot11Deauth):
            attacker = pkt.addr2[:8] + "..." if pkt.addr2 else "Unknown"
            target = pkt.addr1[:8] + "..." if pkt.addr1 else "Unknown"
            
            # Hier könnten Sie eine Benachrichtigung einfügen
            print(f"Angriff erkannt! Angreifer: {attacker} -> Ziel: {target}")

    def stop(self):
        """Stoppt die Überwachung"""
        self.running = False

class SimpleGUI:
    """Minimale GUI für Kollegen"""
    def __init__(self):
        self.detector = AutoDeauthDetector()
        self.setup_gui()

    def setup_gui(self):
        """Erstellt eine einfache Statusanzeige"""
        self.root = tk.Tk()
        self.root.title("POLIZEI DeAuth-Guard")
        self.root.geometry("400x200")
        
        tk.Label(
            self.root, 
            text="DeAuth-Angriffsdetektor",
            font=("Arial", 16)
        ).pack(pady=20)
        
        tk.Label(
            self.root,
            text=f"Aktives Interface: {self.detector.interface}",
            font=("Arial", 12)
        ).pack()
        
        self.status = tk.Label(
            self.root,
            text="Status: Überwachung aktiv",
            fg="green",
            font=("Arial", 12)
        self.status.pack(pady=20)
        
        tk.Button(
            self.root,
            text="Beenden",
            command=self.cleanup,
            bg="red",
            fg="white"
        ).pack()
        
        # Starte Überwachung im Hintergrund
        threading.Thread(target=self.detector.start_detection, daemon=True).start()

    def cleanup(self):
        """Aufräumen beim Beenden"""
        self.detector.stop()
        self.root.destroy()

if __name__ == "__main__":
    # Root-Rechte prüfen
    if os.geteuid() != 0:
        print("Bitte als Administrator ausführen: sudo python3 police_deauth_auto.py")
        sys.exit(1)
    
    # GUI starten
    app = SimpleGUI()
    app.root.mainloop()
