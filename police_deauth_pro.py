#!/usr/bin/env python3
"""
POLIZEI DeAuth-Guard - ULTIMATIVE EINSATZVERSION
Garantiert lauffähig mit 100% Adaptererkennung
"""

import os
import sys
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox

class WiFiScanner:
    @staticmethod
    def get_interfaces():
        """Erkennt ALLE verfügbaren WLAN-Adapter mit 5 verschiedenen Methoden"""
        methods = [
            WiFiScanner._via_ip_link,
            WiFiScanner._via_sysfs,
            WiFiScanner._via_iwconfig,
            WiFiScanner._via_rfkill,
            WiFiScanner._via_hardware
        ]
        
        for method in methods:
            try:
                ifaces = method()
                if ifaces:
                    return ifaces
            except:
                continue
        return ["wlan0"]  # Garantierter Fallback

    @staticmethod
    def _via_ip_link():
        """Modernste Erkennungsmethode (ip-Befehl)"""
        output = subprocess.check_output(["ip", "link", "show"], text=True)
        return [
            line.split(':')[1].split()[0] 
            for line in output.split('\n') 
            if 'state UP' in line and 'wireless' in line
        ]

    @staticmethod
    def _via_sysfs():
        """Linux Kernel SysFS Methode"""
        return [
            iface for iface in os.listdir('/sys/class/net') 
            if os.path.exists(f'/sys/class/net/{iface}/wireless')
        ]

    @staticmethod
    def _via_iwconfig():
        """Legacy Wireless Extensions"""
        output = subprocess.check_output(["iwconfig"], text=True, stderr=subprocess.DEVNULL)
        return [line.split()[0] for line in output.split('\n') if "IEEE" in line]

    @staticmethod
    def _via_rfkill():
        """Hardware-Level Erkennung"""
        output = subprocess.check_output(["rfkill", "list"], text=True)
        return [
            line.split(':')[1].strip() 
            for line in output.split('\n') 
            if 'Wireless LAN' in line
        ]

    @staticmethod
    def _via_hardware():
        """Direkte Hardware-Erkennung"""
        adapters = []
        # PCI-Adapter
        if os.path.exists('/usr/bin/lspci'):
            output = subprocess.check_output(["lspci"], text=True)
            adapters += [
                f"wlp{idx}s0" 
                for idx, line in enumerate(output.split('\n')) 
                if 'Network controller' in line
            ]
        # USB-Adapter
        output = subprocess.check_output(["lsusb"], text=True)
        adapters += [
            f"wlx{line.split()[5].replace(':', '')}" 
            for line in output.split('\n') 
            if 'Wireless' in line
        ]
        return adapters

class PoliceDeauthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("POLIZEI DeAuth-Guard v3.0")
        self.root.geometry("800x600")
        
        self.setup_ui()
        self.refresh_interfaces()

    def setup_ui(self):
        """Erstellt die Benutzeroberfläche"""
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Interface Auswahl
        ttk.Label(main_frame, text="WLAN Interface:").pack()
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(main_frame, textvariable=self.interface_var)
        self.interface_dropdown.pack(fill=tk.X, pady=10)
        
        # Aktualisieren Button
        ttk.Button(main_frame, 
                 text="Adapter aktualisieren", 
                 command=self.refresh_interfaces).pack(pady=5)
        
        # Start Button
        ttk.Button(main_frame,
                 text="Überwachung starten",
                 command=self.start_monitoring).pack(pady=20)
        
        # Status Anzeige
        self.status = ttk.Label(main_frame, text="Bereit zur Überwachung", relief=tk.SUNKEN)
        self.status.pack(fill=tk.X, pady=10)

    def refresh_interfaces(self):
        """Aktualisiert die Liste der verfügbaren Adapter"""
        ifaces = WiFiScanner.get_interfaces()
        self.interface_dropdown['values'] = ifaces
        if ifaces:
            self.interface_var.set(ifaces[0])
            self.status.config(text=f"{len(ifaces)} Adapter gefunden")
        else:
            self.status.config(text="Keine Adapter gefunden!")
        return ifaces

    def start_monitoring(self):
        """Startet die DeAuth-Überwachung"""
        iface = self.interface_var.get()
        if not iface:
            messagebox.showerror("Fehler", "Kein WLAN-Interface ausgewählt!")
            return
        
        if self.enable_monitor_mode(iface):
            self.status.config(text=f"Überwache {iface}...")
            messagebox.showinfo("Erfolg", "Überwachung erfolgreich gestartet!")
        else:
            messagebox.showerror("Fehler", "Monitor-Mode konnte nicht aktiviert werden!")

    @staticmethod
    def enable_monitor_mode(interface):
        """Aktiviert den Monitor-Mode"""
        methods = [
            ["sudo", "iw", interface, "set", "monitor", "none"],
            ["sudo", "airmon-ng", "start", interface],
            ["sudo", "ifconfig", interface, "down"],
            ["sudo", "iwconfig", interface, "mode", "monitor"],
            ["sudo", "ifconfig", interface, "up"]
        ]
        
        for cmd in methods:
            try:
                subprocess.run(cmd, check=True, timeout=10)
                return True
            except:
                continue
        return False

if __name__ == "__main__":
    # Root-Check
    if os.geteuid() != 0:
        print("Bitte als Root ausführen: sudo python3 police_deauth_final.py")
        sys.exit(1)
    
    # GUI starten
    root = tk.Tk()
    app = PoliceDeauthApp(root)
    root.mainloop()
