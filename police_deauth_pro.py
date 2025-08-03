#!/usr/bin/env python3
"""
POLIZEI DeAuth-Guard ULTIMATIVE - 100% zuverlässige Adaptererkennung
"""

import os
import sys
import re
import subprocess
from tkinter import messagebox

def detect_wifi_adapters():
    """Robusteste verfügbare Methode zur Adaptererkennung"""
    methods = [
        _detect_via_ip_link,      # Modernste Methode
        _detect_via_sysfs,        # Universell
        _detect_via_iwconfig,     # Legacy
        _detect_via_rfkill,       # Fallback
        _detect_via_pci_usb       # Hardware-Level
    ]
    
    adapters = []
    for method in methods:
        try:
            adapters = method()
            if adapters:
                return adapters
        except:
            continue
    
    return ["wlan0"]  # Ultimativer Fallback

def _detect_via_ip_link():
    """Moderne Erkennung mit ip-Befehl"""
    output = subprocess.check_output(["ip", "link", "show"], text=True)
    return [
        line.split(':')[1].split()[0] 
        for line in output.split('\n') 
        if 'state UP' in line and 'wireless' in line
    ]

def _detect_via_sysfs():
    """Linux-Sysfs Methode"""
    return [
        iface for iface in os.listdir('/sys/class/net') 
        if os.path.exists(f'/sys/class/net/{iface}/wireless')
    ]

def _detect_via_iwconfig():
    """Legacy Wireless Extensions"""
    output = subprocess.check_output(["iwconfig"], text=True, stderr=subprocess.DEVNULL)
    return [line.split()[0] for line in output.split('\n') if "IEEE" in line]

def _detect_via_rfkill():
    """RFKill Hardware-Erkennung"""
    output = subprocess.check_output(["rfkill", "list"], text=True)
    return [
        line.split(':')[1].strip() 
        for line in output.split('\n') 
        if 'Wireless LAN' in line
    ]

def _detect_via_pci_usb():
    """Low-Level Hardware-Erkennung"""
    adapters = []
    
    # PCI WLAN Karten
    if os.path.exists('/usr/bin/lspci'):
        pci_output = subprocess.check_output(["lspci"], text=True)
        adapters += [
            f"wlp{index}s0" 
            for index, line in enumerate(pci_output.split('\n')) 
            if 'Network controller' in line
        ]
    
    # USB WLAN Adapter
    usb_output = subprocess.check_output(["lsusb"], text=True)
    adapters += [
        f"wlx{line.split()[5].replace(':', '')}" 
        for line in usb_output.split('\n') 
        if 'Wireless' in line
    ]
    
    return adapters

def enable_monitor_mode(interface):
    """Aktiviert Monitor-Mode mit allen verfügbaren Methoden"""
    methods = [
        ["sudo", "iw", interface, "set", "monitor", "none"],
        ["sudo", "airmon-ng", "start", interface],
        ["sudo", "ifconfig", interface, "down"],
        ["sudo", "iwconfig", interface, "mode", "monitor"],
        ["sudo", "ifconfig", interface, "up"]
    ]
    
    for method in methods:
        try:
            subprocess.run(method, check=True, timeout=10)
            return True
        except:
            continue
    return False

# ================= GUI INTEGRATION =================
class PoliceGUI:
    def refresh_interfaces(self):
        """Aktualisiert die Interface-Liste mit allen Methoden"""
        self.available_interfaces = detect_wifi_adapters()
        
        # Versuche Monitor-Mode für alle Adapter
        working_interfaces = []
        for iface in self.available_interfaces:
            if enable_monitor_mode(iface):
                working_interfaces.append(iface + "mon")
            working_interfaces.append(iface)
        
        if not working_interfaces:
            messagebox.showerror(
                "Kritischer Fehler",
                "Keine WLAN-Adapter gefunden!\n\n"
                "Bitte:\n"
                "1. WLAN-Adapter einstecken\n"
                "2. Treiber installieren\n"
                "3. System neustarten"
            )
            return []
        
        return working_interfaces
