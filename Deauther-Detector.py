#!/usr/bin/env python3
"""
POLIZEI-DEAUTH-GUARD - Automatisierte Erkennung & Abwehr
Stabile Version 2.2 - Keine Benutzerabfragen
"""

import os
import sys
import time
import re
import subprocess
import sqlite3
from datetime import datetime
import logging
from scapy.all import sniff, Dot11Deauth, RadioTap, Dot11, sendp

# ===================== KONFIGURATION =====================
class Config:
    DB_PATH = "/var/lib/deauth_guard.db"  # Sichere Speicherung
    LOG_FILE = "/var/log/deauth_guard.log"
    ALLOWED_CHANNELS = [1, 6, 11]  # Standard-Kanäle
    MAX_COUNTER_ATTACKS = 3  # Juristisch sicher

# ===================== SICHERE FUNKTIONEN =====================
def validate_mac(mac):
    """Überprüft MAC-Adressen auf Gültigkeit"""
    return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))

def run_command(cmd):
    """Führt Systembefehle sicher aus"""
    try:
        return subprocess.run(cmd, 
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Befehl fehlgeschlagen: {' '.join(cmd)} - {e.stderr}")
        return None

# ===================== KERNMODUL =====================
class DeauthMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.setup_logging()
        self.setup_database()

    def setup_logging(self):
        """Konfiguriert das System-Logging"""
        logging.basicConfig(
            filename=Config.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def setup_database(self):
        """Initialisiert die Evidenz-Datenbank"""
        os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(Config.DB_PATH)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                timestamp TEXT,
                attacker TEXT,
                target TEXT,
                channel INTEGER,
                action TEXT
            )
        """)

    def start(self):
        """Startet die Überwachung"""
        logging.info(f"Starte Überwachung auf {self.interface}")
        sniff(iface=self.interface,
              prn=self.handle_packet,
              store=False,
              filter="type mgt subtype deauth")

    def handle_packet(self, pkt):
        """Verarbeitet Deauth-Pakete"""
        if not pkt.haslayer(Dot11Deauth):
            return

        attacker = pkt.addr2
        target = pkt.addr1

        if not all(validate_mac(mac) for mac in [attacker, target]):
            return

        self.log_attack(attacker, target)
        self.counter_attack(attacker, target)

    def log_attack(self, attacker, target):
        """Protokolliert Angriffe"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.conn.execute(
            "INSERT INTO attacks VALUES (?, ?, ?, ?, ?)",
            (timestamp, attacker, target, self.get_channel(), "ERKANNT")
        )
        self.conn.commit()

    def counter_attack(self, attacker, target):
        """Automatische Gegenmaßnahme"""
        for _ in range(Config.MAX_COUNTER_ATTACKS):
            pkt = RadioTap() / Dot11(addr1=attacker, addr2=target, addr3=target) / Dot11Deauth()
            sendp(pkt, iface=self.interface, verbose=0)
            time.sleep(0.2)

# ===================== HAUPTPROGRAMM =====================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Bitte als root ausführen!")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Verwendung: sudo python3 deauth_guard.py <interface>")
        sys.exit(1)

    monitor = DeauthMonitor(sys.argv[1])
    
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\nÜberwachung gestoppt")
    except Exception as e:
        logging.critical(f"FEHLER: {str(e)}")
        sys.exit(1)
