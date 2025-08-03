1. Voraussetzungen installieren
Öffnen Sie ein Terminal und führen Sie diese Befehle aus:

bash
sudo apt update
sudo apt install -y \
    python3 \
    python3-tk \
    python3-pip \
    wireless-tools \
    iw \
    aircrack-ng \
    tshark \
    tcpdump \
    usbutils \
    pciutils
Wichtigste Pakete:
Paket	Funktion
python3-tk	GUI-Oberfläche
wireless-tools & iw	WLAN-Adaptersteuerung
airmon-ng	Monitor-Mode-Aktivierung
tshark & tcpdump	Paketanalyse (Fallback)
usbutils & pciutils	Hardware-Erkennung
2. Python-Abhängigkeiten installieren
bash
sudo pip3 install scapy
(Scapy wird für die WLAN-Paketanalyse benötigt.)

3. Code herunterladen & ausführbar machen
Option A: Direkter Download
bash
wget https://example.com/police_deauth_ultimate.py -O police_deauth.py
chmod +x police_deauth.py
Option B: Manuell speichern
Kopieren Sie den vollständigen Code in eine Datei namens police_deauth.py.

Machen Sie sie ausführbar:

bash
chmod +x police_deauth.py
4. Tool starten
bash
sudo ./police_deauth.py
(Immer mit sudo ausführen, da Monitor-Mode Root-Rechte benötigt!)

5. (Optional) Desktop-Verknüpfung erstellen
Für einfachen Zugriff ohne Terminal:

Desktop-Datei erstellen (/usr/share/applications/police-deauth.desktop):

ini
[Desktop Entry]
Name=POLIZEI DeAuth-Guard
Exec=gksudo /pfad/zur/police_deauth.py
Icon=network-wireless
Terminal=false
Type=Application
Categories=Utility;
Ausführbar machen:

bash
sudo chmod +x /usr/share/applications/police-deauth.desktop
Jetzt kann das Tool per Doppelklick gestartet werden (Passwort wird abgefragt).

6. Wichtige Hinweise für den Einsatz
A. Hardware-Anforderungen
Unterstützte WLAN-Adapter:

Ideal: Alfa AWUS036ACH (mit rtl8812au Treiber)

Getestet: TP-Link TL-WN722N (mit ath9k_htc Treiber)

Treiber prüfen:

bash
lsusb | grep -i wireless
# Beispiel-Ausgabe: Bus 001 Device 004: ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU
B. Fehlerbehebung
Problem	Lösung
"No wireless interfaces found"	sudo apt install firmware-realtek
Monitor-Mode aktiviert nicht	sudo airmon-ng check kill
Scapy fehlt	sudo pip3 install --upgrade scapy
GUI startet nicht	sudo apt install python3-tk
C. Rechtlicher Hinweis
Nutzung nur im Rahmen der StPO (§100a) erlaubt

Dokumentationspflicht: Alle erkannten Angriffe werden automatisch in /var/lib/police/deauth_guard.db protokolliert
