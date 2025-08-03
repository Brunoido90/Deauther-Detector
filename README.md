POLIZEI DeAuth-Guard PRO: Echtzeit-Deauth-Angriffserkennung für WLAN
POLIZEI DeAuth-Guard PRO ist ein Python-basiertes Tool zur Erkennung von Deauthentication-Angriffen in WLAN-Netzwerken. Es bietet Echtzeit-Visualisierung, zeigt die Signalstärke des Angreifers an und protokolliert alle erkannten Attacken.

Funktionen 🛡️
Automatische Angriffserkennung: Erkennt zuverlässig Deauthentication- und andere Angriffspakete und zeigt die MAC-Adresse des Angreifers an.

Signalstärken-Messung: Liest die Signalqualität (dBm) direkt aus den Paketen, um die Stärke des Angriffssignals zu bestimmen.

Kanal-Hopping & Fokussierung: Überwacht kontinuierlich verschiedene WLAN-Kanäle. Bei einem erkannten Angriff kann der Kanal fixiert werden, um die Attacke genauer zu analysieren.

Angriffsprotokollierung: Speichert alle erkannten Angriffe, einschließlich MAC-Adresse, Uhrzeit, Kanal und Signalstärke, in einer lokalen SQLite-Datenbank.

Benutzerfreundliche GUI: Eine grafische Benutzeroberfläche auf Basis von Tkinter ermöglicht eine einfache Bedienung und die Echtzeit-Visualisierung der Bedrohungssituation.

Voraussetzungen 💻
Betriebssystem: Linux (z. B. Ubuntu, Kali Linux)

Python 3

WLAN-Adapter: Muss den Monitor-Modus unterstützen und idealerweise die Signalstärke (dBm_AntSignal) in den Paketen bereitstellen.

Empfohlene Modelle: Alfa AWUS036NHA, TP-Link TL-WN722N (v1)

Pakete: Scapy, Tkinter, SQLite3 (Tkinter und SQLite3 sind meistens Standard in Python-Distributionen)

Installation und Einrichtung ⚙️
Repository klonen:

Bash

git clone https://github.com/dein-username/polizei_deauth_guard.git
cd polizei_deauth_guard
Abhängigkeiten installieren:

Bash

pip3 install scapy
WLAN-Adapter in den Monitor-Modus versetzen:
Stelle sicher, dass dein Adapter vor dem Start des Tools im Monitor-Modus läuft.

Skript ausführen:
Führe das Skript mit Root-Rechten aus, da für den Zugriff auf den WLAN-Adapter spezielle Berechtigungen erforderlich sind.

Bash

sudo python3 police_deauth_pro.py
Nutzung 🚀
Adapter auswählen: Wähle in der GUI deinen WLAN-Adapter aus der Liste aus.

Monitoring starten: Klicke auf "Start". Das Tool startet den Überwachungsmodus mit Kanal-Hopping.

Angriffe erkennen: Bei einem Deauthentication-Angriff werden folgende Informationen in Echtzeit angezeigt:

MAC-Adresse des Angreifers

Signalstärke (dBm), sofern vom Adapter unterstützt

Alle Attacken werden in der Datenbank protokolliert.

Monitoring stoppen: Klicke auf "Stop", um die Überwachung zu beenden.

Wichtiger Hinweis zur Signalstärke 📡
Die Anzeige der Signalstärke hängt direkt von den Fähigkeiten deines WLAN-Adapters ab.

Das Tool liest den Wert dBm_AntSignal direkt aus den empfangenen Paketen.

Nicht alle Adapter und Treiber liefern diese Information zuverlässig. Wenn keine oder nur ungenaue Werte angezeigt werden, liegt dies höchstwahrscheinlich am verwendeten Adapter oder dessen Treiber.

Lizenz 📝
Dieses Projekt steht unter einer Open-Source-Lizenz. Pull-Requests, Bug-Reports und Feature-Vorschläge sind jederzeit willkommen.
