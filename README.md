POLIZEI DeAuth-Guard PRO
Ein Python-basiertes Tool zur Erkennung von Deauthentication-Attacken im WLAN, mit Echtzeit-Visualisierung und Signalpegelanzeige. Das System erkennt automatisch Angriffspakete, zeigt die MAC-Adresse des Angreifers an, misst die Signalstärke und fokussiert auf den Kanal.

Funktionen
Automatische Erkennung von Deauth- und Angriffspaketen:
Erkennt echte Attacken im WLAN-Netzwerk und zeigt die MAC-Adresse des Angreifers.

Signalstärke-Messung:
Liest die Signalqualität direkt aus den empfangenen Paketen (dBm_AntSignal), um die Stärke des Angreifer-Signals anzuzeigen.

Kanal-Hopping:
Wechselt kontinuierlich durch Kanäle, um möglichst viele Netzwerke zu überwachen. Bei Angriffserkennung bleibt der Kanal bei Bedarf fixiert.

Angriffsprotokoll:
Speichert alle erkannten Attacken in einer lokalen SQLite-Datenbank.

Benutzeroberfläche (GUI):
Mit Tkinter für einfache Bedienung und Echtzeit-Visualisierung der Bedrohungssituation.

Voraussetzungen
Betriebssystem: Linux (z.B. Ubuntu, Kali Linux)
Benötigte Pakete:
scapy
tkinter (meist vorinstalliert)
sqlite3 (Standard in Python)
WLAN-Adapter:
Muss im Monitor-Mode laufen
Sollte Signalstärke (dBm_AntSignal) in den Paketen liefern (z.B. Alfa AWUS036NHA, TP-Link TL-WN722N v1)
Treiber:
Aktueller, funktionsfähiger Treiber, der Signalstärke in den Paketen bereitstellt
Installation
Repository klonen / Skript herunterladen:
CopyRun
git clone https://github.com/dein-username/polizei_deauth_guard.git
cd polizei_deauth_guard
Benötigte Pakete installieren:
CopyRun
pip3 install scapy
Skript als Root / Administrator ausführen:
CopyRun
sudo python3 police_deauth_pro.py
Einrichtung
Stelle sicher, dass dein WLAN-Adapter im Monitor-Mode läuft:
CopyRun
sudo ./dein-skript-zum-aktivieren-oder manuell aktivieren
Das Script wählt automatisch den ersten verfügbaren WLAN-Adapter aus.
Nutzung
Adapter auswählen:
Im GUI kannst du den WLAN-Adapter aus der Liste wählen.

Monitoring starten:
Klicke auf "Start". Das System wechselt in Monitor-Mode, beginnt mit Kanal-Hopping und überwacht den Verkehr.

Angriffe erkennen:
Bei echten Deauth- oder Angriffspaketen:

Die MAC-Adresse des Angreifers wird vollständig im GUI angezeigt.
Signalstärke in dBm wird angezeigt (sofern dein Adapter diese liefert).
Attacken werden im Protokoll gespeichert.
Monitoring stoppen:
Klicke auf "Stop".

Hinweise zum Signalempfang
Funktion:
Das System liest die Signalstärke (dBm_AntSignal) direkt aus den empfangenen WLAN-Paketen. Diese Angabe ist in den meisten Fällen bei Beacon- und Management-Paketen enthalten.

Voraussetzung:
Dein WLAN-Adapter muss diese Information in den Paketen bereitstellen. Nicht alle Geräte tun das. Empfohlene Modelle sind z.B.:

Alfa AWUS036NHA
TP-Link TL-WN722N (Version 1)
Andere, die dBm_AntSignal in Paketen liefern
Hinweis:
Wenn die Signalstärke nicht angezeigt wird oder sehr ungenau ist, liegt es meist am Adapter oder Treiber.

Hinweise & Tipps
Für beste Ergebnisse nutze einen WLAN-Adapter, der Signalstärke in den Paketen liefert.
Das Tool erkennt nur aktive WLAN-Attacken, die im WLAN-Verkehr sichtbar sind.
Die Datenbank speichert alle erkannten Attacken inklusive MAC, Zeit, Kanal, Signalstärke.
Lizenz
Dieses Projekt ist frei verwendbar. Bei Fragen oder Verbesserungen gerne Pull-Requests schicken.
