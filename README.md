WLAN-Überwachungstool mit Kanal-Hopping und Angriffserkennung
Dieses Python-basierte Tool dient der Überwachung von WLAN-Netzwerken auf Deauth-Attacken und anderen Angriffen. Es kombiniert eine automatische Kanal-Hopping-Funktion mit einer Echtzeit-Erkennung von Deauth-Paketen, um eine umfassende Überwachung aller WLAN-Aktivitäten zu gewährleisten.

Features
Automatisches Kanal-Hopping:
Das Programm wechselt kontinuierlich durch alle WLAN-Kanäle (1-11) im Hintergrund, um möglichst viele Netzwerke und potenzielle Angriffe zu erfassen. Das sorgt für eine flächendeckende Überwachung, auch wenn die Angreifer den Kanal wechseln.

Echtzeit-Erkennung von Deauth-Attacken:
Mithilfe der scapy-Bibliothek wird gezielt nach Deauth-Paketen gesucht. Bei Erkennung einer Attacke werden die Details (Angreifer, Ziel, Signalstärke, Kanal) in einer SQLite-Datenbank gespeichert und in der GUI angezeigt.

Kanal-Fokus bei Angriffen:
Sobald eine Attacke erkannt wird, bleibt das Programm auf dem Kanal, auf dem die Attacke stattgefunden hat, um die Aktivitäten genauer zu überwachen und weitere Pakete zu analysieren.

Benutzeroberfläche (GUI):
Mit tkinter bietet das Tool eine übersichtliche GUI, in der man:

Das WLAN-Interface auswählen kann
Die Signalstärke in Echtzeit überwacht
Die Angriffsdaten in einer Tabelle einsehen
Den Überwachungsvorgang starten und stoppen kann
Benutzerrechte:
Das Programm muss mit Administratorrechten (Root) ausgeführt werden, um die WLAN-Adapter in den Monitor-Modus zu versetzen und Pakete zu sniffen.

Technische Details
Kanal-Hopping:
Implementiert mit einem separaten Thread, der alle Kanäle (1-11) im Abstand von 0,5 Sekunden durchläuft. Bei Erkennung einer Attacke wird der Kanal auf den Angriffskanal gesetzt und das Hopping pausiert.

Attack-Erkennung:
Nutzt scapy zum Sniffen der WLAN-Pakete. Speziell werden Deauth-Pakete (Dot11Deauth) erkannt. Diese werden in einer SQLite-Datenbank geloggt und in der GUI angezeigt.

Datenbank:
CSV-ähnliche Speicherung aller erkannten Angriffe mit Zeitstempel, Angreifer, Ziel, Signalstärke und Kanal.

Benutzeroberfläche:  

Interface-Auswahl: Dropdown zur Auswahl des WLAN-Adapters
Signalstärke: Anzeige in Echtzeit mit Farbkennzeichnung
Angriffsprotokoll: Tabelle mit den letzten Angriffen
Steuerung: Buttons zum Starten und Stoppen der Überwachung
Voraussetzungen
Linux-System mit WLAN-Adapter, der Monitor-Modus unterstützt
Python 3.x
scapy (pip install scapy)
tkinter (standardmäßig enthalten)
Administratorrechte (z.B. per sudo)
Hinweise
Das Programm setzt voraus, dass iwconfig und iw installiert sind.
Die WLAN-Schnittstelle muss kompatibel mit Monitor-Modus sein.
Für die Funktionalität ist es notwendig, das Programm als Root auszuführen.
Beispiel-Workflow
Programm starten (mit sudo)
WLAN-Adapter auswählen
Überwachung starten
Das Tool durchläuft alle Kanäle, erkennt Attacken in Echtzeit
Bei Angriffserkennung bleibt das Programm auf dem Kanal des Angriffs, um weitere Pakete zu überwachen
Überwachung stoppen, um wieder Kanal-Hopping zu aktivieren oder das Programm zu beenden
