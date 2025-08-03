🛡️ Brunoido DeAuth-Guard 🛡️


Ein ✨ Python-basiertes Tool ✨ zur Echtzeit-Erkennung von Deauthentication-Attacken in WLAN-Netzwerken. Es hilft dir, Angriffe zu erkennen, Angreifer zu identifizieren und deine Netzwerksicherheit zu überwachen. Ein Must-have für jeden Security-Enthusiasten! 🕵️‍♂️

🚀 Funktionen
Automatische Angriffserkennung: 🚨 Erkennt Deauth-Pakete im WLAN-Verkehr und zeigt die MAC-Adresse des Angreifers an.

Signalstärken-Analyse: 📊 Misst die Stärke des Angreifersignals (in dBm_AntSignal) direkt aus den empfangenen Paketen.

Dynamisches Kanal-Hopping: 📡 Überwacht kontinuierlich verschiedene WLAN-Kanäle. Bei einer erkannten Attacke fokussiert sich das Tool automatisch auf den betroffenen Kanal.

Angriffsprotokoll: 📝 Speichert alle erkannten Angriffe in einer lokalen SQLite-Datenbank zur späteren Analyse.

Benutzeroberfläche (GUI): 💻 Eine einfache, auf Tkinter basierende Oberfläche visualisiert die Bedrohungssituation in Echtzeit.

🛠️ Voraussetzungen
Stelle sicher, dass die folgenden Punkte erfüllt sind, bevor du das Tool verwendest:

Betriebssystem: Linux 🐧 (z. B. Ubuntu, Kali Linux).

Python 3.x

Benötigte Pakete: scapy, tkinter (normalerweise vorinstalliert), sqlite3.

WLAN-Adapter: Muss Monitor-Mode unterstützen und die Signalstärke (dBm_AntSignal) in den Paketen bereitstellen.

Empfohlene Modelle: Alfa AWUS036NHA, TP-Link TL-WN722N (v1).

Treiber: Ein aktueller, funktionsfähiger Treiber für den WLAN-Adapter.

⚙️ Installation & Nutzung
1. Installation
Klone das Repository und installiere die benötigten Python-Pakete:

Bash

git clone https://github.com/dein-username/brunoido_deauth_guard.git
cd brunoido_deauth_guard
pip3 install scapy
2. Ausführen
Führe das Skript mit Root-Rechten aus, um auf den WLAN-Adapter zugreifen zu können:

Bash

sudo python3 brunoido_deauth_guard.py
3. Einrichtung & Betrieb
Das Tool wählt automatisch den ersten verfügbaren WLAN-Adapter aus und wechselt in den Monitor-Mode.

Klicke in der Benutzeroberfläche auf "Start", um die Überwachung zu beginnen.

Erkannte Angriffe werden direkt im GUI angezeigt und in der Datenbank gespeichert.

⚠️ Hinweise zur Signalstärke
Das Tool ist auf die Informationen angewiesen, die der WLAN-Adapter in den Paketen bereitstellt. Wenn die Signalstärke nicht angezeigt wird oder ungenau ist, liegt dies meist am Adapter oder Treiber. Stelle sicher, dass du einen kompatiblen Adapter verwendest.

📜 Lizenz
Dieses Projekt ist unter der MIT-Lizenz veröffentlicht. 🔓
