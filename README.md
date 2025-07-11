# Leet - HackMyVM - Hard

![Leet.png](Leet.png)

**Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Leet](https://hackmyvm.eu/machines/machine.php?vm=Leet)
**Schwierigkeitsgrad:** Hard

## Übersicht

Dieser Bericht dokumentiert den Pentest der HackMyVM Maschine "Leet". Das Ziel war es, die Kontrolle über das System zu erlangen (Root-Rechte) und die User- und Root-Flags zu finden. Die Maschine stellte eine Herausforderung auf dem Niveau "Hard" dar und beinhaltete die Ausnutzung einer Webanwendungsschwachstelle, die Kompromittierung eines Debuggers und eine Privilegien-Eskalation über misskonfigurierte Sudo-Rechte.

## Verwendete Tools

Folgende Tools kamen während des Pentests zum Einsatz:

*   arp-scan
*   vi
*   nmap
*   nikto
*   gobuster
*   python3
*   curl
*   nano
*   scp
*   ss
*   sudo
*   micro
*   nc (Netcat)
*   su
*   cat
*   firefox_decrypt.py

## Vorgehen (Zusammenfassung)

Der Pentest wurde in folgenden Phasen durchgeführt:

1.  **Reconnaissance:**
    *   Identifizierung der Ziel-IP im lokalen Netzwerk mittels `arp-scan`.
    *   Hinzufügen der IP zur lokalen `/etc/hosts` Datei für einfachere Adressierung.
    *   Umfangreicher Nmap-Scan zur Identifizierung offener Ports und Dienste. Gefunden wurden Port 22 (SSH) und Port 7777 (HTTP - Werkzeug httpd).
    *   Prüfung der HTTP-Header auf Port 7777 mittels `curl`.

2.  **Web Enumeration & Initial Access:**
    *   Automatisiertes Scanning des Webservers auf Port 7777 mittels `nikto`. Interessante Pfade wie `/console` und `/#wp-config.php#` wurden gefunden.
    *   Verzeichnis-Brute-Forcing mittels `gobuster`. Der Endpunkt `/download` mit Status Code 500 wurde identifiziert.
    *   Analyse des `/download`-Endpunkts durch Aufruf im Browser, was zu einem detaillierten Werkzeug Debugger Traceback führte.
    *   Analyse des Tracebacks und des Quellcodes der Fehlerseite, um eine Local File Inclusion (LFI) Schwachstelle und das Debugger SECRET zu identifizieren.
    *   Ausnutzung der LFI-Schwachstelle (`/download?filename=../../../../...`) zum Auslesen sensibler Systemdateien (`/etc/passwd`, `/etc/machine-id`).
    *   Sammeln aller notwendigen Systeminformationen (Username `www-data`, Pfad zur App-Datei, MAC-Adresse, Machine-ID, SECRET) zur Berechnung des Werkzeug Debugger PINs.
    *   Erstellung und Ausführung eines Python-Skripts (`pin_calc.py`) zur Berechnung des Debugger PINs (`142-855-714`).
    *   Eingabe des berechneten PINs in die Werkzeug Debugger Konsole, was Remote Code Execution (RCE) als Benutzer `www-data` ermöglichte.
    *   Nutzung der RCE-Fähigkeit zum Starten einer Reverse Shell zum Angreifer-System mittels `nc`.

3.  **Privilege Escalation:**
    *   Als Benutzer `www-data` Etablierung einer stabilen Shell und initiale Enumeration.
    *   Prüfung der `sudo` Berechtigungen mittels `sudo -l`. Gefunden wurde die Berechtigung, `/usr/bin/micro` als Benutzer `riva` ohne Passworteingabe auszuführen (`(riva) NOPASSWD: /usr/bin/micro`).
    *   Enumeration des Home-Verzeichnisses von Benutzer `riva`.
    *   Übertragung des Firefox-Profils von `riva` auf das Angreifer-System mittels `scp`.
    *   Nutzung von `firefox_decrypt.py` zum Auslesen der im Firefox-Profil gespeicherten Passwörter. Dabei wurde das Passwort für Benutzer `riva` (`PGH$2r0co3L5QL`) gefunden.
    *   Erneute Prüfung der `sudo` Berechtigungen als Benutzer `riva` (jetzt mit bekanntem Passwort) mittels `sudo -l`. Gefunden wurde die Berechtigung, `/usr/sbin/nginx` als `root` auszuführen, wofür das Passwort von `riva` benötigt wird (`(root) /usr/sbin/nginx`).
    *   Erstellung einer bösartigen Nginx-Konfigurationsdatei (`nginx_pwn.conf`), die Nginx anweist, als `root` zu laufen, das System-Root-Verzeichnis als Webroot zu verwenden und die WebDAV `PUT` Methode zu aktivieren (lauschend auf Port 4448).
    *   Starten der bösartigen Nginx-Instanz mit Root-Rechten mittels `sudo -u root /usr/sbin/nginx -c /path/to/nginx_pwn.conf` unter Verwendung des bekannten Passworts von `riva`.
    *   Ausnutzung der Nginx WebDAV PUT-Fähigkeit (laufend als Root) zum Überschreiben der Datei `/etc/passwd` mit einer modifizierten Version, die einen neuen Benutzer `dark` mit UID 0 und GID 0 (Root-Rechte) und einem bekannten Passwort enthält.
    *   Anmeldung als neuer Root-Benutzer `dark` mittels `su dark`.

4.  **Flags:**
    *   Nach Erlangung von Root-Rechten wurden die User-Flag (in `/home/riva/user.txt`) und die Root-Flag (in `/root/r007_fl46.7x7`) ausgelesen.

## Vollständiger Bericht

Für eine detaillierte Schritt-für-Schritt-Anleitung mit Analysen, Bewertungen und Empfehlungen, siehe den vollständigen Pentest-Bericht:

[Zum ausführlichen HTML-Bericht](https://alientec1908.github.io/Leet_HackMyVM_Hard/)

## Autor

DarkSpirit

## Berichtsdatum

15. Juni 2025
