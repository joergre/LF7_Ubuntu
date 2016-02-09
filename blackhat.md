Blackhat
========
Ein schöner Film wenn auch ein wenig überzogen und mit unrealistischer Geschwindigkeit: https://de.wikipedia.org/wiki/Blackhat_(Film)
Blackhat sind im Gegensatz zu den Whitehat die bösen Hacker, die zerstören und Geld verdienen möchten (https://de.wikipedia.org/wiki/Hacker_(Computersicherheit)#White-.2C_Grey-_und_Black-Hats).
Der Beginn des Films mit der zerstörten Kühlmittelpumpe ist durchaus realistisch. Ein beispiel ist z.B. Stuxnet (https://de.wikipedia.org/wiki/Stuxnet), ein Angriff auf Frequenzumrichter die Motoren für Zentrifugen steuern. Auch Kursmanipulationen durch Hacker sind bereits Realität geworden: http://www.welivesecurity.com/2007/09/20/virus-bulletin-2007/
Das Hacker mit der Polizei zusammen arbeiten und dafür eine deutliche Strafreduzierung bekommen, ist bereits vorgekommen (z.B. Sabu): https://de.wikipedia.org/wiki/Hector_Xavier_Monsegur

Edge-Router
-----------

Bereits in der 9:43 Minuten fällt der erste Fachbregiff: Edge-Router.
Edge-Router ist der Router der ein oder mehre lokale Netzwerke mit einem Backbone 
oder dem Internet verbindet. Die Aussage in dem Film ist: "Ihre Edge-Router wurden zerstört. Und wir können nicht rein. Es ist zu heiß." Der Satz macht durchaus Sinn, weil ohne Edge-Router (im einfachsten Fall eine Fritz!box) kein Zugriff von außen auf ein Netzwerk möglich ist. Sicherlich müsste dann geschaut werden, ob es die Möglichkeit gibt, an einer anderen Stelle einen Router in das Netzwerk einzubringen. Sicherlich in dem hier beschriebenem Szenario einer Kernschmelze in einem Atomkraftwerk ein nicht ganz einfaches Unterfangen.

RAT
---
Erstes auftreten bei 09:16. RAT steht für Remote Administration Tool und bezeichnet ein Fernwartungstool jeglicher Art und fasst Teamviewer, ssh, telnet, Remote Desktop, VNC und viele andere Produkte unter einem Namen zusammen (https://de.wikipedia.org/wiki/Fernwartungssoftware). Sehr gerne werden für den unbemerkten Zugriff sogenannte Reverse Shells eingesetzt, die von sich aus den Kontakt zu einem Server aufbauen. Sie machen sich den Umstand zu nutze, dass Firewalls den Zugriff von außen nach innen komplett blockieren aber nicht von innen nach außen. Selbstverständlich können sie auch weiteren Schadcode nachladen und Programme auf dem System ausführen. Reverse Shells sind gefährlich, weil sie nur sehr schwer gefunden werden können, fast nicht über Firewalls zu blockieren und extrem einfach zu programmieren sind. Es gibt auch fertige Bausätze für Reverse Shells unter anderem für PHP und Python. Ein Beispiel für Python steht hier: https://haiderm.com/simple-python-fully-undetectable-fud-reverse-shell-backdoor/

Optisches Overlay Netzwerk
--------------------------
(12:53) ist ein Netzwerk, dass auf ein bestehendes Netzwerk aufsetzt und sich z.B. durch ein eigenes Routing oder andere logische Strukturen von dem darunter liegenden Netz abgrenzt. Beispiele sind z.B. VoIP (Telefongespräche über das Internet führen, wobei das logische Netz mit den Endgeräten eine von dem Internet unabhängige Logik  hat) oder das Tornetz, dass versucht Datenpakete anonym über das Internet zu transportieren. Weitere Informationen: https://de.wikipedia.org/wiki/Overlay-Netz

Deep Packet Inspection
----------------------
(23:57) ist eine Art von Firewall die vor allem bei grossen Unternehmen und staatlichen Einrichtungen verwendet wird. Die gängig Firewall ist eine SPI (Stateful Packet Inspection), die in fast jedem heute verkauften Router zum Einsatz kommt. Diese Firewall untersucht den Kopf und den Fuss eines jeden Datenpakets und überprüft, anhand einer Tabelle über alle bestehenden Datenverbindungen, ob dieses Paket zu einer existierenden Datenverbindung gehört. Wenn das Paket zu einem bestehenden Socket (Kommunikationskanal) gehört wird das Paket durchgelassen. 

Dem gegenüber beinhaltet das DPI (Deep Packet Inspection) alle eigenschaften von SPI und überprüft zusätzlich auch den Inhalt eines jeden Datenpakets. Anhand des Inhaltes wird dann zusätlich entschieden wie dieses Datenpaket behandelt wird. Um auch verschlüsselten Internetverkehr wie z.B. SSL-Verbindungen zu überprüfen baut die DPI eine Art "Man in the Middel-Attack" auf. 
![Man in the middle](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e7/Man_in_the_middle_attack.svg/500px-Man_in_the_middle_attack.svg.png "Man in the miidle")
Wenn Alice mit Bob kommunizieren möchte über eine DPI-Firewall (Mallory), dann baut Alice eine Kommunikation zu Mallory auf. Die Verbindung zwischen Mallory und Alice kann (muß aber nicht zwingend) mit SSL verschlüsselt sein. Mallory baut eine Verbindung zu Bob auf und reicht die Überprüften und gefilterten Daten von Alice an Bob weiter. Die Antworten von Bob werden von Mallory entpackt und überprüft und dann an Allice weitergereicht. Das bedeutet, dass es keine Verschlüsselte Kommunikation zwischen Bob und Allice gibt. Zusätzlich muss Alice dann die SSL Zertifikate von Mallory auf ihrem System installiert haben um SSL-Warnungen zu minimieren. 
Diese Systeme können nicht nur auf Viren überprüfen sondern auch auf Pronographie oder andere Inhalte reagieren. Bei DPI-Firewalls wird also Zensur des Internetverkehrs nur noch eine Frage einer Konfigurationsdatei. Insbesondere liegt an dieser Firewall der gesammte Verkehr der nachgeordneten Netze (eines Landes oder einer Firma etc.) in unverschlüsselter Form vor. 
Diskutiert werden diese Firewalls z.B. in Großbritannien als sogenannter Pornofilter (https://netzpolitik.org/2013/uk-pornofilter-soll-auch-andere-unliebsame-inhalte-im-internet-sperren/). Bereits eingesetzt wird die Technik bei der sogenannten "Clean Pipe" und dem "Corporate Security Hub" der Deutschen Telekom sowie "Secure Net" und "Secure Family" von Vodafone Deutschland. Fortinet, Cisco (Service Control Engine), Huawei und Sandvine bieten z.B. Firewals mit DPI an. Weiterführende Informationen zu den Datenschutzproblemen: https://netzpolitik.org/2014/waschmaschine-im-netz-wie-telekom-und-vodafone-deep-packet-inspection-als-feature-verkaufen/ und https://netzpolitik.org/2012/deep-packet-inspection-der-unterschied-zwischen-internet-in-diktaturen-und-deutschland-ist-nur-eine-konfigurationsdatei/. Zur Technik: https://de.wikipedia.org/wiki/Deep_Packet_Inspection

Intrusion Detection System
--------------------------
(23:57) Es gibt sowohl Host basierende Systeme wie auch Systeme die Bestandteil einer Firewall sind. Letztere sind vom technischen Standpunkt die bessere Lösung. Intrusion Detection System beobachten den Netzverkehr und versuchen regelbasiert Angriffsmsuter zu erkennen. Ein bekanntes Produkt eines IDS ist Snort (https://www.snort.org/). Es bezeichnet sich selbst als NIDS um darauf hinzuweisen, dass es nicht Host basiert ist sondern ein Netzwerk vor Angriffen schützt. Ein HIDS (Host basierte IDS) ist z.B. OSSEC (https://ossec.github.io/) oder Samhain (http://www.la-samhna.de/samhain/). Es können auch NIDS und HIDS in einem Netzwerk zeitgleich eingesetzt werden.
HIDS untersucht insbeondere Logdateien, System- und Kerneldateien und meldet Veränderungen und auffällige Einträge. Eine NIDS überwacht hingegen den Netzwerkverkehr und meldet auffällige Muster wie z.B. ein Portscan, auffällig viele Zugriffe aus einem IP-Raum oder andere Auffälligkeiten. Selbstverständlich gibt auch HIDS und NIDS in einem Produkt kombiniert. Das nennt man dann Hybride IDS. Ein bekannter Vertreter ist Prelude https://www.prelude-siem.org/. Auf Grund des komplexen Aufbaus und der zentralen, exponierten Standortes in einem Netzwerk können diese, ähnlich wie DPI-System, selbst zu einem heruasragenden Ziel für Angriffe werden. Zu einem gutem NIDS-System gehören dann noch sogenannte Honeypots dazu. Honeypots (Honigtopf) sind Systeme , die keine Funktion im Netzwerk haben aber dazu dienen Angreifer anzulocken. Wird auf diesen System eine Aktivität verzeichnet, findet mit hoher Wahrscheinlichkeit gerade ein Angriff auf das Netzwerk statt. Es gibt eine sehr grosse Auswahl an Programmen und Betriebssysteme die einen Honeypot zur Verfügung stellen. 
Weitere Informationen zum IDS https://de.wikipedia.org/wiki/Intrusion_Prevention_System und zu Honeypots: https://de.wikipedia.org/wiki/Honeypot

autorun.inf
-----------
Diese Datei wird auf einem Unix-Betriebssystem vom USB-Stick bei 24:54 geöffnet. Diese Datei kommt aus dem Microsoftbereich und war zuerst bei Serverbetriebssysteme von Microsoft gesperrt und nicht bei Unix-betribssystem implementiert. 
Die Datei autorun.inf wird häufig automatisch ausgeführt beim einstecken von USB-Geräten oder dem einlegen von Datenträgern wie DVD. Durch den großen Erfolg der Datei wurde die Sperre bei Server-Bertriebssystemen der Firma Microsoft aufgehoben und sie wird sogar von Unix-Betriebssystemen beachtet. Man kann sie manuell bei allen Betriebssystemen ausschalten (Drop-Out). 
Die Zeile open=.mssvc gibt an, dass die versteckte Datei (.) .mssvc beim einstecken des Sticks ausgeführt werden soll. Zusätzlich gibt es noch die Zeile shellexecute. Shellexecute bewirkt, dass nicht direkt ausführbare Dateien mit dem entsprechenden Programm gestertet werden. Beispielsweise ermöglicht shellexecute das Anzeigen einer HTML-Seite beim einlegen des Datenträfers. Shellexecute und open sollten eigentlich nicht in der gleichen Datei verwendet werden, dies passiert in der Praxis aber sehr häufig. Beim einstecken des Sticks wird also automatisch (nach Entsperrung mit dem Fingerabdruck) die versteckte Datei .mssvc ausgeführt, in der wohl das RAT steht. Die Datei .mssvc gehört zur Samsung SecretZone (http://www.seagate.com/de/de/support/downloads/item/samsung-secretzone-master-dl/) und dient dazu, Teile eines Speichermediums vor unberechtigten Zugriff zu schützen.
Weitere Informationen über den Aufbau: https://de.wikipedia.org/wiki/Autorun

xxd
---
Das Programm xxd erzeugt einen Hexdump einer Datei und wurde entwickelt um eine Datei per Mail zu übertragen. Das Programm kann auch ein Hexdump wieder in die ursprüngliche Datei zurückwandeln (Option -r). Ein Beispiel des Befehls gibt es hier: https://github.com/joergre/ttyrecords/ (xxd.demo). Weitere Informationen: http://linuxcommand.org/man_pages/xxd1.html.

DD-WRT
------
(30:48) Ist eine offene Software für Router (https://de.wikipedia.org/wiki/DD-WRT und http://www.dd-wrt.com/site/index) Das Onion-Router-Project ist bereits in der DD-WRT-Software vorbereitet und kann durch anhacken aktiviert werden (http://dd-wrt.com/wiki/index.php/Tor_on_R7000)

Onion-Router
-------------
(30:48) Onion ist eine andere Bezeichnung für das Tor-Netzwerk. Das Tor-Netzwerk verschleiert die echte IP-Adresse, da diese durch die IP-Adresse der Exit-Nodes ersetzt wird. Durch die (hoffentlich) hohen Anzahl von Computern auf dem Weg zum Exit-Node kann nicht festgestellt werden von welchem Computer tatsächlich die Verbindung aufgebaut wurde.

IP-Adresse
----------
(39:26) Eine IP-Adresse ist eine eindeutige Nummer innerhalb eines Computernetzwerkes. Eine IPv4-Adresse besteht aus 4 Zahlen die maximal bis 255 (da eine Zahl 1 Byte darstellt und damit 2^8 mögliche Kombinationen) gehen. Insofern ist die IP-Adresse 95.45.265.284 keine gültige IP-Adresse.

who und write
-------------
Der Befehl who zeigt eine Vielzahl von Informationen über die momentan am System angemeldeten Benutzer an (https://wiki.ubuntuusers.de/who/).
Mit write können Nachrichten zwischen den Benutzern eines Computers ausgetauscht werden (Beispielsitzung: https://youtu.be/obDYpIn-PYM
 und mehr zum Befehl: https://en.wikipedia.org/wiki/Write_(Unix))
whois zeigt den DNS-Eintrag der entsprechenden IP-Adresse an. Beispiel: https://github.com/joergre/ttyrecords/ (whois.rec).

Proxy-Server
------------
(41:59) Proxy bedeutet Stellvertreter und ersetzt die IP-Adressen der zu einem Dienst aufbauenden IP-Adressen durch die eigene. Damit ist die eigentliche IP-Adresse versteckt und kann nicht einfach zurückverfolgt werden.

Bluetooth
---------
Bluetooth zur Kommunikation zu verwenden ist eine extrem gute Idee. Der Vorteil liegt, dass die Signalreichweite extrem eingeschränkt ist. Es gibt Bluetoothscanner die die Stärke eines Senders angeben (http://beste-apps.chip.de/android/app/bluetooth-scanner-android-app,power.bluetooth.scanner/). Auf der anderen Seite gibt es bereits fertige Scripte wie z.B. eine Bluetooth-Chat um die Kommunikation erfolgreich herzustellen: http://www.radekdostal.com/content/android-bluetooth-chat-client-python.Bluetooth.

PGP
---
PGP steht für Pretty Good Privacy und eines der am besten überprüften Verschlüsselungsverfahren. Vom Verfahren auf die Schlüssellänge zu schliessen ist etwas gewagt, aber die Einschätzung, dass mit normalen Mitteln hier eine Entschlüsselung nicht möglch ist, ist durchaus richtig. Weitere Informationen: https://de.wikipedia.org/wiki/Pretty_Good_Privacy

Festplattenrettung
------------------
(1:12:28) Programme die aus Speicherresten zusammenhängende Bereich erstellen gibt es doch einige. Hier ist sicherlich nicht unbedingt das FBI von nöten. Aber eventuell ist das FBI doch besser aufgestellt, als die vielen Firmen die Professionell Festplatten wieder herstellen.

Keylocker
---------
Keylocker ist ein Programm das alle Tastatureingaben aufnimmt und in Echtzeit oder später wieder abspielen kann. PDF-Dateien können durchaus so verändert werden, dass sie als Keylocker funktionieren können z.B.: http://null-byte.wonderhowto.com/how-to/hack-like-pro-embed-backdoor-connection-innocent-looking-pdf-0140942/ oder https://www.youtube.com/watch?v=TC9rWXHjtkI Wobei die Anpassung an das Zielsystem zeitaufwendig ist und sicherlich nicht mal so schnell nebenbei funktioniert.

rhgb quite single
-----------------
Es handelt sich um ein CentOS oder Redhat Betriebssystem. rhgb steht für redhat graphical boot. quite sorgt dafür, dass alle Bootmeldungen unterdrückt werden und Single User ist ein Modus in dem das System sich im Wartungsmodus befindet. man kann alles mit dem System machen ohne das es nach einem Passwort etc. fragt. 

mount
-----
Er bindet eine Festplatte in das System ein (wohl seine USB-Festplatte) die mit NTFS formatiert ist. Das ist eigentlich ungewöhnlich weil man bisher den Eindruck hatte, dass er der Unixwelt doch zugetan ist. NTFS ist das Standard-Filesystem ab Windows 7 und für Server seit Windows Server NT. 

Überweisung
-----------
(1:46:31) Den direkten Zugriff ohne Passwort von einem fast öffentlichen Terminal sollte nicht wirklich funktionieren. 

ssh
---
(1:46:31) SSH ist eine stark verschlüsselte Verbindung zu einem anderen Computer. Woher er jetzt das Passwort hat, ist mir nicht ganz klar, aber gut. Die rote Einfärbung der Schrift macht sich einfach besser für einen Film.
