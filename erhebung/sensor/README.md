# Sensor (T-Pot)

Der Sensor wurde nach Ende der Erhebung neu aufgesetzt; seine
Konfigurationsdateien und Skripte liegen nicht mehr vor. Diese
Beschreibung stammt aus dem Installationsprotokoll der Erhebung
(Kap. 3.1).

## Plattform

- T-Pot (`telekom-security/tpotce`, Branch `master`, Commit `3fefeba`
  vom 04.09.2026), Installationstyp Hive, Debian 13, eine öffentliche
  IPv4-Adresse, die nicht veröffentlicht wurde.
- Modulauswahl mit `compose/customizer.py` erzeugt und als
  `docker-compose.yml` eingesetzt; `tpot.service` startet den Stack.
- `ewsposter`, der Dienst zur Datenübermittlung an den Hersteller, war
  nie Teil der Konfiguration (Kap. 3.2).
- Administrativer SSH-Zugang auf Port 64295, damit Cowrie die Ports 22
  und 23 belegen kann.

## Sensoren

Inbetriebnahme am 05.09.2026 mit Glutton, Cowrie, Dionaea und Log4Pot,
am 06.09.2026 ergänzt um h0neytr4p, adbhoney, redishoneypot und
elasticpot. Die ergänzten Sensoren wurden mit einer harmlosen
Testanfrage bis in die Datenbank geprüft.

| Sensor | Rolle in der Arbeit | Ports |
|---|---|---|
| Glutton | Verbindungsmitschnitt, legt Nutzlasten als Dateien ab | alle sonst nicht belegten Ports |
| Cowrie | SSH- und Telnet-Sitzungen, Zugangsdaten, Kommandos | 22, 23 |
| Dionaea | Schadsoftware-Verbreitung | 20, 21, 42, 69/udp, 81, 135, 445, 1433, 1723, 1883, 3306, 27017 |
| h0neytr4p | Web-Sensor | 443, 2087 |
| Log4Pot | Log4j-Schwachstelle (CVE-2021-44228) | 80, 8080, 25565 |
| adbhoney | Android Debug Bridge | 5555 |
| redishoneypot | Redis | 6379 |
| elasticpot | Elasticsearch | 9200 |

Dazu fünf Infrastruktur-Container: `tpotinit`, `elasticsearch`,
`logstash`, `kibana`, `nginx`. Die Protokolle von `nginx` enthalten nur
den eigenen Administrationszugang und gehen in keine Datenart ein.

## Änderung an der Standardkonfiguration

Bis zum 06.09.2026 erhielten Cowrie und Teile von Dionaea keinen
Verkehr. Glutton leitet per TPROXY jede eingehende Verbindung an sich
selbst um; T-Pots `rules.sh` setzt Ausnahmen nur für die Ports aus der
Compose-Datei. Die Ports 20, 21, 22, 23 und 42 stehen dort in einfachen
Anführungszeichen (`'22:22'`), die `rules.sh` nicht entfernt; für sie
entstand keine Ausnahme.

Behebung: doppelte statt einfache Anführungszeichen (`- "22:22"`).
Danach waren SSH, Telnet, FTP und Port 42 erreichbar. Der Neustart
verursachte eine Erfassungslücke von 51 Sekunden.

## Übertragung an den Datenserver

Der Sensor schreibt nicht direkt in die Datenbank. Er liefert über SSH
an die erzwungenen Befehle in [`../db-server/`](../db-server/), mit
einem eigenen Ed25519-Schlüssel je Kanal. Die Schlüssel wurden auf dem
Sensor erzeugt.

| Kanal | Schlüssel (Kommentar) | Gegenstelle |
|---|---|---|
| Ereignisse aus dem lokalen Elasticsearch | `honeypot-vps-to-db-vps` | `run_receiver.sh` |
| Nutzlastdateien von Glutton | `honeypot-vps-payloads` | `run_payload_receiver.sh` |
| Zählung je Modul für den Abgleich | `honeypot-vps-count-check` | `run_count.sh` |

Übertragen werden die vollständigen Elasticsearch-Dokumente,
base64-kodiert als zeilenweises JSON. Die Dokumentkennung ist auf dem
Datenserver eindeutiger Schlüssel (`es_doc_id`); wiederholte
Übertragungen erzeugen keine Dubletten.

## Zeitplan (cron)

| Takt | Aufgabe |
|---|---|
| alle 10 min | Überwachung der 13 Container, von Platte und Last; Neustart bei Ausfall |
| alle 15 min | `sync_to_db.py`: neue Ereignisse übertragen |
| xx:05, :20, :35, :50 | `sync_payloads.py`: neue Nutzlastdateien übertragen |
| täglich 08:00 | `sync_to_db.py --full-days 2`: erneute Übertragung der letzten zwei Tage |
| täglich 08:10 | `sync_payloads.py --full`: alle Nutzlastdateien abgleichen |
| täglich 08:30 | `completeness_check.py`: Zählung je Modul, Elasticsearch gegen PostgreSQL |
| täglich 08:35 | `kriterien_check.py`: vorab festgelegte Abnahmekriterien, stumme Sensoren |
| täglich 00:23 | T-Pot: Aufräumen und Neustart |

Ausgewertet wird ausschließlich der Bestand in PostgreSQL.
