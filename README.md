# Zuordnung von Angriffsdaten aus Honeypots zu bekannten Schwachstellen

Code zur Bachelorarbeit „Zuordnung von Angriffsdaten aus Honeypots zu
bekannten Schwachstellen: Reichweite des öffentlichen
Schwachstellenwissens und Grenzen der semantischen Suche“
(Rafael Seel, IU Internationale Hochschule, B.Sc. Cyber Security,
Abgabe 10.11.2026, Betreuung Prof. Dr. Alexander Lawall).
Kapitelangaben beziehen sich auf die abgegebene Arbeit.

```
erhebung/sensor/      T-Pot-Sensor, Beschreibung des Aufbaus (Kap. 3.1)
erhebung/db-server/   Datenserver: Datenbank und Empfang der Sensordaten (Kap. 3.1, 3.2)
auswertung/           Auswertungskette von den Rohdaten zu den Ergebnissen (Kap. 3.3 bis 3.7, 4)
```

## Erhebung

Sensor ist eine T-Pot-Instanz, Erhebungszeitraum 05.09.2026 bis
05.10.2026. Die Daten liegen auf einem zweiten Server in PostgreSQL 16
mit pgvector.

Der Sensor wurde nach der Erhebung neu aufgesetzt. Seine Konfiguration
ist in [`erhebung/sensor/README.md`](erhebung/sensor/README.md)
beschrieben, die Dateien selbst liegen nicht mehr vor.

Dateien des Datenservers (`erhebung/db-server/`):

| Datei | Zweck |
|---|---|
| `docker-compose.yml` | PostgreSQL 16 mit pgvector, nur auf 127.0.0.1 erreichbar |
| `.env.example` | benötigte Variablen ohne Werte |
| `schema.sql`, `schema_payloads.sql` | Tabellen für Ereignisse und Nutzlastdateien |
| `run_receiver.sh` | erzwungener SSH-Befehl für die Ereignisse |
| `run_payload_receiver.sh` | erzwungener SSH-Befehl für die Nutzlastdateien |
| `run_count.sh` | erzwungener SSH-Befehl für den Vollständigkeitsabgleich |
| `receiver/` | Empfängercontainer, schreibt ausschließlich über parametrisierte Abfragen |
| `repair_module_names.sh` | einmalige Korrektur der Modulzuordnung vom 14.09.2026 |

Jeder der drei SSH-Schlüssel des Sensors ist in `authorized_keys` an
genau einen dieser Befehle gebunden (`command="…",no-port-forwarding,
no-X11-forwarding,no-agent-forwarding,no-pty`). Der Sensor kann damit
Daten einliefern, aber auf dem Datenserver nichts anderes ausführen.

## Auswertung

Reihenfolge der Skripte, Voraussetzungen, die Läufe, aus denen die
berichteten Ergebnisse stammen, und eine Zuordnung der zentralen Zahlen
der Arbeit zu Skript und Ausgabedatei stehen in
[`auswertung/README.md`](auswertung/README.md).

| Skripte | Inhalt | Arbeit |
|---|---|---|
| `schema_*.sql` | Stichtag, Sichten je Datenart, Güte der Pfadmuster | Kap. 3.3, 3.4 |
| `01`–`05` | Nuclei-Templates zerlegen und laden, Ground Truth bilden und prüfen | Kap. 3.4 |
| `06`–`08` | Korpus und Trainingspaare, Verfahrensvergleich, Domänenanpassung | Kap. 3.5, 3.7, 4.3.1 |
| `15` | Mittelung über Quellnetze, Bootstrap, paarweiser Vergleich | Kap. 3.7, 4.3.1 |
| `17` | Wortüberschneidung als Bedingung | Kap. 4.3.2 |
| `18` | Abgleich mit dem KEV-Katalog der CISA | Kap. 4.2.3 |
| `20` | Reichweite über die Betriebstage | Kap. 4.2.2 |
| `16` | Zahlenreihen für zwei Abbildungen | Kap. 4.2.1, 4.3.1 |
| `09`, `13`, `19` | Kommandos: Verdichtung der Sitzungen, Referenz aus Atomic Red Team, Abgleich | Kap. 3.6, 4.4, 5 |
| `11`, `12` | Zugangsdatenpaare: Referenz und Anfragen | Kap. 3.6, 4.5 |
| `14` | Zielports | Kap. 3.6, 4.6 |
| `_diagnose_verlust.py` | Diagnose zum Parser, kein Teil der Ergebnisse | |

## Daten

Rohdaten und abgeleitete Arbeitsdateien sind nicht enthalten. Sie
enthalten Quelladressen und damit personenbezogene Daten; nach Kap. 3.2
werden sie nicht an Dritte weitergegeben. Die Skripte erzeugen die
Arbeitsdateien aus der Datenbank im Ordner `auswertung/daten/`, der per
`.gitignore` ausgeschlossen ist. Die Referenzdaten sind öffentlich
(Nuclei-Templates, Atomic Red Team, IANA-Portregistrierung,
KEV-Katalog); die Bezugsquellen stehen in `auswertung/README.md`.

Einsicht in die Daten ist auf Anfrage möglich, etwa im Kolloquium.

## Rechte

Alle Rechte vorbehalten. Das Repository dient der Begutachtung der
Bachelorarbeit.
