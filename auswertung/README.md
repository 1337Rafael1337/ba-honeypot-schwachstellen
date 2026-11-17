# Auswertungskette

Skripte und Datenbanksichten, die aus den Rohdaten die Ergebnisse der
Arbeit erzeugen. Alle Befehle werden in diesem Ordner ausgeführt;
Zwischenergebnisse liegen in `daten/` (nicht versioniert).

In Dateinamen und Bezeichnern steht *Bodenwahrheit* für die Ground Truth
der Arbeit. Die Skripte sind nach ihrer Entstehung nummeriert; die
Nummer 10 ist nicht vergeben. Die Hilfsfunktionen `psql`
(Datenbankabfrage) und `ist_test` (Aufteilung in Trainings- und
Testmenge) stehen in jedem Skript, das sie braucht. Die Skripte `14` bis
`17` laden die Ähnlichkeits- und Bewertungsfunktionen aus
`07_retrieval_messen.py`.

## Voraussetzungen

- Python 3 mit den Paketen aus [`requirements.txt`](requirements.txt)
  (Versionsstand der Auswertung)
- Für die Domänenanpassung (`08`) eine GPU; verwendet wurde eine Karte
  mit 12 GB
- SSH-Zugang zum Datenserver unter dem Alias `ba-db-vps`. Die Skripte
  fragen dort den Container `ba-postgres` mit den Zugangsdaten aus
  `~/ba-db/.env` ab (siehe `../erhebung/db-server/`).

## Datenbank

Die Schemata werden einmalig in dieser Reihenfolge eingespielt:

| Datei | Inhalt |
|---|---|
| `../erhebung/db-server/schema.sql` | Rohdaten `captured_events` |
| `../erhebung/db-server/schema_payloads.sql` | Nutzlastdateien `glutton_payloads` |
| `schema_stichtag.sql` | Stichtag der Auswertung (05.10.2026, 00:00 UTC) |
| `schema_nuclei.sql` | Templates, Pfadmuster, Ladeprotokoll |
| `schema_sichten.sql` | Datenart 1: `beobachtete_pfade` |
| `schema_sichten_2.sql` | Datenarten 2 bis 4: Kommandos, Zugangsdaten, Zielports |
| `schema_bodenwahrheit.sql` | Gütestufe je Pfadmuster: `nuclei_bodenwahrheit` |
| `schema_klassen.sql` | Zielklassen und Konzentration je Klasse |

Die Auswertungsskripte lesen die Daten ausschließlich über diese
Sichten und damit nur Ereignisse vor dem Stichtag. Ausnahme ist die
Gegenprüfung `05`, die für Stichproben direkt `captured_events` abfragt.

## Referenzdaten

```
git clone https://github.com/projectdiscovery/nuclei-templates daten/nuclei-templates
git clone https://github.com/redcanaryco/atomic-red-team daten/atomic-red-team
```

Dazu die IANA-Portregistrierung als `daten/iana-ports.csv`
(service-names-port-numbers.csv). Den KEV-Katalog lädt
`18_kev_abgleich.py` bei Bedarf selbst. Der verwendete Stand der
Nuclei-Templates wird beim Laden in der Tabelle `nuclei_ladelauf`
festgehalten.

## Ablauf

**Anfragepfade (Datenart 1)**

```
python 01_nuclei_parsen.py                    # Templates in Text- und Musterseite zerlegen
python 02_parser_pruefen.py                   # Gegenprüfung des Parsers
python 03_nuclei_laden.py                     # in die Datenbank laden
python 04_bodenwahrheit.py                    # Ground Truth: beobachtete Pfade -> Templates
python 05_bodenwahrheit_pruefen.py            # Gegenprüfung der Ground Truth
python 06_retrieval_daten.py                  # Korpus, Anfragen, Trainingspaare
python 08_anpassen.py --basis intfloat/e5-base-v2 --epochen 1 --batch 32
python 07_retrieval_messen.py --modelle tfidf-char,tfidf-wort,intfloat/e5-base-v2,daten/modelle/angepasst-e5-base-v2-e1-b32 --gpu
python 15_robustheit.py --datenart pfade --gpu                      # Bereiche, paarweiser Vergleich
python 15_robustheit.py --datenart pfade --gpu --netzregel haupt    # Gegenprobe
python 15_robustheit.py --datenart pfade --gpu --netzregel erst     # Gegenprobe
python 17_wortueberschneidung.py --gpu        # Wirkung der Wortüberschneidung
python 18_kev_abgleich.py                     # Abgleich mit dem KEV-Katalog
python 20_reichweite_verlauf.py               # Reichweite über die Betriebstage
python 16_abbildungen.py --gpu                # Zahlenreihen für zwei Abbildungen
```

**Kommandos (Datenart 2)**

```
python 13_kommandos_referenz.py               # Referenz aus Atomic Red Team
python 19_kommandos_abgleich.py               # Abgleich, streng und locker
python 09_logprecis_pruefen.py                # Verdichtung der Sitzungen, LogPrecis-Probe
```

**Zugangsdatenpaare (Datenart 3)**

```
python 11_zugangsdaten_referenz.py            # Paare aus den Default-Login-Templates
python 12_zugangsdaten_daten.py               # Anfragen und Trainingspaare
python 08_anpassen.py --basis intfloat/e5-base-v2 --epochen 3 --batch 16 --paare paare_zugangsdaten.jsonl
python 07_retrieval_messen.py --datenart zugangsdaten --modelle tfidf-char,intfloat/e5-base-v2,daten/modelle/angepasst-e5-base-v2-zugangsdaten-e3-b16 --gpu
python 15_robustheit.py --datenart zugangsdaten --gpu --netzregel haupt --modelle tfidf-char,intfloat/e5-base-v2,daten/modelle/angepasst-e5-base-v2-zugangsdaten-e3-b16
```

**Zielports (Datenart 4)**

```
python 14_ports_messen.py --gpu               # setzt das angepasste Modell aus 08 voraus
```

`_diagnose_verlust.py` ist ein Diagnosewerkzeug zum Parser und gehört
nicht zum Ablauf.

## Ausgaben in `daten/`

| Datei | Inhalt |
|---|---|
| `templates.jsonl`, `muster.jsonl` | Text- und Musterseite der Templates |
| `bodenwahrheit.jsonl` | beobachteter Pfad -> Template |
| `korpus.jsonl` | Suchtexte mit Kennzeichen Training/Test |
| `anfragen.jsonl`, `anfragen_zugangsdaten.jsonl` | Anfragen mit Ground Truth und Quellnetzen |
| `paare.jsonl`, `paare_zugangsdaten.jsonl` | Trainingspaare, nur aus Trainings-Templates |
| `messungen.jsonl` | Messwerte, eine Zeile je Verfahren und Lauf (angehängt) |
| `robustheit.jsonl` | Bereiche und paarweise Vergleiche (angehängt) |
| `trainingslaeufe.jsonl` | Protokoll der Domänenanpassung (angehängt) |

## Grundlage der berichteten Ergebnisse

Die angehängten Dateien enthalten auch Läufe vom 14.09. bis 20.09.2026.
Das waren Funktionsprüfungen der Kette während der Erhebung, keine
Ergebnisse. Die Ergebnisse der Arbeit stammen ausschließlich aus Läufen
ab dem 05.10.2026 auf dem Stichtagsbestand, je Datenart und Verfahren aus
dem jeweils letzten Lauf:

| Datenart | Lauf (UTC) |
|---|---|
| Anfragepfade | 05.10.2026, 14:28 bis 14:32 (211 Testanfragen) |
| Zugangsdaten | 05.10.2026, 15:16 bis 15:18 und 22:25 (eigens angepasstes Modell) |
| Zielports | 05.10.2026, 15:20 |
| Robustheit | Anfragepfade: 05.10.2026, letzter Lauf je Netzregel; Zugangsdaten: 05.10.2026, 22:25 (Netzregel haupt) |

Der Verlauf der Reichweite (`20`) wurde am 06.10.2026 ebenfalls auf dem
Stichtagsbestand gerechnet.

## Zentrale Zahlen der Arbeit und ihre Herkunft

| Zahl in der Arbeit | Stelle | Skript | Quelle der Zahl |
|---|---|---|---|
| 11.471 verschiedene Pfade, Verdichtung rund 23 zu 1 | 4.2.1 | `04` | Konsolenausgabe |
| Anteil der größten 1 bzw. 5 Prozent der Netze: 58,9 bzw. 74,4 Prozent | 4.2.1 | `16` | Konsolenausgabe |
| 720 Muster mit Ground Truth (590 eindeutig), Reichweite 6,3 Prozent; 35.298 von 265.733 Ereignissen | 4.2.2 | `04` | `bodenwahrheit.jsonl` |
| Reichweite nach Tag 1, 10, 20: 17,0 / 11,0 / 8,8 Prozent | 4.2.2 | `20` | `reichweite_verlauf.jsonl` |
| 150 probierte CVE, davon 51 im KEV-Katalog; 3.395 von 11.740 Ereignissen | 4.2.3 | `18` | `kev_abgleich.json` |
| Anfragepfade, MRR über die Anfragen: 0,395 / 0,285 / 0,338 / 0,207; R@10 und R@50 | 4.3.1, Tab. Verfahrensvergleich | `07` | `messungen.jsonl` |
| Anfragepfade, MRR über die Netze (Hauptregel, 49 Netze): 0,286 / 0,211 / 0,200 / 0,156 | 4.3.1 | `15` | `robustheit.jsonl` |
| Bereiche und paarweise Differenzen | 4.3.1 | `15` | `robustheit.jsonl` |
| Trefferquote über die Rangtiefe (z. B. R@1 0,332 / 0,289) | 4.3.1, Abbildung | `16` | Konsolenausgabe |
| Aufteilung nach Wortüberschneidung (137 / 74 Anfragen) | 4.3.2 | `17` | Konsolenausgabe |
| 6.208 Sitzungen, 2.264 Abfolgen, 2,7 zu 1 | 4.4, 5 | `09` | Konsolenausgabe |
| 3.480 Kommandozeilen; streng 5 zugeordnet, locker 3.078 (88,5 Prozent) | 4.4 | `19` | `kommandos_abgleich.json` |
| Zugangsdaten, 53 Testanfragen: MRR 0,174 / 0,146 / 0,091 (Anfragen), 0,198 / 0,170 / 0,099 (Netze) | 4.5 | `07`, `15` | `messungen.jsonl`, `robustheit.jsonl` |
| Zielports, 6.197 Anfragen: MRR 0,0052 / 0,0044 / 0,0036, Zufall 0,0015 | 4.6 | `14` | `messungen.jsonl` |

Die Reihenfolge der MRR-Werte folgt jeweils der Tabelle in der Arbeit.

## Reproduzierbarkeit

Fest sind die Aufteilung in Trainings- und Testmenge (Hash der
Template-Kennung), die Bootstrap-Ziehungen (`--saat`, Vorgabe 42) und die
Stichproben in `02` und `17`. Die Domänenanpassung in `08` setzt dagegen
keinen Startwert für torch: Ein erneutes Training erzeugt ein leicht
abweichendes Modell und damit leicht abweichende Werte. Die berichteten
Ergebnisse beruhen auf den Modellen vom 05.10.2026 (siehe
`trainingslaeufe.jsonl`).

## Bekannte Abweichung

`12_zugangsdaten_daten.py` bildet die Gesamtzahl der Anmeldeversuche aus
der zeilenweise gelesenen psql-Ausgabe. Paare mit Zeilenumbruch oder
Tabulator im Kennwort fallen dabei heraus (164.013 statt 164.020). Die
Arbeit nennt den Wert aus `count(*)` der Sicht (164.020); die
Zuordnungen selbst sind nicht betroffen.

## Zwei Aufteilungen

- **Nach Template-Kennung** (`06_retrieval_daten.py`, fester Hash,
  Testanteil 30 Prozent): trennt Trainings- von Testmenge für den
  Verfahrensvergleich.
- **Nach dem /24-Netz der Quelle** (Felder `quellnetze`, `hauptnetz`,
  `erstnetz`): Grundlage der Mittelung über Netze in
  `15_robustheit.py`, damit ein einzelner Scanner das Ergebnis nicht
  dominiert.
