#!/usr/bin/env python3
"""
Erstellt die Datengrundlage fuer den Verfahrensvergleich.

Aufgabe: Zu einem beobachteten Anfragepfad das passende Nuclei-Template
finden, gesucht wird ausschliesslich im Beschreibungstext der Templates.
Anfrage und Dokument sind damit verschiedene Textsorten (Pfad gegen
Fliesstext).

Drei Mengen entstehen:

  korpus.jsonl     alle Templates mit ihrem Suchtext (Textseite)
  anfragen.jsonl   beobachtete Pfade mit ihrer Bodenwahrheit
  paare.jsonl      Trainingspaare (Beschreibung, Pfadmuster)

Aufteilung: Die Trainingspaare enthalten keine Templates, die in der
Bewertung als Ground Truth dienen. Getrennt wird reproduzierbar nach
einem Hash der Template-Kennung (Testanteil 30 Prozent).

Die zweite Aufteilung, nach dem /24-Netz der Quelle, betrifft die
beobachteten Pfade. Sie wird hier vorbereitet (Feld `quellnetz`) und
in der Auswertung angewandt.

Aufruf:
    python 06_retrieval_daten.py [--host ba-db-vps] [--test-anteil 0.3]
"""
import argparse
import collections
import hashlib
import io
import json
import os
import subprocess
import sys

DATEN = "daten"
TAB = chr(9)


def psql(host, sql):
    befehl = (
        "set -a; . ~/ba-db/.env; set +a; "
        "docker exec -i -e PGPASSWORD=$POSTGRES_PASSWORD ba-postgres "
        "psql -U $POSTGRES_USER -d $POSTGRES_DB -tA -F'" + TAB + "' -f -"
    )
    p = subprocess.run(["ssh", host, befehl], input=sql.encode("utf-8"),
                       capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        sys.exit("Abfrage fehlgeschlagen.")
    return [z.split(TAB) for z in
            p.stdout.decode("utf-8", "replace").splitlines() if z.strip()]


def suchtext(name, beschreibung, tags):
    """Suchtext eines Templates: Name, Beschreibung, Tags.

    Der Name steht vorn, weil er das Ziel am knappsten beschreibt; die
    Tags stehen am Ende, weil sie Stichworte ohne Satzbau sind.
    """
    teile = [t.strip() for t in (name, beschreibung) if t and t.strip()]
    if tags:
        teile.append(" ".join(tags))
    return " ".join(teile).replace("\n", " ").strip()


def ist_test(template_id, anteil):
    """Reproduzierbare Aufteilung ueber einen Hash der Kennung.

    Anders als ein Zufallsgenerator bleibt die Zuordnung ueber Laeufe,
    Rechner und Aenderungen des Bestands hinweg gleich.
    """
    h = hashlib.sha256(template_id.encode("utf-8")).digest()
    return (int.from_bytes(h[:4], "big") % 10000) < anteil * 10000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    ap.add_argument("--test-anteil", type=float, default=0.3)
    ap.add_argument("--out", default=DATEN)
    args = ap.parse_args()

    print("Korpus laden ...")
    korpus = []
    for z in psql(args.host, """
        SELECT template_id, name, description, severity,
               array_to_string(tags, ' '), coalesce(cve_id, '')
        FROM nuclei_template;"""):
        if len(z) < 6:
            continue
        tags = z[4].split() if z[4] else []
        text = suchtext(z[1], z[2], tags)
        if not text:
            continue
        korpus.append({
            "template_id": z[0], "name": z[1], "description": z[2],
            "severity": z[3], "tags": tags, "cve_id": z[5] or None,
            "text": text,
            "test": ist_test(z[0], args.test_anteil)})
    print(f"  {len(korpus)} Templates mit Suchtext")
    n_test = sum(1 for k in korpus if k["test"])
    print(f"  davon Testmenge: {n_test} ({100.0*n_test/len(korpus):.1f} %)")

    print("Bodenwahrheit laden ...")
    bw = [json.loads(z) for z in
          io.open(os.path.join(DATEN, "bodenwahrheit.jsonl"), encoding="utf-8")]
    print(f"  {len(bw)} zugeordnete Pfade")

    print("Quellnetze je Pfad laden ...")
    netze = {}
    for z in psql(args.host, """
        SELECT pfad, string_agg(DISTINCT host(quellnetz), ',')
        FROM beobachtete_pfade GROUP BY pfad;"""):
        if len(z) >= 2:
            netze[z[0]] = z[1].split(",") if z[1] else []

    # Eindeutige Netzzuordnung fuer die Robustheitspruefung (Kap. 3.7).
    # Ein Pfad wird im Median aus zwei Netzen gesehen und zaehlt bei der
    # Mittelung ueber Netze in jedem davon mit; die Netze sind dadurch
    # nicht unabhaengig. Zur Gegenprobe wird jeder Pfad genau einem Netz
    # zugeschlagen, nach zwei alternativen Regeln:
    #
    #   hauptnetz  Netz mit den meisten Ereignissen zu diesem Pfad
    #   erstnetz   Netz, aus dem der Pfad zuerst beobachtet wurde;
    #              unabhaengig von spaeteren Wiederholungen
    print("Eindeutige Netzzuordnung (Gegenprobe) laden ...")
    hauptnetz, erstnetz = {}, {}
    for z in psql(args.host, """
        WITH je AS (
          SELECT pfad, host(quellnetz) AS netz, count(*) AS n,
                 min(event_time) AS erst
          FROM beobachtete_pfade GROUP BY 1, 2)
        SELECT pfad,
               (array_agg(netz ORDER BY n DESC, netz))[1],
               (array_agg(netz ORDER BY erst ASC, netz))[1]
        FROM je GROUP BY pfad;"""):
        if len(z) >= 3:
            hauptnetz[z[0]] = z[1]
            erstnetz[z[0]] = z[2]

    im_korpus = {k["template_id"] for k in korpus}
    anfragen = []
    fehlend = 0
    for b in bw:
        if b["template_id"] not in im_korpus:
            fehlend += 1
            continue
        anfragen.append({
            "pfad": b["pfad"],
            "template_id": b["template_id"],
            "guete": b["guete"],
            "art": b["art"],
            "events": b["events"],
            "quellen": b["quellen"],
            "quellnetze": netze.get(b["pfad"], []),
            "hauptnetz": hauptnetz.get(b["pfad"]),
            "erstnetz": erstnetz.get(b["pfad"]),
        })
    if fehlend:
        print(f"  {fehlend} ohne Template im Korpus uebersprungen")

    print("Trainingspaare bilden ...")
    # Paare (Beschreibungstext, Pfadmuster) nur aus Templates der
    # Trainingsmenge.
    trainings_ids = {k["template_id"] for k in korpus if not k["test"]}
    text_je_id = {k["template_id"]: k["text"] for k in korpus}
    paare = []
    for z in psql(args.host, """
        SELECT template_id, muster FROM nuclei_bodenwahrheit
        WHERE guete IN ('eindeutig', 'eng');"""):
        if len(z) < 2:
            continue
        tid, muster = z[0], z[1]
        if tid in trainings_ids and tid in text_je_id:
            paare.append({"template_id": tid, "text": text_je_id[tid],
                          "muster": muster})
    print(f"  {len(paare)} Paare aus {len(trainings_ids)} Trainings-Templates")

    os.makedirs(args.out, exist_ok=True)
    for name, daten in (("korpus.jsonl", korpus),
                        ("anfragen.jsonl", anfragen),
                        ("paare.jsonl", paare)):
        with io.open(os.path.join(args.out, name), "w",
                     encoding="utf-8", newline="\n") as fh:
            for d in daten:
                fh.write(json.dumps(d, ensure_ascii=False) + "\n")

    print()
    print("=" * 62)
    print("DATENGRUNDLAGE")
    print("=" * 62)
    print(f"Korpus    : {len(korpus)} Templates")
    print(f"Anfragen  : {len(anfragen)} beobachtete Pfade mit Bodenwahrheit")
    test_anf = [a for a in anfragen if ist_test(a["template_id"],
                                                args.test_anteil)]
    print(f"  davon auf Test-Templates: {len(test_anf)}")
    print(f"Paare     : {len(paare)} (nur Trainings-Templates)")
    g = collections.Counter(a["guete"] for a in anfragen)
    print("Guete der Anfragen:", dict(g))
    ohne_netz = sum(1 for a in anfragen if not a["quellnetze"])
    print(f"Anfragen ohne Quellnetz: {ohne_netz}")


if __name__ == "__main__":
    main()
