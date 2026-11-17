#!/usr/bin/env python3
"""
Datengrundlage fuer den Modellvergleich auf Datenart 3
(Zugangsdatenpaare).

Gleicher Aufbau wie `06_retrieval_daten.py` fuer die Pfade, damit die
Ergebnisse vergleichbar sind:

  Anfrage = beobachtetes Paar `benutzer:kennwort`
  Korpus  = Beschreibungstexte der Nuclei-Templates zu Werkseinstellungen
  Ziel    = das Template, dessen Zugangsdaten auf das Paar passen

Vielfachheit: Wie bei den Pfaden taugt ein Paar nur als Ground Truth,
wenn hoechstens fuenf Templates es fuehren. `admin:admin` steht in 81
Templates und faellt heraus, `a:3ware` in einem einzigen.

Aufruf:
    python 12_zugangsdaten_daten.py [--host ba-db-vps] [--test-anteil 0.3]
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
    return p.stdout.decode("utf-8", "replace").splitlines()


def ist_test(tid, anteil=0.3):
    h = hashlib.sha256(tid.encode("utf-8")).digest()
    return (int.from_bytes(h[:4], "big") % 10000) < anteil * 10000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    ap.add_argument("--test-anteil", type=float, default=0.3)
    ap.add_argument("--max-vielfachheit", type=int, default=5)
    args = ap.parse_args()

    # Gesucht wird im vollstaendigen Templatebestand, nicht nur in den 307
    # Templates zu Werkseinstellungen. Nur bei gleicher Korpusgroesse sind
    # die Werte mit denen der Anfragepfade vergleichbar.
    korpus = [json.loads(z) for z in
              io.open(os.path.join(DATEN, "korpus.jsonl"), encoding="utf-8")]
    print(f"Korpus (vollstaendig): {len(korpus)} Templates")

    paare = [json.loads(z) for z in
             io.open(os.path.join(DATEN, "zugangsdaten_paare.jsonl"),
                     encoding="utf-8")]
    je_paar = collections.defaultdict(list)
    for p in paare:
        je_paar[p["paar"]].append(p["template_id"])

    # Beobachtete Paare. Die Zeilen werden von rechts getrennt, weil
    # Benutzernamen und Kennwoerter selbst Tabulatoren enthalten koennen.
    # Wie bei den Pfaden werden die Quellnetze mitgefuehrt (Mittelung
    # ueber Netze, siehe 15_robustheit.py), dazu die zwei eindeutigen
    # Zuordnungen fuer die Gegenprobe:
    #   hauptnetz  Netz mit den meisten Versuchen zu diesem Paar
    #   erstnetz   Netz, aus dem das Paar zuerst kam
    beob = {}
    for z in psql(args.host, """
        WITH je AS (
          SELECT paar, host(quellnetz) AS netz, count(*) AS n,
                 min(event_time) AS erst
          FROM beobachtete_zugangsdaten GROUP BY 1, 2)
        SELECT paar, sum(n)::bigint, count(*)::bigint,
               string_agg(DISTINCT netz, ','),
               (array_agg(netz ORDER BY n DESC, netz))[1],
               (array_agg(netz ORDER BY erst ASC, netz))[1]
        FROM je GROUP BY paar;"""):
        t = z.rsplit(TAB, 5)
        if len(t) == 6 and t[1].isdigit() and t[2].isdigit():
            beob[t[0]] = (int(t[1]), int(t[2]),
                          t[3].split(",") if t[3] else [], t[4], t[5])
    print(f"beobachtete Paare: {len(beob)}")

    anfragen = []
    verworfen = collections.Counter()
    for paar, (events, netze, netzliste, haupt, erst) in beob.items():
        tids = je_paar.get(paar)
        if not tids:
            verworfen["kein Referenzpaar"] += 1
            continue
        eindeutige = sorted(set(tids))
        if len(eindeutige) > args.max_vielfachheit:
            verworfen[f"ueber {args.max_vielfachheit} Templates"] += 1
            continue
        anfragen.append({
            "anfrage": paar,
            "template_id": eindeutige[0],
            "alle_templates": eindeutige,
            "vielfachheit": len(eindeutige),
            "guete": "eindeutig" if len(eindeutige) == 1 else "eng",
            "events": events, "netze": netze,
            "quellnetze": netzliste,
            "hauptnetz": haupt, "erstnetz": erst,
        })

    trainings_ids = {k["template_id"] for k in korpus
                     if not ist_test(k["template_id"], args.test_anteil)}
    text_je_id = {k["template_id"]: k["text"] for k in korpus}
    lernpaare = [{"template_id": p["template_id"],
                  "text": text_je_id[p["template_id"]],
                  "muster": p["paar"]}
                 for p in paare
                 if p["template_id"] in trainings_ids
                 and p["template_id"] in text_je_id]

    for name, daten in (("anfragen_zugangsdaten.jsonl", anfragen),
                        ("paare_zugangsdaten.jsonl", lernpaare)):
        with io.open(os.path.join(DATEN, name), "w",
                     encoding="utf-8", newline="\n") as fh:
            for x in daten:
                fh.write(json.dumps(x, ensure_ascii=False) + "\n")

    print()
    print("=" * 62)
    print("DATENGRUNDLAGE DATENART 3")
    print("=" * 62)
    print(f"Anfragen mit Bodenwahrheit : {len(anfragen)}")
    test_anf = [a for a in anfragen if ist_test(a["template_id"],
                                                args.test_anteil)]
    print(f"davon auf Test-Templates   : {len(test_anf)}")
    print(f"Trainingspaare             : {len(lernpaare)}")
    g = collections.Counter(a["guete"] for a in anfragen)
    print("Guete:", dict(g))
    print("verworfen:", dict(verworfen.most_common()))
    ev = sum(a["events"] for a in anfragen)
    evges = sum(v[0] for v in beob.values())
    print(f"abgedeckte Ereignisse      : {ev} von {evges} "
          f"({100.0 * ev / max(1, evges):.1f} %)")


if __name__ == "__main__":
    main()
