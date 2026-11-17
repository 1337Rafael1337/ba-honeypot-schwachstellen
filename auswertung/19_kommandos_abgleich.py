#!/usr/bin/env python3
"""
Gleicht die beobachteten Kommandos mit Atomic Red Team ab (Kap. 3.6, 4.4).

Atomic Red Team ordnet jeder ATT&CK-Technik konkrete Kommandozeilen zu.
Eine beobachtete Zeile gilt als zugeordnet, wenn sie nach Normalisierung
einer Referenzzeile entspricht. Referenzzeilen mit Platzhaltern (#{...})
sind ausgeschlossen, weil sie auf beliebigen Text passen wuerden.

Zusaetzlich wird ein lockerer Abgleich ueber das erste Wort der Zeile,
also den aufgerufenen Befehl, gerechnet. Er zeigt, ob ein niedriges
Ergebnis an der Strenge der Regel liegt.

Aufruf:
    python 19_kommandos_abgleich.py [--host ba-db-vps]
"""
import argparse
import collections
import io
import json
import os
import re
import subprocess
import sys

DATEN = "daten"


def psql(host, sql):
    TAB = chr(9)
    befehl = ("set -a; . ~/ba-db/.env; set +a; "
              "docker exec -i -e PGPASSWORD=$POSTGRES_PASSWORD ba-postgres "
              "psql -U $POSTGRES_USER -d $POSTGRES_DB -tA -F'" + TAB + "' -f -")
    p = subprocess.run(["ssh", host, befehl], input=sql.encode("utf-8"),
                       capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        sys.exit("Abfrage fehlgeschlagen.")
    return [z.split(TAB) for z in p.stdout.decode("utf-8", "replace").splitlines()
            if z.strip()]


def normal(s):
    """Vereinheitlicht Leerraum und Anfuehrungszeichen, sonst nichts."""
    s = s.strip().lower()
    s = s.replace('"', "'")
    return re.sub(r"\s+", " ", s)


def erstes_wort(s):
    s = normal(s)
    s = re.sub(r"^(sudo|nohup|exec)\s+", "", s)
    m = re.match(r"[./a-z0-9_-]+", s)
    return m.group(0).rsplit("/", 1)[-1] if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    args = ap.parse_args()

    ref = [json.loads(z) for z in
           io.open(os.path.join(DATEN, "kommandos_referenz.jsonl"),
                   encoding="utf-8") if z.strip()]
    ref = [r for r in ref if not r.get("hat_platzhalter")]
    ref_exakt = {}
    ref_befehl = collections.defaultdict(set)
    for r in ref:
        ref_exakt.setdefault(normal(r["kommando"]), r["template_id"])
        w = erstes_wort(r["kommando"])
        if w:
            ref_befehl[w].add(r["template_id"])
    print(f"Referenzzeilen ohne Platzhalter : {len(ref)}")
    print(f"davon verschieden               : {len(ref_exakt)}")

    # Tabulatoren und Zeilenumbrueche in Kommandos wuerden die
    # psql-Ausgabe zerlegen; sie werden in der Abfrage durch Leerzeichen
    # ersetzt. Die Anzahl steht vorn, damit ein verbliebener Trenner das
    # Einlesen nicht stoert.
    zeilen = psql(args.host, """
        SELECT count(*),
               regexp_replace(kommando, '[	
]+', ' ', 'g')
        FROM beobachtete_kommandos
        GROUP BY kommando ORDER BY count(*) DESC;
    """)
    TAB = chr(9)
    beob = []
    for z in zeilen:
        anzahl, rest = z[0], TAB.join(z[1:])
        beob.append((rest, int(anzahl)))
    ereignisse = sum(n for _, n in beob)
    print(f"beobachtete Kommandozeilen      : {len(beob)}")
    print(f"beobachtete Kommandoereignisse  : {ereignisse}")

    treffer, treffer_ev = [], 0
    locker, locker_ev = [], 0
    for k, n in beob:
        if normal(k) in ref_exakt:
            treffer.append((k, n, ref_exakt[normal(k)]))
            treffer_ev += n
        w = erstes_wort(k)
        if w and w in ref_befehl:
            locker.append((k, n))
            locker_ev += n

    print()
    print("=" * 62)
    print("ABGLEICH GEGEN ATOMIC RED TEAM")
    print("=" * 62)
    print(f"streng (ganze Zeile)  : {len(treffer)} Zeilen "
          f"({100.0*len(treffer)/max(1,len(beob)):.2f} %), "
          f"{treffer_ev} Ereignisse "
          f"({100.0*treffer_ev/max(1,ereignisse):.2f} %)")
    print(f"locker (erstes Wort)  : {len(locker)} Zeilen "
          f"({100.0*len(locker)/max(1,len(beob)):.2f} %), "
          f"{locker_ev} Ereignisse "
          f"({100.0*locker_ev/max(1,ereignisse):.2f} %)")
    if treffer:
        print()
        print("die strengen Treffer:")
        for k, n, t in sorted(treffer, key=lambda x: -x[1])[:15]:
            print(f"  {n:>6} x  {t:<12} {k[:60]}")

    with io.open(os.path.join(DATEN, "kommandos_abgleich.json"), "w",
                 encoding="utf-8", newline="\n") as fh:
        json.dump({
            "referenzzeilen": len(ref),
            "beobachtete_zeilen": len(beob),
            "beobachtete_ereignisse": ereignisse,
            "streng_zeilen": len(treffer),
            "streng_ereignisse": treffer_ev,
            "locker_zeilen": len(locker),
            "locker_ereignisse": locker_ev,
        }, fh, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
