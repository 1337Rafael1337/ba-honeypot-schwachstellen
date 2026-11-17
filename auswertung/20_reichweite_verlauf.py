"""
Verlauf der Reichweite des Referenzwissens ueber die Betriebstage
(Kap. 4.2.2).

Kumulierter Zeitschnitt durch den abgeschlossenen Bestand (Stichtag
05.10.2026): Fuer jeden Betriebstag wird gezaehlt, welche Muster bis zu
dessen Ende erstmals beobachtet waren und wie viele davon eine Ground
Truth haben.

Tagesdefinition wie in der Abbildung zum Musterzuwachs: Betriebstag k
umfasst [Start + (k-1) * 24 h, Start + k * 24 h), Start ist der
05.09.2026, 15:47 UTC. Der angebrochene 30. Tag wird gekennzeichnet
ausgegeben.

Die Ground Truth stammt aus daten/bodenwahrheit.jsonl (Ausgabe von
04_bodenwahrheit.py auf dem Stichtagsbestand). Ob ein Muster eine Ground
Truth hat, haengt nur vom Pfad und vom Nuclei-Stand ab, nicht vom
Zeitpunkt; der Zeitschnitt aendert also nur die Menge der Muster.

Aufruf:
    python 20_reichweite_verlauf.py [--host ba-db-vps]
"""

import argparse
import datetime as dt
import io
import json
import os
import subprocess
import sys

HIER = os.path.dirname(os.path.abspath(__file__))
DATEN = os.path.join(HIER, "daten")
START = dt.datetime(2026, 9, 5, 15, 47, tzinfo=dt.timezone.utc)

SQL = """
SELECT pfad, min(event_time) AT TIME ZONE 'UTC'
FROM beobachtete_pfade
GROUP BY pfad;
"""


def psql(host, sql):
    """Wie in 04_bodenwahrheit.py: echtes Tabulatorzeichen als Trenner."""
    tab = chr(9)
    befehl = (
        "set -a; . ~/ba-db/.env; set +a; "
        "docker exec -i -e PGPASSWORD=$POSTGRES_PASSWORD ba-postgres "
        "psql -U $POSTGRES_USER -d $POSTGRES_DB -tA -F'" + tab + "' -f -"
    )
    p = subprocess.run(["ssh", host, befehl], input=sql.encode("utf-8"),
                       capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        sys.exit("Abfrage fehlgeschlagen.")
    return [z.split(tab) for z in
            p.stdout.decode("utf-8", "replace").splitlines() if z.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    args = ap.parse_args()

    mit_gt = {json.loads(z)["pfad"] for z in
              io.open(os.path.join(DATEN, "bodenwahrheit.jsonl"),
                      encoding="utf-8") if z.strip()}

    erster_tag = {}
    for pfad, zeit in psql(args.host, SQL):
        t = dt.datetime.fromisoformat(zeit[:19]).replace(
            tzinfo=dt.timezone.utc)
        erster_tag[pfad] = int((t - START).total_seconds() // 86400) + 1

    fehlend = mit_gt - set(erster_tag)
    if fehlend:
        sys.exit(f"{len(fehlend)} Pfade mit Ground Truth fehlen in der "
                 "Datenbank -- Datenstaende passen nicht zusammen.")

    letzter = max(erster_tag.values())
    zeilen = []
    for k in range(1, letzter + 1):
        muster = [p for p, d in erster_tag.items() if d <= k]
        n_gt = sum(1 for p in muster if p in mit_gt)
        zeilen.append({"tag": k, "muster": len(muster), "mit_gt": n_gt,
                       "anteil": round(100.0 * n_gt / len(muster), 2),
                       "angebrochen": k == letzter and k > 29})
        print(f"Tag {k:2d}{'*' if zeilen[-1]['angebrochen'] else ' '} "
              f"Muster {len(muster):6d}  mit GT {n_gt:4d}  "
              f"{zeilen[-1]['anteil']:5.2f} %")

    with io.open(os.path.join(DATEN, "reichweite_verlauf.jsonl"), "w",
                 encoding="utf-8") as fh:
        for z in zeilen:
            fh.write(json.dumps(z, ensure_ascii=False) + "\n")
    print("geschrieben: daten/reichweite_verlauf.jsonl")


if __name__ == "__main__":
    main()
