#!/usr/bin/env python3
"""
Bildet die Ground Truth: Welcher beobachtete Anfragepfad gehoert
nachweisbar zu welchem Nuclei-Template?

Ein beobachteter Pfad gehoert zu einem Template, wenn dessen Pfadmuster
darauf passt. Die Suche arbeitet ausschliesslich mit dem
Beschreibungstext; diese Zuordnung dient nur der Bewertung.

Drei Stufen der Zuordnung, absteigend nach Sicherheit:

  exakt      beobachteter Pfad == Muster
  praefix    Muster ohne Platzhalter ist ein Praefix des Pfades
             (deckt Anfragen mit angehaengten Parametern ab)
  regex      Muster mit Platzhaltern, in einen Ausdruck uebersetzt

Verwendet werden nur Muster der Guete `eindeutig` und `eng` aus der
Sicht nuclei_bodenwahrheit (siehe schema_bodenwahrheit.sql).

Der Abgleich laeuft lokal, weil Muster und Pfade vollstaendig in den
Speicher passen und ein Regex-Join in SQL deutlich langsamer waere.

Aufruf:
    python 04_bodenwahrheit.py [--host ba-db-vps] [--min-laenge 4]
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
    """Fragt die Datenbank ueber SSH ab und liefert Zeilen als Listen.

    Der Feldtrenner wird als echtes Tabulatorzeichen uebergeben; die
    Schreibweise -F'\\t' kaeme ueber SSH als zwei Zeichen an.
    """
    TAB = chr(9)
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
    zeilen = []
    for z in p.stdout.decode("utf-8", "replace").splitlines():
        if z.strip():
            zeilen.append(z.split("\t"))
    return zeilen


SQL_BEOBACHTET = """
SELECT pfad, count(*), count(DISTINCT src_ip), count(DISTINCT quellnetz)
FROM beobachtete_pfade
GROUP BY pfad;
"""

SQL_MUSTER = """
SELECT template_id, methode, muster, hat_platzhalter, guete, vielfachheit
FROM nuclei_bodenwahrheit
WHERE guete IN ('eindeutig', 'eng');
"""


def muster_zu_regex(muster):
    """Uebersetzt ein Muster mit Platzhaltern in einen Ausdruck.

    {{...}} steht fuer einen zur Laufzeit eingesetzten Wert. Er darf
    keinen Schraegstrich enthalten, damit `/a/{{x}}` nicht auch auf
    `/a/b/c/d` passt.
    """
    teile = re.split(r"(\{\{[^}]*\}\})", muster)
    raus = []
    for t in teile:
        if t.startswith("{{") and t.endswith("}}"):
            raus.append(r"[^/]{1,80}")
        else:
            raus.append(re.escape(t))
    return re.compile("^" + "".join(raus) + "$", re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    ap.add_argument("--min-laenge", type=int, default=4,
                    help="kuerzere beobachtete Pfade werden ignoriert; 4 laesst /mcp, /sse und /.env zu")
    ap.add_argument("--out", default=DATEN)
    args = ap.parse_args()

    print("Beobachtete Pfade laden ...")
    beob = []
    for z in psql(args.host, SQL_BEOBACHTET):
        if len(z) < 4:
            continue
        beob.append({"pfad": z[0], "events": int(z[1]),
                     "quellen": int(z[2]), "netze": int(z[3])})
    print(f"  {len(beob)} verschiedene Pfade")

    print("Muster laden ...")
    exakt = collections.defaultdict(list)
    praefixe = []
    regexe = []
    n_muster = 0
    for z in psql(args.host, SQL_MUSTER):
        if len(z) < 6:
            continue
        tid, methode, muster = z[0], z[1], z[2]
        hat_pl = z[3] == "t"
        guete, vielf = z[4], int(z[5])
        n_muster += 1
        if hat_pl:
            try:
                regexe.append((tid, muster, muster_zu_regex(muster),
                               guete, vielf))
            except re.error:
                pass
        else:
            schluessel = muster.lower().rstrip("/") or "/"
            exakt[schluessel].append((tid, muster, guete, vielf))
            praefixe.append((tid, muster, schluessel, guete, vielf))
    # Laengste Praefixe zuerst, bei gleicher Laenge das eindeutigere.
    praefixe.sort(key=lambda x: (-len(x[2]), x[4]))
    print(f"  {n_muster} diskriminierende Muster "
          f"({len(exakt)} exakt, {len(regexe)} mit Platzhalter)")

    print("Abgleich ...")
    treffer = []
    art_zaehler = collections.Counter()
    for b in beob:
        p = b["pfad"]
        if len(p) < args.min_laenge:
            art_zaehler["zu kurz"] += 1
            continue
        # `/admin` und `/admin/` bezeichnen dieselbe Ressource.
        pl = p.lower().rstrip("/") or "/"
        gefunden = None

        if pl in exakt:
            # Bei mehreren Templates gilt das mit der geringsten
            # Vielfachheit als spezifischste Zuordnung.
            tid, muster, guete, vielf = sorted(exakt[pl],
                                               key=lambda x: x[3])[0]
            gefunden = (tid, muster, "exakt", guete, vielf)
        if gefunden is None:
            # Ein Muster gilt nur als Praefix, wenn danach Parameter
            # folgen (?, &, ;, #), nicht ein weiterer Pfadabschnitt:
            # `/config` soll nicht auf `/config/app.json` passen.
            for tid, muster, ml, guete, vielf in praefixe:
                if pl.startswith(ml) and (len(pl) == len(ml)
                                          or pl[len(ml)] in "?&;#"):
                    gefunden = (tid, muster, "praefix", guete, vielf)
                    break
        if gefunden is None:
            for tid, muster, rx, guete, vielf in regexe:
                if rx.match(p):
                    gefunden = (tid, muster, "regex", guete, vielf)
                    break

        if gefunden:
            art_zaehler[gefunden[2]] += 1
            treffer.append({
                "pfad": p, "template_id": gefunden[0], "muster": gefunden[1],
                "art": gefunden[2], "guete": gefunden[3],
                "vielfachheit": gefunden[4],
                "events": b["events"], "quellen": b["quellen"],
                "netze": b["netze"]})
        else:
            art_zaehler["kein Treffer"] += 1

    os.makedirs(args.out, exist_ok=True)
    ziel = os.path.join(args.out, "bodenwahrheit.jsonl")
    with io.open(ziel, "w", encoding="utf-8", newline="\n") as fh:
        for t in treffer:
            fh.write(json.dumps(t, ensure_ascii=False) + "\n")

    gesamt = len(beob)
    zugeordnet = len(treffer)
    ev_gesamt = sum(b["events"] for b in beob)
    ev_zugeordnet = sum(t["events"] for t in treffer)

    print()
    print("=" * 62)
    print("ERGEBNIS")
    print("=" * 62)
    print(f"beobachtete Pfade      : {gesamt}")
    print(f"davon zugeordnet       : {zugeordnet}"
          f"  ({100.0 * zugeordnet / max(1, gesamt):.1f} %)")
    print(f"Ereignisse gesamt      : {ev_gesamt}")
    print(f"davon zugeordnet       : {ev_zugeordnet}"
          f"  ({100.0 * ev_zugeordnet / max(1, ev_gesamt):.1f} %)")
    print()
    for art, n in art_zaehler.most_common():
        print(f"  {art:<14} {n:>7}")
    print()
    guete_z = collections.Counter(t["guete"] for t in treffer)
    for g in ("eindeutig", "eng"):
        n = guete_z.get(g, 0)
        ev = sum(t["events"] for t in treffer if t["guete"] == g)
        print(f"  Guete {g:<10} {n:>6} Pfade, {ev:>7} Ereignisse")
    print()
    print(f"geschrieben nach {ziel}")


if __name__ == "__main__":
    main()
