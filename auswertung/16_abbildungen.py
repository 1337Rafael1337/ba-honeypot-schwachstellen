#!/usr/bin/env python3
"""
Erzeugt die Zahlenreihen fuer zwei Abbildungen des Ergebniskapitels als
pgfplots-Koordinatenlisten. Die Abbildungen werden dadurch in LaTeX in
derselben Schrift wie der Fliesstext gesetzt.

  1. Trefferquote ueber den Rang: Anteil der Testanfragen, deren
     zutreffender Eintrag unter den ersten k Raengen liegt, fuer k von 1
     bis 50 (Kap. 4.3.1).
  2. Konzentration der Herkunftsnetze: Anteil des Musterbestands, der auf
     die groessten Netze entfaellt (Kap. 4.2.1).

Aufruf:
    python 16_abbildungen.py --gpu
"""
import argparse
import collections
import hashlib
import io
import json
import os
import subprocess
import sys

import numpy as np

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


def laden(name):
    with io.open(os.path.join(DATEN, name), encoding="utf-8") as fh:
        return [json.loads(z) for z in fh if z.strip()]


def ist_test(tid, anteil=0.3):
    h = hashlib.sha256(tid.encode("utf-8")).digest()
    return (int.from_bytes(h[:4], "big") % 10000) < anteil * 10000


def reihe(xs, ys, stelle=3):
    """Formt eine pgfplots-Koordinatenliste, umbrochen auf 72 Zeichen."""
    teile = [f"({x},{round(float(y), stelle)})" for x, y in zip(xs, ys)]
    zeilen, zeile = [], "        "
    for t in teile:
        if len(zeile) + len(t) + 1 > 72:
            zeilen.append(zeile)
            zeile = "        "
        zeile += t + " "
    zeilen.append(zeile.rstrip())
    return chr(10).join(zeilen)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    ap.add_argument("--gpu", action="store_true")
    ap.add_argument("--stichtag", default="2026-10-05 00:00:00+00")
    ap.add_argument("--kmax", type=int, default=50)
    args = ap.parse_args()

    import importlib.util
    spec = importlib.util.spec_from_file_location("m", "07_retrieval_messen.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    # ---- Abbildung 1: Trefferquote ueber den Rang --------------------
    korpus = laden("korpus.jsonl")
    korpus_text = [k["text"] for k in korpus]
    idx = {k["template_id"]: i for i, k in enumerate(korpus)}
    anfragen = [a for a in laden("anfragen.jsonl")
                if ist_test(a["template_id"]) and a["template_id"] in idx]
    texte = [a["pfad"] for a in anfragen]
    ziele = [idx[a["template_id"]] for a in anfragen]
    print(f"Testanfragen: {len(anfragen)}")

    modelle = [("lexikalisch", "tfidf-char"),
               ("allgemein", "intfloat/e5-base-v2"),
               ("angepasst", "daten/modelle/angepasst-e5-base-v2-e1-b32")]
    ks = list(range(1, args.kmax + 1))
    print()
    print("% ---- Abbildung: Trefferquote ueber den Rang ----")
    for name, modell in modelle:
        if modell.startswith("tfidf"):
            S = m.tfidf_aehnlichkeit(texte, korpus_text, "char")
        else:
            S = m.embedding_aehnlichkeit(modell, texte, korpus_text,
                                         args.gpu, 64)
        raenge = np.array([m.raenge_mit_gleichstand(S[i], z)
                           for i, z in enumerate(ziele)])
        werte = [float((raenge <= k).mean()) for k in ks]
        print(f"% {name}: R@1 {werte[0]:.3f}  R@10 {werte[9]:.3f}  "
              f"R@50 {werte[-1]:.3f}")
        print(reihe(ks, werte))
        print()

    # ---- Abbildung 2: Konzentration der Herkunftsnetze ---------------
    zeilen = psql(args.host, f"""
        SELECT host(quellnetz), count(DISTINCT pfad)
        FROM beobachtete_pfade
        WHERE event_time <= '{args.stichtag}'
        GROUP BY 1 ORDER BY 2 DESC;""")
    je_netz = sorted((int(z[1]) for z in zeilen if len(z) >= 2), reverse=True)
    gesamt_netze = len(je_netz)
    # Ein Muster kann aus mehreren Netzen kommen. Bezugsgroesse ist
    # deshalb die Summe der Muster je Netz, nicht die Zahl der
    # verschiedenen Muster.
    summe = float(sum(je_netz))
    kum = np.cumsum(je_netz) / summe
    anteil_netze = np.arange(1, gesamt_netze + 1) / gesamt_netze

    # Auf rund 60 Stuetzstellen ausduennen.
    schritt = max(1, gesamt_netze // 60)
    xs = [round(100.0 * anteil_netze[i], 2)
          for i in range(0, gesamt_netze, schritt)]
    ys = [round(100.0 * kum[i], 2) for i in range(0, gesamt_netze, schritt)]
    if xs[-1] < 100.0:
        xs.append(100.0)
        ys.append(100.0)

    print("% ---- Abbildung: Konzentration der Quellen ----")
    print(f"% Netze: {gesamt_netze}, Beitragsmasse: {int(summe)}")
    for marke in (1, 5, 10, 25, 50):
        i = max(0, int(gesamt_netze * marke / 100.0) - 1)
        print(f"% groesste {marke:>2} % der Netze: {100.0 * kum[i]:.1f} % "
              f"der Beitragsmasse")
    print(reihe(xs, ys, 2))


if __name__ == "__main__":
    main()
