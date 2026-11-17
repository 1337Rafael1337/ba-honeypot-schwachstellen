#!/usr/bin/env python3
"""
Prueft die Annahme, auf der der Einsatz von Embeddings beruht (Kap. 4.3.2).

Die Arbeit begruendet Embeddings damit, dass beobachteter Pfad und
Beschreibungstext oft kein gemeinsames Wort haben und eine lexikalische
Suche sie deshalb nicht verbinden kann. Die Testanfragen werden danach
aufgeteilt, ob Pfad und Beschreibungstext mindestens ein gemeinsames Wort
enthalten, und die Verfahren in beiden Gruppen verglichen. Stammt der
Vorsprung des angepassten Modells nur aus der Gruppe mit gemeinsamen
Woertern, beruht er auf Zeichenueberschneidung und nicht auf
Bedeutungsaehnlichkeit.

Zusaetzlich wird eine lexikalische Suche ueber Woerter gemessen, um die
Wahl der Zeichen-n-Gramme fuer die Baseline zu belegen.

Aufruf:
    python 17_wortueberschneidung.py --gpu
"""
import argparse
import hashlib
import io
import json
import os
import re

import numpy as np

DATEN = "daten"
WORT = re.compile(r"[a-z0-9]+")


def laden(name):
    with io.open(os.path.join(DATEN, name), encoding="utf-8") as fh:
        return [json.loads(z) for z in fh if z.strip()]


def ist_test(tid, anteil=0.3):
    h = hashlib.sha256(tid.encode("utf-8")).digest()
    return (int.from_bytes(h[:4], "big") % 10000) < anteil * 10000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gpu", action="store_true")
    ap.add_argument("--mindestlaenge", type=int, default=3,
                    help="kuerzere Token zaehlen nicht als Ueberschneidung")
    args = ap.parse_args()

    import importlib.util
    spec = importlib.util.spec_from_file_location("m", "07_retrieval_messen.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    korpus = laden("korpus.jsonl")
    kt = [k["text"] for k in korpus]
    idx = {k["template_id"]: i for i, k in enumerate(korpus)}

    anfragen = [a for a in laden("anfragen.jsonl")
                if ist_test(a["template_id"]) and a["template_id"] in idx]
    texte = [a["pfad"] for a in anfragen]
    ziele = [idx[a["template_id"]] for a in anfragen]

    # ---- Gruppenbildung ----------------------------------------------
    # Ein Token zaehlt nur ab drei Zeichen, damit Kuerzel wie "v1" oder
    # "id" keine Ueberschneidung vortaeuschen.
    mit, ohne = [], []
    for i, a in enumerate(anfragen):
        pt = {t for t in WORT.findall(a["pfad"].lower())
              if len(t) >= args.mindestlaenge}
        bt = {t for t in WORT.findall(korpus[ziele[i]]["text"].lower())
              if len(t) >= args.mindestlaenge}
        (mit if (pt & bt) else ohne).append(i)

    print(f"Testanfragen gesamt            : {len(anfragen)}")
    print(f"  mit gemeinsamem Wort         : {len(mit)} "
          f"({100.0*len(mit)/len(anfragen):.1f} %)")
    print(f"  ohne gemeinsames Wort        : {len(ohne)} "
          f"({100.0*len(ohne)/len(anfragen):.1f} %)")
    print()

    modelle = [("lexikalisch Zeichen", "tfidf-char"),
               ("lexikalisch Wort", "tfidf-wort"),
               ("allgemein", "intfloat/e5-base-v2"),
               ("angepasst", "daten/modelle/angepasst-e5-base-v2-e1-b32")]

    ergebnis = {}
    print(f"{'Verfahren':<22}{'MRR ges.':>10}{'mit Wort':>10}"
          f"{'ohne Wort':>11}{'R@10 ohne':>11}")
    print("-" * 64)
    for name, mod in modelle:
        if mod.startswith("tfidf"):
            S = m.tfidf_aehnlichkeit(texte, kt,
                                     "char" if "char" in mod else "wort")
        else:
            S = m.embedding_aehnlichkeit(mod, texte, kt, args.gpu, 64)
        rr = np.array([1.0 / m.raenge_mit_gleichstand(S[i], z)
                       for i, z in enumerate(ziele)])
        rg = np.array([m.raenge_mit_gleichstand(S[i], z)
                       for i, z in enumerate(ziele)])
        ergebnis[name] = (rr, rg)
        r10_ohne = float((rg[ohne] <= 10).mean()) if ohne else float("nan")
        print(f"{name:<22}{rr.mean():>10.4f}{rr[mit].mean():>10.4f}"
              f"{rr[ohne].mean():>11.4f}{r10_ohne:>11.3f}")

    # ---- Traegt die Anpassung auch ohne Wortueberschneidung? ---------
    print()
    print("=" * 64)
    print("PAARWEISE DIFFERENZ, getrennt nach Gruppe")
    print("=" * 64)
    zufall = np.random.default_rng(42)
    for a, b in [("angepasst", "allgemein"),
                 ("angepasst", "lexikalisch Zeichen"),
                 ("lexikalisch Zeichen", "lexikalisch Wort")]:
        ra, rb = ergebnis[a][0], ergebnis[b][0]
        for gruppe, ix in (("mit Wort", mit), ("ohne Wort", ohne)):
            if not ix:
                continue
            d = (ra - rb)[ix]
            n = len(ix)
            zieh = zufall.integers(0, n, size=(2000, n))
            vert = d[zieh].mean(axis=1)
            u, o = np.percentile(vert, [2.5, 97.5])
            sicher = "gesichert" if (u > 0 or o < 0) else "nicht gesichert"
            print(f"{a:<20} gegen {b:<20} {gruppe:<10} "
                  f"{d.mean():+.4f} [{u:+.4f}; {o:+.4f}] {sicher}")
        print()


if __name__ == "__main__":
    main()
