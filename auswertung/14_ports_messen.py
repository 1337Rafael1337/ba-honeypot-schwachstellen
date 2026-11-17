#!/usr/bin/env python3
"""
Datenart 4 (Profile der angesteuerten Zielports).

Diese Datenart ist der Endpunkt der Skala: Sie enthaelt keinen Text. Eine
Portnummer traegt keine Bedeutung, an der ein Sprachmodell ansetzen
koennte (Kap. 4.6).

Aufbau wie bei den anderen Datenarten:

  Anfrage = die beobachtete Portnummer als Zeichenkette, etwa "3306"
  Korpus  = die Dienstbeschreibungen der IANA-Registrierung
  Ziel    = der Eintrag, der zu dieser Portnummer gehoert

Die Ground Truth ist hier vollstaendig, weil die IANA-Zuordnung von Port
zu Dienst feststeht. Ein schwaches Ergebnis kann daher nicht an der
Bewertungsgrundlage liegen.

Als Vergleichswert wird der Erwartungswert bei zufaelliger Reihenfolge
mitgerechnet.

Aufruf:
    python 14_ports_messen.py [--gpu]
"""
import argparse
import collections
import csv
import io
import json
import os
import subprocess
import sys
import time

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    ap.add_argument("--gpu", action="store_true")
    ap.add_argument("--iana", default=os.path.join(DATEN, "iana-ports.csv"))
    args = ap.parse_args()

    import importlib.util
    spec = importlib.util.spec_from_file_location("m", "07_retrieval_messen.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    # ---- Korpus: eine Zeile je Port, Beschreibungen zusammengefasst ---
    je_port = collections.defaultdict(list)
    with io.open(args.iana, encoding="utf-8", errors="replace") as fh:
        for r in csv.DictReader(fh):
            p = (r.get("Port Number") or "").strip()
            if not p.isdigit():
                continue
            teile = [t for t in ((r.get("Service Name") or "").strip(),
                                 (r.get("Description") or "").strip()) if t]
            if teile:
                je_port[int(p)].append(" ".join(teile))
    korpus = []
    for port in sorted(je_port):
        texte = []
        for t in je_port[port]:
            if t not in texte:
                texte.append(t)
        korpus.append({"port": port, "text": " ".join(texte)[:400]})
    print(f"Korpus: {len(korpus)} Ports mit Dienstbeschreibung")

    idx = {k["port"]: i for i, k in enumerate(korpus)}
    korpus_text = [k["text"] for k in korpus]

    # ---- Anfragen: beobachtete Ports ---------------------------------
    beob = []
    for z in psql(args.host, """
        SELECT zielport, count(*), count(DISTINCT quellnetz)
        FROM beobachtete_ports GROUP BY 1 ORDER BY 2 DESC;"""):
        if len(z) >= 3 and z[0].isdigit():
            beob.append((int(z[0]), int(z[1]), int(z[2])))
    print(f"beobachtete Ports: {len(beob)}")

    anfragen = [(p, n, q) for p, n, q in beob if p in idx]
    print(f"davon in der IANA-Registrierung: {len(anfragen)} "
          f"({100.0 * len(anfragen) / max(1, len(beob)):.1f} %)")

    ports = [str(p) for p, _n, _q in anfragen]
    ziele = [idx[p] for p, _n, _q in anfragen]

    ergebnisse = []
    for modell in ["tfidf-char", "intfloat/e5-base-v2",
                   "daten/modelle/angepasst-e5-base-v2-e1-b32"]:
        t0 = time.time()
        if modell == "tfidf-char":
            S = m.tfidf_aehnlichkeit(ports, korpus_text, "char")
        else:
            S = m.embedding_aehnlichkeit(modell, ports, korpus_text,
                                         args.gpu, 64)
        w = m.bewerten(S, ziele)
        w["modell"] = modell
        w["sekunden"] = round(time.time() - t0, 1)
        ergebnisse.append(w)
        print(f"  {modell[:44]:<46} MRR {w['mrr']:.4f}  "
              f"R@10 {w['recall_10']:.3f}  R@50 {w['recall_50']:.3f}")

    # ---- Vergleichswert: zufaellige Reihenfolge ----------------------
    # Erwartungswert von MRR und Recall bei zufaelliger Reihenfolge
    # eines Korpus der Groesse N.
    N = len(korpus)
    zufall_mrr = float(np.mean([1.0 / r for r in range(1, N + 1)]))
    print()
    print(f"  {'Raten (Erwartungswert)':<46} MRR {zufall_mrr:.4f}  "
          f"R@10 {10.0 / N:.3f}  R@50 {50.0 / N:.3f}")

    with io.open(os.path.join(DATEN, "messungen.jsonl"), "a",
                 encoding="utf-8", newline="\n") as fh:
        for e in ergebnisse:
            e.update({"datenart": "ports", "korpus": N,
                      "vermerk": "IANA-Registrierung, Bodenwahrheit "
                                 "definitionsgemaess vollstaendig",
                      "zufall_mrr": round(zufall_mrr, 5),
                      "zeit": time.strftime("%Y-%m-%d %H:%M:%S")})
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")

    # ---- Abstand zum Zufallswert -------------------------------------
    # 23 der 6.262 Eintraege tragen ihre eigene Portnummer im
    # Beschreibungstext ("apc-2160 APC 2160"). Geprueft wird, ob diese
    # Zeichenkettentreffer den Abstand zum Zufallswert erklaeren.
    mit_nummer = sum(1 for k in korpus if str(k["port"]) in k["text"])
    erwartet = mit_nummer / max(1, len(anfragen))
    print()
    print("=" * 66)
    print(f"Ports mit eigener Nummer im Text : {mit_nummer} von {len(korpus)}")
    print(f"allein daraus erwartbarer MRR    : {erwartet:.4f}")
    bester = max(e["mrr"] for e in ergebnisse)
    print(f"tatsaechlich bester MRR          : {bester:.4f}")
    print()
    if bester <= (erwartet + zufall_mrr) * 1.5:
        print("BEFUND: Der Ueberschuss gegenueber dem Raten laesst sich")
        print("vollstaendig durch Zeichenkettenzufaelle erklaeren. Die")
        print("Datenart traegt keine Bedeutung, die ein Sprachmodell")
        print("nutzen koennte. Das ist die Grenze des Ansatzes.")
    else:
        print("BEFUND: Es bleibt ein Rest, der sich nicht allein durch")
        print("Zeichenkettenzufaelle erklaeren laesst. Nachpruefen.")
    print("=" * 66)


if __name__ == "__main__":
    main()
