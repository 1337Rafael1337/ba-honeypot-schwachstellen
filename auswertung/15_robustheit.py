#!/usr/bin/env python3
"""
Robustheitspruefung des Verfahrensvergleichs (Kap. 3.7, 4.3.1).

1. Mittelung ueber Quellnetze. Die Testmenge ist stark konzentriert,
   ein einzelnes /24-Netz stellt einen grossen Teil der Anfragen. Neben
   dem Mittel ueber alle Anfragen (mikro) wird deshalb zuerst je Netz
   und dann ueber die Netze gemittelt (makro); jeder Scanner zaehlt so
   einmal.

2. Bereiche. 95-Prozent-Bereiche per Bootstrap (Ziehen mit
   Zuruecklegen). Fuer das Makro-Mass wird ueber Netze gezogen, weil
   Anfragen desselben Scanners keine unabhaengigen Beobachtungen sind.

3. Paarweiser Vergleich. Alle Verfahren werden auf denselben Ziehungen
   bewertet, je Ziehung wird die Differenz gebildet. Ein Unterschied gilt
   als gesichert, wenn der Bereich der Differenz die Null nicht enthaelt.
   Ein Vergleich der Einzelbereiche waere zu streng, weil die Streuung
   aus der Auswahl der Anfragen beide Verfahren gleichermassen trifft.

Mit --netzregel haupt oder erst wird jede Anfrage nur einem Netz
zugeschlagen (Gegenprobe zur Mehrfachzaehlung, siehe
06_retrieval_daten.py).

Aufruf:
    python 15_robustheit.py --datenart pfade --gpu
"""
import argparse
import collections
import hashlib
import io
import json
import os
import time

import numpy as np

DATEN = "daten"


def laden(name):
    with io.open(os.path.join(DATEN, name), encoding="utf-8") as fh:
        return [json.loads(z) for z in fh if z.strip()]


def ist_test(tid, anteil=0.3):
    h = hashlib.sha256(tid.encode("utf-8")).digest()
    return (int.from_bytes(h[:4], "big") % 10000) < anteil * 10000


def bereich(werte):
    unten, oben = np.percentile(werte, [2.5, 97.5])
    return float(unten), float(oben)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datenart", default="pfade")
    ap.add_argument("--gpu", action="store_true")
    ap.add_argument("--ziehungen", type=int, default=2000)
    ap.add_argument("--saat", type=int, default=42)
    # "alle" zaehlt eine Anfrage in jedem Netz, aus dem sie kam; "haupt"
    # nur im Netz mit den meisten Ereignissen; "erst" nur im Netz, aus
    # dem sie zuerst kam.
    ap.add_argument("--netzregel", default="alle",
                    choices=["alle", "haupt", "erst"])
    ap.add_argument("--modelle", default=(
        "tfidf-char,intfloat/e5-base-v2,"
        "daten/modelle/angepasst-e5-base-v2-e1-b32"))
    args = ap.parse_args()

    import importlib.util
    spec = importlib.util.spec_from_file_location("m", "07_retrieval_messen.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    korpus = laden("korpus.jsonl")
    korpus_text = [k["text"] for k in korpus]
    idx = {k["template_id"]: i for i, k in enumerate(korpus)}

    if args.datenart == "pfade":
        anfragen = laden("anfragen.jsonl")
        feld = "pfad"
    else:
        anfragen = laden(f"anfragen_{args.datenart}.jsonl")
        feld = "anfrage"
    netzfeld = "quellnetze"

    anfragen = [a for a in anfragen
                if ist_test(a["template_id"]) and a["template_id"] in idx]
    texte = [a[feld] for a in anfragen]
    ziele = [idx[a["template_id"]] for a in anfragen]
    n = len(anfragen)
    print(f"Datenart {args.datenart}: {n} Testanfragen, "
          f"Korpus {len(korpus)}")

    # ---- Netzzugehoerigkeit je Anfrage --------------------------------
    # Unter der Regel "alle" zaehlt eine Anfrage aus mehreren Netzen in
    # jedem davon mit; die Netze sind dann nicht vollstaendig
    # unabhaengig. Die Regeln "haupt" und "erst" pruefen, ob das
    # Ergebnis davon abhaengt.
    netz_anfragen = collections.defaultdict(list)
    fehlend = 0
    for i, a in enumerate(anfragen):
        if args.netzregel == "alle":
            zugeordnet = a.get(netzfeld) or ["ohne"]
        else:
            feld_name = "hauptnetz" if args.netzregel == "haupt" else "erstnetz"
            eins = a.get(feld_name)
            if not eins:
                # Ohne eindeutige Zuordnung gilt das erste gelistete Netz,
                # damit die Gegenprobe dieselben Anfragen umfasst.
                gelistet = a.get(netzfeld) or []
                eins = gelistet[0] if gelistet else "ohne"
                fehlend += 1
            zugeordnet = [eins]
        for netz in zugeordnet:
            netz_anfragen[netz].append(i)
    if fehlend:
        print(f"  {fehlend} Anfragen ohne eindeutige Netzangabe, "
              f"ersatzweise erstes gelistetes Netz")
    netze = sorted(netz_anfragen)
    netz_index = [np.array(netz_anfragen[x]) for x in netze]
    groesstes = max(netz_index, key=len)
    print(f"Netzregel: {args.netzregel}")
    print(f"Quellnetze: {len(netze)}, groesstes Netz stellt "
          f"{len(groesstes)} Anfragen "
          f"({100.0 * len(groesstes) / max(1, n):.0f} %)")

    # ---- Ziehungen einmal fuer alle Verfahren festlegen ---------------
    # Gleiche Ziehungen fuer alle Verfahren sind Voraussetzung fuer den
    # paarweisen Vergleich.
    zufall = np.random.default_rng(args.saat)
    zieh_anfragen = zufall.integers(0, n, size=(args.ziehungen, n))
    zieh_netze = zufall.integers(0, len(netze),
                                 size=(args.ziehungen, len(netze)))

    rr_je_modell = {}
    tabelle = []

    for modell in [x.strip() for x in args.modelle.split(",") if x.strip()]:
        t0 = time.time()
        if modell.startswith("tfidf"):
            S = m.tfidf_aehnlichkeit(texte, korpus_text,
                                     "char" if "char" in modell else "wort")
        else:
            S = m.embedding_aehnlichkeit(modell, texte, korpus_text,
                                         args.gpu, 64)
        rr = np.array([1.0 / m.raenge_mit_gleichstand(S[i], z)
                       for i, z in enumerate(ziele)])
        rr_je_modell[modell] = rr

        mikro = float(rr.mean())
        je_netz = np.array([rr[ix].mean() for ix in netz_index])
        makro = float(je_netz.mean())

        mikro_vert = rr[zieh_anfragen].mean(axis=1)
        makro_vert = je_netz[zieh_netze].mean(axis=1)
        mu, mo = bereich(mikro_vert)
        au, ao = bereich(makro_vert)

        tabelle.append({
            "modell": modell,
            "mrr_mikro": round(mikro, 4),
            "mikro_ci": [round(mu, 4), round(mo, 4)],
            "mrr_makro": round(makro, 4),
            "makro_ci": [round(au, 4), round(ao, 4)],
            "anfragen": n, "netze": len(netze),
            "sekunden": round(time.time() - t0, 1),
        })
        print(f"  {modell[:42]:<44} mikro {mikro:.4f} [{mu:.3f}; {mo:.3f}]"
              f"   makro {makro:.4f} [{au:.3f}; {ao:.3f}]")

    print()
    print("=" * 78)
    print(f"{'Modell':<34}{'MRR mikro':>10}{'Bereich':>16}"
          f"{'MRR makro':>11}{'Bereich':>16}")
    print("=" * 78)
    for t in sorted(tabelle, key=lambda x: -x["mrr_makro"]):
        b1 = f"[{t['mikro_ci'][0]:.3f}; {t['mikro_ci'][1]:.3f}]"
        b2 = f"[{t['makro_ci'][0]:.3f}; {t['makro_ci'][1]:.3f}]"
        print(f"{t['modell'][-33:]:<34}{t['mrr_mikro']:>10.4f}{b1:>16}"
              f"{t['mrr_makro']:>11.4f}{b2:>16}")

    # ---- Paarweiser Vergleich -----------------------------------------
    print()
    print("=" * 78)
    print("PAARWEISER VERGLEICH (dieselben Anfragen, dieselben Ziehungen)")
    print("=" * 78)
    print("Verglichen wird die Differenz je Ziehung, nicht die Lage zweier")
    print("Einzelbereiche. Gesichert heisst: Der Bereich der Differenz")
    print("enthaelt die Null nicht.")
    print()

    namen = [t["modell"] for t in tabelle]
    vergleiche = []
    for i in range(len(namen)):
        for j in range(i + 1, len(namen)):
            a, b = namen[i], namen[j]
            ra, rb = rr_je_modell[a], rr_je_modell[b]
            na = np.array([ra[ix].mean() for ix in netz_index])
            nb = np.array([rb[ix].mean() for ix in netz_index])

            d_mikro = (ra - rb)[zieh_anfragen].mean(axis=1)
            d_makro = (na - nb)[zieh_netze].mean(axis=1)

            for mass, punkt, vert in (("mikro", ra.mean() - rb.mean(), d_mikro),
                                      ("makro", na.mean() - nb.mean(), d_makro)):
                u, o = bereich(vert)
                sicher = (u > 0) or (o < 0)
                anteil = float((vert > 0).mean())
                vergleiche.append({
                    "a": a, "b": b, "mass": mass,
                    "differenz": round(float(punkt), 4),
                    "ci": [round(u, 4), round(o, 4)],
                    "anteil_positiv": round(anteil, 4),
                    "gesichert": bool(sicher),
                })
                kurz_a, kurz_b = a[-22:], b[-22:]
                print(f"{kurz_a:>24} gegen {kurz_b:<24} {mass}")
                print(f"{'':>24}   Differenz {punkt:+.4f}  "
                      f"[{u:+.4f}; {o:+.4f}]  "
                      f"{'GESICHERT' if sicher else 'nicht gesichert'}"
                      f"  (in {100 * anteil:.1f} % der Ziehungen positiv)")
            print()

    # ---- Zusammenfassung ----------------------------------------------
    mikro_g = [v for v in vergleiche if v["mass"] == "mikro" and v["gesichert"]]
    makro_g = [v for v in vergleiche if v["mass"] == "makro" and v["gesichert"]]
    print("-" * 78)
    print(f"gesicherte Unterschiede: {len(mikro_g)} von "
          f"{len(vergleiche) // 2} (mikro), {len(makro_g)} von "
          f"{len(vergleiche) // 2} (makro)")
    if makro_g:
        print("Berichtet werden darf eine Rangfolge nur fuer die makro")
        print("gesicherten Paare. Alle uebrigen sind bei dieser")
        print("Stichprobengroesse nicht unterscheidbar.")
    else:
        print("Unter Makro-Mittelung ist kein Unterschied gesichert.")
        print("Es darf keine Rangfolge berichtet werden.")

    zeit = time.strftime("%Y-%m-%d %H:%M:%S")
    with io.open(os.path.join(DATEN, "robustheit.jsonl"), "a",
                 encoding="utf-8", newline="\n") as fh:
        for t in tabelle:
            t.update({"datenart": args.datenart, "zeit": zeit,
                      "art": "modell", "netzregel": args.netzregel,
                      "saat": args.saat})
            fh.write(json.dumps(t, ensure_ascii=False) + "\n")
        for v in vergleiche:
            v.update({"datenart": args.datenart, "zeit": zeit,
                      "art": "vergleich", "netzregel": args.netzregel,
                      "saat": args.saat})
            fh.write(json.dumps(v, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
