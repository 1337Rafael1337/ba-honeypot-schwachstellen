#!/usr/bin/env python3
"""
Gleicht die probierten Schwachstellen mit dem KEV-Katalog der CISA ab
(Kap. 4.2.3).

Der Katalog fuehrt Schwachstellen mit belegter Ausnutzung in freier
Wildbahn und dient vielen Betreibern zur Priorisierung von
Aktualisierungen. Geprueft wird, wie weit er abdeckt, was gegen einen
einzelnen Host probiert wird, und umgekehrt, wie viel des Katalogs im
Verkehr auftaucht.

Ein Unterschied zwischen beiden Mengen misst den Abstand zwischen
Absuche und belegter Ausnutzung, nicht die Qualitaet des Katalogs: Die
Aufnahme in den KEV setzt einen Beleg fuer tatsaechliche Ausnutzung
voraus.

Aufruf:
    python 18_kev_abgleich.py [--kev daten/kev.json]

Die Katalogdatei wird bei Bedarf geladen von
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
import argparse
import collections
import io
import json
import os
import urllib.request

DATEN = "daten"
QUELLE = ("https://www.cisa.gov/sites/default/files/feeds/"
          "known_exploited_vulnerabilities.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev", default=os.path.join(DATEN, "kev.json"))
    ap.add_argument("--laden", action="store_true",
                    help="Katalog neu von der Quelle holen")
    args = ap.parse_args()

    if args.laden or not os.path.exists(args.kev):
        print("lade Katalog ...")
        with urllib.request.urlopen(QUELLE, timeout=60) as r:
            roh = r.read()
        with io.open(args.kev, "wb") as fh:
            fh.write(roh)

    kev = json.load(io.open(args.kev, encoding="utf-8"))
    kset = {v["cveID"].upper() for v in kev["vulnerabilities"]}
    print(f"KEV-Katalog        : {len(kset)} Eintraege, "
          f"Version {kev['catalogVersion']}")

    bw = [json.loads(z) for z in
          io.open(os.path.join(DATEN, "bodenwahrheit.jsonl"),
                  encoding="utf-8")]
    ereignisse = collections.Counter()
    for b in bw:
        t = b["template_id"].upper()
        if t.startswith("CVE-"):
            ereignisse[t] += b["events"]
    probiert = set(ereignisse)
    drin = probiert & kset
    ohne = probiert - kset

    ev_drin = sum(n for t, n in ereignisse.items() if t in drin)
    ev_ges = sum(ereignisse.values())

    print(f"probierte CVE      : {len(probiert)}")
    print(f"davon im Katalog   : {len(drin)} "
          f"({100.0 * len(drin) / max(1, len(probiert)):.1f} %)")
    print(f"nicht im Katalog   : {len(ohne)} "
          f"({100.0 * len(ohne) / max(1, len(probiert)):.1f} %)")
    print(f"Ereignisanteil     : {ev_drin} von {ev_ges} "
          f"({100.0 * ev_drin / max(1, ev_ges):.1f} %)")

    # Gegenrichtung: wie viel des Katalogs taucht im Verkehr auf
    print(f"Anteil des Katalogs, der im Verkehr auftaucht: "
          f"{100.0 * len(drin) / max(1, len(kset)):.1f} %")

    for titel, menge in (("im Katalog", drin), ("nicht im Katalog", ohne)):
        print()
        print(f"haeufigste {titel}:")
        for t, n in sorted(((t, ereignisse[t]) for t in menge),
                           key=lambda x: -x[1])[:5]:
            print(f"   {t:<20} {n:>5} Ereignisse")

    with io.open(os.path.join(DATEN, "kev_abgleich.json"), "w",
                 encoding="utf-8", newline="\n") as fh:
        json.dump({
            "katalogversion": kev["catalogVersion"],
            "katalog_eintraege": len(kset),
            "probierte_cve": len(probiert),
            "im_katalog": len(drin),
            "nicht_im_katalog": len(ohne),
            "ereignisse_im_katalog": ev_drin,
            "ereignisse_gesamt": ev_ges,
        }, fh, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
