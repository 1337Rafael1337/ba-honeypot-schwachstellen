#!/usr/bin/env python3
"""
Gegenpruefung zu 01_nuclei_parsen.py: prueft die Ausgabe inhaltlich.

  1. Wie viele Templates mit http-Block liefern kein Muster? Diese
     Templates fehlen in der Ground Truth.
  2. Haben die gewonnenen Muster die Form von Anfragepfaden?
  3. Stimmen Stichproben mit der jeweiligen YAML-Datei ueberein?
  4. Wie vollstaendig ist die Textseite (Beschreibung, Tags, CVE)?

Aufruf:  python 02_parser_pruefen.py
"""
import collections
import io
import json
import os
import random
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML fehlt")

DATEN = "daten"
REPO = "daten/nuclei-templates"


def laden(name):
    with io.open(os.path.join(DATEN, name), encoding="utf-8") as fh:
        return [json.loads(z) for z in fh if z.strip()]


def main():
    tpl = laden("templates.jsonl")
    mus = laden("muster.jsonl")
    nach_id = {t["template_id"]: t for t in tpl}
    muster_je_tpl = collections.Counter(m["template_id"] for m in mus)

    print("=" * 66)
    print("1. Verlustpruefung: http-Block vorhanden, aber kein Muster")
    print("=" * 66)
    http_tpl = [t for t in tpl if "http" in t["protokolle"]
                or "requests" in t["protokolle"]]
    ohne = [t for t in http_tpl if muster_je_tpl.get(t["template_id"], 0) == 0]
    print(f"Templates mit http-Block : {len(http_tpl)}")
    print(f"davon ohne Muster        : {len(ohne)}"
          f"  ({100.0 * len(ohne) / max(1, len(http_tpl)):.1f} %)")

    if ohne:
        print("\nStichprobe der Verlustfaelle (was steht im http-Block?):")
        grund = collections.Counter()
        for t in ohne:
            pfad = os.path.join(REPO, t["datei"])
            try:
                d = yaml.safe_load(io.open(pfad, encoding="utf-8",
                                           errors="replace").read())
            except Exception:
                grund["YAML nicht lesbar"] += 1
                continue
            bloecke = d.get("http") or d.get("requests") or []
            schluessel = set()
            for b in bloecke:
                if isinstance(b, dict):
                    schluessel |= set(b.keys())
            if not bloecke:
                grund["http-Block leer"] += 1
            elif "path" not in schluessel and "raw" not in schluessel:
                grund["weder path noch raw: " +
                      ",".join(sorted(schluessel & {"payloads", "method",
                                                    "body", "headers",
                                                    "attack", "fuzzing"}))] += 1
            else:
                grund["path/raw vorhanden, aber nichts gewonnen"] += 1
        for g, n in grund.most_common(8):
            print(f"   {n:>5}  {g}")

    print()
    print("=" * 66)
    print("2. Formpruefung der Muster")
    print("=" * 66)
    mit_platz = sum(1 for m in mus if m["hat_platzhalter"])
    print(f"Muster gesamt            : {len(mus)}")
    print(f"davon mit Platzhalter    : {mit_platz}"
          f"  ({100.0 * mit_platz / max(1, len(mus)):.1f} %)")
    beginnt_slash = sum(1 for m in mus if m["muster"].startswith("/"))
    print(f"beginnt mit /            : {beginnt_slash}  (Soll: alle)")
    nur_slash = sum(1 for m in mus if m["muster"] == "/")
    print(f"nur '/'                  : {nur_slash}")
    laengen = sorted(len(m["muster"]) for m in mus)
    print(f"Laenge Median / P95 / max: {laengen[len(laengen)//2]} / "
          f"{laengen[int(len(laengen)*0.95)]} / {laengen[-1]}")
    meth = collections.Counter(m["methode"] for m in mus)
    print("Methoden                 :", dict(meth.most_common(6)))

    print("\n10 zufaellige Muster:")
    for m in random.Random(42).sample(mus, 10):
        print(f"   {m['methode']:<7} {m['muster'][:74]}")

    print()
    print("=" * 66)
    print("3. Stichprobe gegen die Quelldatei")
    print("=" * 66)
    stichprobe = random.Random(7).sample(
        [t for t in tpl if muster_je_tpl.get(t["template_id"], 0) > 0], 5)
    for t in stichprobe:
        eigene = sorted({m["muster"] for m in mus
                         if m["template_id"] == t["template_id"]})
        print(f"\n{t['template_id']}  ({t['datei']})")
        print(f"   Name      : {t['name'][:70]}")
        print(f"   geparst   : {len(eigene)} Muster")
        for e in eigene[:4]:
            print(f"      {e[:70]}")
        roh = io.open(os.path.join(REPO, t["datei"]), encoding="utf-8",
                      errors="replace").read()
        zeilen = [z.strip() for z in roh.splitlines()
                  if re.search(r'(\{\{BaseURL\}\}|HTTP/1\.[01])', z)]
        print(f"   in Datei  : {len(zeilen)} einschlaegige Zeilen")
        for z in zeilen[:4]:
            print(f"      {z[:70]}")

    print()
    print("=" * 66)
    print("4. Textseite")
    print("=" * 66)
    ohne_desc = sum(1 for t in tpl if not t["description"])
    ohne_tags = sum(1 for t in tpl if not t["tags"])
    mit_cve = sum(1 for t in tpl if t["cve_id"])
    print(f"ohne description         : {ohne_desc}"
          f"  ({100.0 * ohne_desc / len(tpl):.1f} %)")
    print(f"ohne tags                : {ohne_tags}")
    print(f"mit CVE-Kennung          : {mit_cve}"
          f"  ({100.0 * mit_cve / len(tpl):.1f} %)")
    sev = collections.Counter(t["severity"] for t in tpl)
    print("Schweregrade             :", dict(sev.most_common()))
    alle_tags = collections.Counter(tag for t in tpl for tag in t["tags"])
    print("haeufigste Tags          :", dict(alle_tags.most_common(10)))


if __name__ == "__main__":
    main()
