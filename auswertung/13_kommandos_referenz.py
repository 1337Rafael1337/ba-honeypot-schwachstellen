#!/usr/bin/env python3
"""
Referenzwissen fuer Datenart 2 (Kommandos aus abgefangenen Sitzungen).

Nuclei deckt Webanfragen ab, aber keine Shell-Kommandos. Fuer diese
Datenart liefert Atomic Red Team dieselbe zweiseitige Struktur:

  Textseite   -> Technikname und Testbeschreibung   (die Suchanfrage)
  Musterseite -> die tatsaechlichen Kommandozeilen   (nur Bodenwahrheit)

Jeder Eintrag ist einer MITRE-ATT&CK-Technik zugeordnet, womit die
Zuordnung dieselbe Form bekommt wie bei den Pfaden: Ein beobachtetes
Kommando gehoert zu einer Technik, wenn deren Kommandozeile darauf
passt; gesucht wird ausschliesslich mit dem Beschreibungstext.

Zwei Eigenheiten dieser Quelle:

1. Die Kommandos enthalten Platzhalter der Form `#{name}`, die aus
   `input_arguments` mit Vorgabewerten aufgeloest werden.
2. Ein Eintrag enthaelt oft mehrzeilige Skripte. Fuer den Abgleich
   zaehlt die einzelne Zeile, weil Cowrie ebenfalls einzelne
   Kommandozeilen erfasst.

Aufruf:
    python 13_kommandos_referenz.py [--repo daten/atomic-red-team]
"""
import argparse
import collections
import io
import json
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML fehlt")

PLATZHALTER = re.compile(r"#\{([^}]+)\}")


def loese_platzhalter(text, argumente):
    """Setzt die Vorgabewerte aus input_arguments ein.

    Ohne diesen Schritt bestehen viele Kommandos aus Platzhaltern und
    passen auf nichts. Bleibt ein Platzhalter uebrig, wird er als
    Jokerzeichen behandelt.
    """
    def ersetze(m):
        name = m.group(1).strip()
        wert = (argumente or {}).get(name)
        if isinstance(wert, dict):
            vorgabe = wert.get("default")
            if vorgabe is not None:
                return str(vorgabe)
        return m.group(0)
    return PLATZHALTER.sub(ersetze, text)


def zeilen_aus_kommando(befehl):
    """Zerlegt ein mehrzeiliges Skript in einzelne Kommandozeilen."""
    raus = []
    for zeile in (befehl or "").splitlines():
        z = zeile.strip()
        if not z or z.startswith("#"):
            continue
        # Fortsetzungszeichen entfernen
        z = z.rstrip("\\").strip()
        if len(z) >= 4:
            raus.append(z)
    return raus


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="daten/atomic-red-team")
    ap.add_argument("--out", default="daten")
    args = ap.parse_args()

    wurzel = os.path.join(args.repo, "atomics")
    dateien = sorted(
        os.path.join(w, n)
        for w, _v, ns in os.walk(wurzel) for n in ns
        if re.match(r"^T\d+(\.\d+)?\.yaml$", n))
    print(f"Techniken gefunden: {len(dateien)}")

    techniken = []
    kommandos = []
    plattform = collections.Counter()
    fehler = collections.Counter()

    for pfad in dateien:
        try:
            d = yaml.safe_load(io.open(pfad, encoding="utf-8",
                                       errors="replace").read())
        except Exception as e:
            fehler[type(e).__name__] += 1
            continue
        if not isinstance(d, dict):
            continue
        tid = str(d.get("attack_technique") or "").strip()
        name = str(d.get("display_name") or "").strip()
        if not tid:
            continue

        beschreibungen = []
        eigene = set()
        for test in (d.get("atomic_tests") or []):
            if not isinstance(test, dict):
                continue
            tname = str(test.get("name") or "").strip()
            tbesch = str(test.get("description") or "").strip()
            if tname or tbesch:
                beschreibungen.append((tname + " " + tbesch).strip())
            for pf in (test.get("supported_platforms") or []):
                plattform[str(pf)] += 1
            ex = test.get("executor")
            if not isinstance(ex, dict):
                continue
            befehl = loese_platzhalter(str(ex.get("command") or ""),
                                       test.get("input_arguments"))
            for z in zeilen_aus_kommando(befehl):
                eigene.add((z, tuple(str(p) for p in
                                     (test.get("supported_platforms") or []))))

        text = " ".join([name] + beschreibungen).replace("\n", " ")
        text = re.sub(r"\s+", " ", text).strip()
        techniken.append({
            "template_id": tid,
            "name": name,
            "description": " ".join(beschreibungen)[:4000],
            "tags": [],
            "text": text,
            "datei": os.path.relpath(pfad, args.repo).replace("\\", "/"),
            "kommandos": len(eigene),
        })
        for z, pfs in sorted(eigene):
            kommandos.append({"template_id": tid, "kommando": z,
                              "plattformen": list(pfs),
                              "hat_platzhalter": bool(PLATZHALTER.search(z))})

    os.makedirs(args.out, exist_ok=True)
    for datei, daten in (("kommandos_techniken.jsonl", techniken),
                         ("kommandos_referenz.jsonl", kommandos)):
        with io.open(os.path.join(args.out, datei), "w",
                     encoding="utf-8", newline="\n") as fh:
            for x in daten:
                fh.write(json.dumps(x, ensure_ascii=False) + "\n")

    mit = sum(1 for t in techniken if t["kommandos"])
    print(f"Techniken gelesen   : {len(techniken)}")
    print(f"davon mit Kommandos : {mit}")
    print(f"Kommandozeilen      : {len(kommandos)}")
    print(f"eindeutige Zeilen   : "
          f"{len(set(k['kommando'] for k in kommandos))}")
    print("Plattformen         :", dict(plattform.most_common(6)))
    if fehler:
        print("Lesefehler          :", dict(fehler))

    v = collections.Counter(k["kommando"] for k in kommandos)
    vert = collections.Counter()
    for n in v.values():
        vert["1" if n == 1 else "2" if n == 2
             else "3-5" if n <= 5 else "ueber 5"] += 1
    print("Vielfachheit        :", dict(vert))


if __name__ == "__main__":
    main()
