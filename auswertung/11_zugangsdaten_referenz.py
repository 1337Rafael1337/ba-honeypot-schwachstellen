#!/usr/bin/env python3
"""
Referenzwissen fuer Datenart 3 (Zugangsdatenpaare).

Dieselbe Konstruktion wie bei den Anfragepfaden, nur mit einem anderen
Teil der Nuclei-Templates: Die 307 Templates unter
`http/default-logins/` beschreiben Geraete und Anwendungen mit
Werkseinstellung und fuehren die zugehoerigen Zugangsdaten im
`payloads`-Block.

  Textseite   -> name, description, tags   (die Suchanfrage)
  Musterseite -> username/password-Paare   (nur Bodenwahrheit)

Damit gilt fuer diese Datenart dieselbe Regel wie fuer die Pfade:
Gesucht wird ausschliesslich mit dem Beschreibungstext, bewertet
ausschliesslich ueber die Paare.

Anders als ein Pfad ist ein Zugangsdatenpaar kein Text, sondern zwei
kurze Zeichenketten ohne Syntax; `root:root` sagt nichts darueber, welches
Geraet gemeint ist (Ergebnisse in Kap. 4.5).

Aufruf:
    python 11_zugangsdaten_referenz.py [--repo daten/nuclei-templates]
"""
import argparse
import collections
import io
import json
import os
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML fehlt")


def text_liste(wert):
    if wert is None:
        return []
    if isinstance(wert, str):
        return [t.strip() for t in wert.split(",") if t.strip()]
    if isinstance(wert, list):
        return [str(t).strip() for t in wert if str(t).strip()]
    return []


def werte(pl, *namen):
    """Liefert die erste vorhandene Nutzlastliste unter den Namen.

    Die Templates benennen die Listen uneinheitlich (`username`/`password`,
    `user`/`pass`, vereinzelt `aem_user`/`aem_pass`). Ohne die
    alternativen Namen fehlte rund ein Sechstel der Templates.
    """
    for n in namen:
        v = pl.get(n)
        if isinstance(v, list) and v:
            return [str(x) for x in v if isinstance(x, (str, int, float))]
        if isinstance(v, (str, int, float)):
            return [str(v)]
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="daten/nuclei-templates")
    ap.add_argument("--out", default="daten")
    args = ap.parse_args()

    wurzel = os.path.join(args.repo, "http", "default-logins")
    dateien = []
    for w, verz, namen in os.walk(wurzel):
        for n in namen:
            if n.endswith((".yaml", ".yml")):
                dateien.append(os.path.join(w, n))
    dateien.sort()
    print(f"Templates unter default-logins: {len(dateien)}")

    eintraege = []
    paare = []
    ohne_paare = collections.Counter()

    for pfad in dateien:
        try:
            d = yaml.safe_load(io.open(pfad, encoding="utf-8",
                                       errors="replace").read())
        except Exception:
            ohne_paare["YAML nicht lesbar"] += 1
            continue
        if not isinstance(d, dict) or "info" not in d:
            continue
        info = d.get("info") or {}
        tid = str(d.get("id") or "").strip()
        if not tid:
            continue

        gefunden = []
        for b in (d.get("http") or d.get("requests") or []):
            if not isinstance(b, dict):
                continue
            pl = b.get("payloads")
            if not isinstance(pl, dict):
                continue
            benutzer = werte(pl, "username", "user", "aem_user", "login")
            kennwoerter = werte(pl, "password", "pass", "aem_pass", "passwd")
            if not kennwoerter:
                continue
            if not benutzer:
                # Einige Templates pruefen nur das Kennwort (etwa bei
                # Geraeten mit festem Benutzernamen im Anfragetext).
                benutzer = [""]
            for u in benutzer[:20]:
                for p in kennwoerter[:20]:
                    gefunden.append((u, p))

        if not gefunden:
            ohne_paare["keine Nutzlast mit Kennwort"] += 1

        text = " ".join(x for x in [
            str(info.get("name") or "").strip(),
            str(info.get("description") or "").strip(),
            " ".join(text_liste(info.get("tags"))),
        ] if x).replace("\n", " ").strip()

        eintraege.append({
            "template_id": tid,
            "name": str(info.get("name") or "").strip(),
            "description": str(info.get("description") or "").strip(),
            "tags": text_liste(info.get("tags")),
            "text": text,
            "datei": os.path.relpath(pfad, args.repo).replace("\\", "/"),
            "paare": len(set(gefunden)),
        })
        for u, p in sorted(set(gefunden)):
            paare.append({"template_id": tid, "benutzer": u, "kennwort": p,
                          "paar": u + ":" + p})

    os.makedirs(args.out, exist_ok=True)
    for name, daten in (("zugangsdaten_templates.jsonl", eintraege),
                        ("zugangsdaten_paare.jsonl", paare)):
        with io.open(os.path.join(args.out, name), "w",
                     encoding="utf-8", newline="\n") as fh:
            for x in daten:
                fh.write(json.dumps(x, ensure_ascii=False) + "\n")

    mit = sum(1 for e in eintraege if e["paare"])
    print(f"Templates gelesen      : {len(eintraege)}")
    print(f"davon mit Zugangsdaten : {mit}"
          f"  ({100.0 * mit / max(1, len(eintraege)):.1f} %)")
    print(f"Paare gesamt           : {len(paare)}")
    print(f"eindeutige Paare       : {len(set(p['paar'] for p in paare))}")
    if ohne_paare:
        print("ohne Paare             :", dict(ohne_paare.most_common()))

    # Vielfachheit: wie viele Templates beanspruchen dasselbe Paar?
    v = collections.Counter(p["paar"] for p in paare)
    verteilung = collections.Counter()
    for n in v.values():
        verteilung["1" if n == 1 else "2" if n == 2
                   else "3-5" if n <= 5 else "ueber 5"] += 1
    print("Vielfachheit der Paare :", dict(verteilung))
    print("haeufigste Paare       :",
          [f"{k} ({n})" for k, n in v.most_common(5)])


if __name__ == "__main__":
    main()
