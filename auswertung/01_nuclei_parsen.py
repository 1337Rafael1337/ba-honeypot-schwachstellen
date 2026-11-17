#!/usr/bin/env python3
"""
Schritt 1 der Auswertungskette: liest die Nuclei-Templates und zerlegt
jedes Template in zwei Teile.

  Textseite   -> id, name, description, tags, severity   (die Suchanfrage)
  Musterseite -> die Anfragepfade aus dem http-Block      (nur Bodenwahrheit)

Gesucht wird ausschliesslich mit dem Beschreibungstext, bewertet
ausschliesslich ueber die Pfadmuster. Die Ground Truth ist dadurch nicht
zirkulaer und kommt ohne manuelle Labels aus (Kap. 3.4).

Nuclei kennt zwei Anfrageformen:

  http: - path: ["{{BaseURL}}/admin/login"]      -> direkt verwertbar
  http: - raw:  ["GET /{{path}} HTTP/1.1 ..."]   -> Platzhalter, die aus
                payloads: path: [...]               dem payloads-Block
                                                    aufgeloest werden

Die zweite Form betrifft rund ein Drittel der Templates, darunter die
meisten aelteren CVE-Eintraege; beide werden ausgewertet.

Aufruf:
    python 01_nuclei_parsen.py [--repo PFAD] [--out PFAD]

Erzeugt zwei JSONL-Dateien in daten/:
    templates.jsonl   eine Zeile je Template  (Textseite)
    muster.jsonl      eine Zeile je Pfadmuster (Musterseite)

Wiederholbar: ueberschreibt die Ausgabe vollstaendig, kein Zustand.
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
    sys.exit("PyYAML fehlt:  pip install pyyaml")

# Platzhalter, die Nuclei zur Laufzeit ersetzt. {{BaseURL}} und
# {{RootURL}} markieren den Beginn des Pfades und werden entfernt;
# alle uebrigen bleiben als Platzhalter stehen und machen das Muster
# zu einem Suchmuster statt zu einem festen Pfad.
BASIS_RE = re.compile(r"\{\{\s*(BaseURL|RootURL|Hostname|Host)\s*\}\}", re.I)
PLATZHALTER_RE = re.compile(r"\{\{[^}]*\}\}")
# Erste Zeile einer rohen HTTP-Anfrage: "GET /pfad HTTP/1.1"
RAW_START_RE = re.compile(r"^\s*([A-Z]{3,10})\s+(\S+)\s+HTTP/", re.M)

PROTOKOLLE = ("http", "requests", "network", "dns", "file", "ssl",
              "code", "javascript", "headless")


def text_liste(wert):
    """tags kommen mal als String, mal als Liste."""
    if wert is None:
        return []
    if isinstance(wert, str):
        return [t.strip() for t in wert.split(",") if t.strip()]
    if isinstance(wert, list):
        return [str(t).strip() for t in wert if str(t).strip()]
    return []


def pfad_normalisieren(roh):
    """Macht aus einem Nuclei-Pfadausdruck ein vergleichbares Muster.

    `{{BaseURL}}` ohne Zusatz bezeichnet die Wurzel und wird zu "/".
    2.055 Templates fragen nur die Wurzel ab und pruefen Kopfzeilen
    oder Inhalt. Sie bleiben im Bestand, werden aber ueber das Feld
    `diskriminierend` von der Ground Truth ausgeschlossen.
    """
    if not isinstance(roh, str):
        return None
    p = BASIS_RE.sub("", roh).strip()
    # Fragment abtrennen; fuer den Abgleich zaehlt nur der Pfad.
    p = p.split("#", 1)[0]
    if not p:
        return "/"
    if not p.startswith("/"):
        p = "/" + p
    # Mehrfache Schraegstriche zusammenfassen.
    p = re.sub(r"/{2,}", "/", p)
    return p


# Wortteile, die in beliebigem Verkehr vorkommen und ein Muster deshalb
# nicht unterscheidbar machen. Die Mindestlaenge von vier Zeichen
# verhindert, dass etwa `/{{str}}.json` auf jeden .json-Pfad passt.
GENERISCH = {
    "api", "www", "web", "app", "src", "lib", "bin", "tmp", "var", "usr",
    "html", "http", "https", "index", "main", "test", "data", "file",
    "files", "json", "xml", "php", "asp", "aspx", "jsp", "txt", "log",
    "logs", "css", "js", "img", "images", "static", "public", "assets",
    "admin", "user", "users", "login", "home", "page", "pages", "site",
}
WORT_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{3,}")


def ist_diskriminierend(muster):
    """Taugt das Muster als Bodenwahrheit?

    Nur, wenn nach Entfernen aller Platzhalter mindestens ein Wortteil
    mit vier oder mehr Zeichen uebrig bleibt, der nicht in jedem
    beliebigen Verkehr vorkommt. `/` und `/{{path}}` fallen damit
    heraus, `/wp-content/plugins/foo/readme.txt` bleibt drin.
    """
    ohne = PLATZHALTER_RE.sub(" ", muster or "")
    for wort in WORT_RE.findall(ohne):
        if wort.lower() not in GENERISCH:
            return True
    return False


def payload_varianten(block, pfad):
    """Loest {{name}}-Platzhalter aus dem payloads-Block auf.

    Nuclei setzt fuer jeden Wert der Nutzlastliste eine eigene Anfrage
    ab. Abgeglichen werden diese Einzelpfade, weil ein Muster mit
    unaufgeloestem {{path}} auf keinen beobachteten Pfad passt.
    """
    payloads = block.get("payloads")
    if not isinstance(payloads, dict):
        return [pfad]
    namen = PLATZHALTER_RE.findall(pfad)
    if not namen:
        return [pfad]
    ergebnis = [pfad]
    for roh_name in namen:
        schluessel = roh_name.strip("{} ").strip()
        werte = payloads.get(schluessel)
        if isinstance(werte, str):
            # Verweis auf eine Wortliste im Repo, nicht aufgeloest.
            continue
        if not isinstance(werte, list) or not werte:
            continue
        neu = []
        for bisher in ergebnis:
            for w in werte[:40]:      # hoechstens 40 Werte je Platzhalter
                if not isinstance(w, (str, int, float)):
                    continue
                neu.append(bisher.replace(roh_name, str(w)))
        if neu:
            ergebnis = neu
    return ergebnis


def pfade_aus_block(block):
    """Sammelt alle Anfragepfade eines einzelnen http-Blocks."""
    treffer = []
    methode_vorgabe = block.get("method")

    for roh in block.get("path") or []:
        p = pfad_normalisieren(roh)
        if p:
            for variante in payload_varianten(block, p):
                treffer.append((methode_vorgabe or "GET", variante))

    rohanfragen = block.get("raw") or []
    for anfrage in rohanfragen:
        if not isinstance(anfrage, str):
            continue
        m = RAW_START_RE.search(anfrage)
        if not m:
            continue
        p = pfad_normalisieren(m.group(2))
        if p:
            for variante in payload_varianten(block, p):
                treffer.append((m.group(1), variante))
    return treffer


def template_lesen(pfad, repo):
    try:
        rohtext = io.open(pfad, encoding="utf-8", errors="replace").read()
        daten = yaml.safe_load(rohtext)
    except Exception as fehler:
        return None, f"{type(fehler).__name__}"
    if not isinstance(daten, dict) or "info" not in daten:
        return None, "kein Template"

    info = daten.get("info") or {}
    if not isinstance(info, dict):
        return None, "info kein Abbild"

    klass = info.get("classification") or {}
    if not isinstance(klass, dict):
        klass = {}

    rel = os.path.relpath(pfad, repo).replace("\\", "/")
    protokolle = [k for k in PROTOKOLLE if k in daten]

    bloecke = daten.get("http") or daten.get("requests") or []
    muster = []
    if isinstance(bloecke, list):
        for b in bloecke:
            if isinstance(b, dict):
                muster.extend(pfade_aus_block(b))

    eintrag = {
        "template_id": str(daten.get("id") or "").strip(),
        "name": str(info.get("name") or "").strip(),
        "description": str(info.get("description") or "").strip(),
        "severity": str(info.get("severity") or "").strip().lower(),
        "tags": text_liste(info.get("tags")),
        "cve_id": str(klass.get("cve-id") or "").strip() or None,
        "cvss_score": klass.get("cvss-score"),
        "datei": rel,
        "protokolle": protokolle,
        "muster_zahl": len(muster),
    }
    return (eintrag, muster), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="daten/nuclei-templates")
    ap.add_argument("--out", default="daten")
    args = ap.parse_args()

    dateien = []
    for wurzel, verzeichnisse, namen in os.walk(args.repo):
        verzeichnisse[:] = [v for v in verzeichnisse if v != ".git"]
        for n in namen:
            if n.endswith((".yaml", ".yml")):
                dateien.append(os.path.join(wurzel, n))
    dateien.sort()
    print(f"Dateien gefunden: {len(dateien)}")

    os.makedirs(args.out, exist_ok=True)
    f_tpl = io.open(os.path.join(args.out, "templates.jsonl"), "w",
                    encoding="utf-8", newline="\n")
    f_mus = io.open(os.path.join(args.out, "muster.jsonl"), "w",
                    encoding="utf-8", newline="\n")

    fehler = collections.Counter()
    proto = collections.Counter()
    ohne_id = ohne_text = 0
    n_tpl = n_mus = n_disk = 0
    gesehen = set()
    doppelt = 0

    for pfad in dateien:
        ergebnis, grund = template_lesen(pfad, args.repo)
        if ergebnis is None:
            fehler[grund] += 1
            continue
        eintrag, muster = ergebnis
        if not eintrag["template_id"]:
            ohne_id += 1
            continue
        if eintrag["template_id"] in gesehen:
            doppelt += 1
            continue
        gesehen.add(eintrag["template_id"])
        if not (eintrag["name"] or eintrag["description"]):
            ohne_text += 1
        for p in eintrag["protokolle"]:
            proto[p] += 1

        f_tpl.write(json.dumps(eintrag, ensure_ascii=False) + "\n")
        n_tpl += 1

        einmalig = set()
        for methode, pfadmuster in muster:
            schluessel = (methode, pfadmuster)
            if schluessel in einmalig:
                continue
            einmalig.add(schluessel)
            disk = ist_diskriminierend(pfadmuster)
            f_mus.write(json.dumps({
                "template_id": eintrag["template_id"],
                "methode": methode,
                "muster": pfadmuster,
                "hat_platzhalter": bool(PLATZHALTER_RE.search(pfadmuster)),
                "diskriminierend": disk,
            }, ensure_ascii=False) + "\n")
            n_mus += 1
            if disk:
                n_disk += 1

    f_tpl.close()
    f_mus.close()

    print(f"Templates geschrieben : {n_tpl}")
    print(f"Pfadmuster geschrieben: {n_mus}")
    print(f"davon diskriminierend : {n_disk}"
          f"  ({100.0 * n_disk / max(1, n_mus):.1f} %)")
    print(f"ohne id               : {ohne_id}")
    print(f"ohne Text             : {ohne_text}")
    print(f"doppelte id           : {doppelt}")
    if fehler:
        print("uebersprungen         :", dict(fehler.most_common()))
    print("Protokollbloecke      :", dict(proto.most_common(9)))


if __name__ == "__main__":
    main()
