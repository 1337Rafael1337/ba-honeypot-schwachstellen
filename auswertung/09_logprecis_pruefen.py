#!/usr/bin/env python3
"""
Kommandos aus abgefangenen Sitzungen: Verdichtung und Probe mit den
Modellen aus LogPrecis (Boffa et al., 2024), das mit demselben Sensor
(Cowrie) arbeitet.

  1. Verdichtung: Sitzungen auf verschiedene Abfolgen und Kommandos auf
     verschiedene Kommandos (Kap. 4.4). Vergleichswert aus LogPrecis:
     400.000 Angriffe auf rund 3.000 Fingerabdruecke, etwa 133 zu 1
     (Kap. 5).
  2. Taktikzuordnung mit dem Modell SmartDataPolito/logprecis
     (Token-Klassifikation auf ATT&CK-Taktiken) fuer eine Stichprobe von
     400 Sitzungen. Reine Machbarkeitsprobe, in der Arbeit nicht
     berichtet.

Die Modellgewichte tragen auf Hugging Face keine Lizenzangabe; sie
werden hier nur zum Vergleich geladen.

Aufruf:
    python 09_logprecis_pruefen.py [--host ba-db-vps] [--grenze 2000]
"""
import argparse
import collections
import io
import json
import os
import subprocess
import sys
import time

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


# Quelle ist die Sicht beobachtete_kommandos: Sie beruecksichtigt den
# Stichtag und schliesst die vom Honeypot selbst erzeugte
# Eingabeaufforderung aus.
#
# Die Verdichtung wird ueber alle Sitzungen gerechnet (die Obergrenze
# liegt ueber dem Bestand). Die Reihenfolge nach md5(sitzung) ist
# pseudozufaellig; die Modellprobe nimmt daraus die ersten 400 Sitzungen.
# Eine Auswahl nach Laenge waere verzerrt, weil lange Sitzungen fast nie
# identisch sind.
SQL_SITZUNGEN = """
SELECT sitzung,
       string_agg(kommando, ' ; ' ORDER BY event_time) AS kommandos,
       count(*) AS schritte,
       min(host(src_ip)) AS quelle
FROM beobachtete_kommandos
WHERE source_module = 'Cowrie'
GROUP BY sitzung
ORDER BY md5(sitzung)
LIMIT %d;
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    ap.add_argument("--grenze", type=int, default=100000,
                    help="Obergrenze der geladenen Sitzungen. Die "
                         "Vorgabe liegt bewusst ueber dem Bestand, "
                         "damit die Verdichtung alle Sitzungen sieht.")
    ap.add_argument("--gpu", action="store_true", default=True)
    args = ap.parse_args()

    print("Sitzungen laden ...")
    zeilen = psql(args.host, SQL_SITZUNGEN % args.grenze)
    sitzungen = []
    for z in zeilen:
        if len(z) < 4:
            continue
        sitzungen.append({"sitzung": z[0], "kommandos": z[1],
                          "schritte": int(z[2]), "quelle": z[3]})
    print(f"  {len(sitzungen)} Sitzungen mit Kommandos")
    if not sitzungen:
        sys.exit("Keine Sitzungen gefunden.")

    laengen = sorted(s["schritte"] for s in sitzungen)
    print(f"  Schritte je Sitzung: Median {laengen[len(laengen)//2]}, "
          f"max {laengen[-1]}")

    # ---- Frage 3: Verdichtung ohne Modell ----------------------------
    print()
    print("=" * 62)
    print("Verdichtung der eigenen Sitzungen")
    print("=" * 62)
    roh = [s["kommandos"] for s in sitzungen]
    einmalig = set(roh)
    if len(roh) >= args.grenze:
        print("ACHTUNG: Die Obergrenze wurde erreicht. Die folgende "
              "Verdichtung gilt nur fuer die geladene Teilmenge.")
    print(f"Sitzungen              : {len(roh)}")
    print(f"verschiedene Abfolgen  : {len(einmalig)}")
    print(f"Verdichtung Sitzungen  : "
          f"{len(roh)/max(1,len(einmalig)):.2f} zu 1")
    # Zweite, davon verschiedene Verdichtung: einzelne Kommandos statt
    # ganzer Abfolgen. Die Querschnittstabelle der Arbeit berichtet
    # diese, nicht die der Sitzungen.
    schritte = sum(s["schritte"] for s in sitzungen)
    kommandos = set()
    for s in sitzungen:
        kommandos.update(x.strip() for x in s["kommandos"].split(" ; "))
    print(f"Kommandoereignisse     : {schritte}")
    print(f"verschiedene Kommandos : {len(kommandos)}")
    print(f"Verdichtung Kommandos  : "
          f"{schritte/max(1,len(kommandos)):.1f} zu 1")
    print("Vergleichsmarke LogPrecis: 133 zu 1 "
          "(400.000 Angriffe auf 3.000 Fingerabdruecke)")

    # ---- Fragen 1 und 2: Modelle ------------------------------------
    print()
    print("=" * 62)
    print("Modelle aus LogPrecis")
    print("=" * 62)
    try:
        import torch
        from transformers import (AutoTokenizer,
                                  AutoModelForTokenClassification)
    except ImportError as e:
        sys.exit(f"transformers/torch fehlen: {e}")

    geraet = "cuda" if (args.gpu and torch.cuda.is_available()) else "cpu"
    print(f"Geraet: {geraet}")

    name = "SmartDataPolito/logprecis"
    t0 = time.time()
    try:
        tok = AutoTokenizer.from_pretrained(name)
        mod = AutoModelForTokenClassification.from_pretrained(name).to(geraet)
        mod.eval()
    except Exception as e:
        sys.exit(f"Modell nicht ladbar: {type(e).__name__}: {e}")
    print(f"geladen in {time.time()-t0:.1f} s")
    etiketten = mod.config.id2label
    print(f"Etiketten ({len(etiketten)}): "
          f"{', '.join(str(v) for v in etiketten.values())}")

    print()
    print("Zuordnung auf den eigenen Sitzungen ...")
    zaehler = collections.Counter()
    je_sitzung = []
    with torch.no_grad():
        for i in range(0, min(len(sitzungen), 400), 16):
            gruppe = sitzungen[i:i + 16]
            texte = [g["kommandos"][:2000] for g in gruppe]
            ein = tok(texte, return_tensors="pt", truncation=True,
                      max_length=512, padding=True).to(geraet)
            aus = mod(**ein).logits.argmax(-1).cpu()
            for j, g in enumerate(gruppe):
                maske = ein["attention_mask"][j].cpu().bool()
                ids = aus[j][maske].tolist()
                taktiken = [etiketten[k] for k in ids]
                gefiltert = [t for t in taktiken
                             if str(t).upper() not in ("O", "LABEL_0")]
                zaehler.update(gefiltert)
                je_sitzung.append({
                    "sitzung": g["sitzung"], "quelle": g["quelle"],
                    "schritte": g["schritte"],
                    "taktiken": sorted(set(gefiltert)),
                })
    print(f"  {len(je_sitzung)} Sitzungen zugeordnet")
    print()
    print("Haeufigste Taktiken:")
    for t, n in zaehler.most_common(12):
        print(f"  {n:>7}  {t}")

    mehrfach = collections.Counter(len(s["taktiken"]) for s in je_sitzung)
    print()
    print("Taktiken je Sitzung:", dict(sorted(mehrfach.items())))

    os.makedirs(DATEN, exist_ok=True)
    with io.open(os.path.join(DATEN, "logprecis_probe.jsonl"), "w",
                 encoding="utf-8", newline="\n") as fh:
        for s in je_sitzung:
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"\ngeschrieben nach {DATEN}/logprecis_probe.jsonl")


if __name__ == "__main__":
    main()
