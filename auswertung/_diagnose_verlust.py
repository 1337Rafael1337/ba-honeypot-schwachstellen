#!/usr/bin/env python3
"""Diagnose zu 01_nuclei_parsen.py: Warum liefern Templates mit http-Block
kein Pfadmuster?"""
import collections
import io
import json
import os
import sys
import yaml

REPO = "daten/nuclei-templates"
tpl = [json.loads(z) for z in io.open("daten/templates.jsonl", encoding="utf-8")]
mus = [json.loads(z) for z in io.open("daten/muster.jsonl", encoding="utf-8")]
hat = collections.Counter(m["template_id"] for m in mus)

ohne = [t for t in tpl
        if ("http" in t["protokolle"] or "requests" in t["protokolle"])
        and hat.get(t["template_id"], 0) == 0]

beispiele = collections.Counter()
roh_beispiele = collections.defaultdict(list)

for t in ohne:
    try:
        d = yaml.safe_load(io.open(os.path.join(REPO, t["datei"]),
                                   encoding="utf-8", errors="replace").read())
    except Exception:
        continue
    for b in (d.get("http") or d.get("requests") or []):
        if not isinstance(b, dict):
            continue
        for roh in (b.get("path") or []):
            s = str(roh).strip()
            schl = s if len(s) < 30 else s[:30] + "..."
            beispiele["path: " + schl] += 1
            if len(roh_beispiele["path"]) < 6:
                roh_beispiele["path"].append((t["template_id"], s))
        for anfrage in (b.get("raw") or []):
            erste = str(anfrage).strip().splitlines()
            erste = erste[0] if erste else ""
            schl = erste if len(erste) < 40 else erste[:40] + "..."
            beispiele["raw:  " + schl] += 1
            if len(roh_beispiele["raw"]) < 6:
                roh_beispiele["raw"].append((t["template_id"], erste))

print("Haeufigste Ausdruecke in den Verlustfaellen:")
for k, n in beispiele.most_common(15):
    print(f"  {n:>5}  {k}")

print("\nRohbeispiele path:")
for tid, s in roh_beispiele["path"]:
    print(f"  {tid:<34} {s[:70]}")
print("\nRohbeispiele raw:")
for tid, s in roh_beispiele["raw"]:
    print(f"  {tid:<34} {s[:70]}")
