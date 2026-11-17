#!/usr/bin/env python3
"""
Domaenenanpassung des Embedding-Modells ohne manuelle Labels (Kap. 3.5).

Die Trainingspaare stammen aus den Templates selbst: Das Pfadmuster ist
die Anfrage, der Beschreibungstext das gesuchte Dokument. Anders als bei
GPL (Wang et al., 2022) sind dafuer weder ein Generierungsmodell fuer
Pseudo-Anfragen noch ein Cross-Encoder als Lehrermodell noetig.

Trainiert wird ausschliesslich auf Templates der Trainingsmenge (siehe
06_retrieval_daten.py); die Testmenge bleibt ungesehen.

Aufruf:
    python 08_anpassen.py --basis intfloat/e5-base-v2 --epochen 1
    python 08_anpassen.py --basis ... --epochen 3 --batch 32

Das Ergebnis liegt unter daten/modelle/<name>/ und ist danach mit
07_retrieval_messen.py messbar.
"""
import argparse
import io
import json
import os
import random
import time

DATEN = "daten"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--basis", default="intfloat/e5-base-v2")
    ap.add_argument("--epochen", type=int, default=1)
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--name", default=None)
    ap.add_argument("--max-laenge", type=int, default=256)
    ap.add_argument("--paare", default="paare.jsonl",
                    help="Datei mit den Trainingspaaren in daten/")
    ap.add_argument("--bf16", action="store_true", default=True)
    args = ap.parse_args()

    from sentence_transformers import (SentenceTransformer, InputExample,
                                       losses)
    from torch.utils.data import DataLoader
    import torch

    if not torch.cuda.is_available():
        print("WARNUNG: keine GPU sichtbar, das dauert sehr lange.")
    else:
        print(f"GPU: {torch.cuda.get_device_name(0)}")

    paare = [json.loads(z) for z in
             io.open(os.path.join(DATEN, args.paare), encoding="utf-8")]
    print(f"Trainingspaare: {len(paare)}")

    ist_e5 = "e5" in args.basis.lower()
    beispiele = []
    for p in paare:
        anfrage = p["muster"]
        dokument = p["text"]
        if ist_e5:
            anfrage = "query: " + anfrage
            dokument = "passage: " + dokument
        beispiele.append(InputExample(texts=[anfrage, dokument]))

    random.Random(42).shuffle(beispiele)

    modell = SentenceTransformer(args.basis, device="cuda"
                                 if torch.cuda.is_available() else "cpu")
    # Begrenzte Sequenzlaenge: Die Texte sind kurz, und mit der
    # Voreinstellung 512 reicht der Grafikspeicher (12 GB) bei einer
    # Batchgroesse von 64 nicht aus.
    modell.max_seq_length = args.max_laenge
    laengen = [len(b.texts[0]) + len(b.texts[1]) for b in beispiele[:2000]]
    print(f"Zeichen je Paar (Stichprobe): Median "
          f"{sorted(laengen)[len(laengen)//2]}, max {max(laengen)}")
    lader = DataLoader(beispiele, shuffle=True, batch_size=args.batch,
                       drop_last=True)
    # MultipleNegativesRankingLoss: Die uebrigen Paare eines Batches
    # dienen als Negativbeispiele (vgl. Gao et al., 2021). Eigens
    # gewonnene harte Negativbeispiele werden nicht verwendet, da sie bei
    # Herkunft aus der Ausgangsdomaene schaden koennen (Yuksel et al., 2025).
    verlust = losses.MultipleNegativesRankingLoss(modell)

    kennung = os.path.splitext(args.paare)[0].replace("paare", "").strip("_-")
    name = args.name or (
        "angepasst-" + args.basis.split("/")[-1] +
        (f"-{kennung}" if kennung else "") +
        f"-e{args.epochen}-b{args.batch}")
    ziel = os.path.join(DATEN, "modelle", name)
    os.makedirs(os.path.dirname(ziel), exist_ok=True)

    schritte = len(lader) * args.epochen
    print(f"Basis    : {args.basis}")
    print(f"Epochen  : {args.epochen}   Kleingruppe: {args.batch}")
    print(f"Schritte : {schritte}   max_seq_length: {modell.max_seq_length}")
    print(f"Ziel     : {ziel}")
    print()

    t0 = time.time()
    modell.fit(
        train_objectives=[(lader, verlust)],
        epochs=args.epochen,
        warmup_steps=int(0.1 * schritte),
        optimizer_params={"lr": args.lr},
        use_amp=True,
        show_progress_bar=True,
        output_path=ziel,
    )
    dauer = time.time() - t0
    if torch.cuda.is_available():
        print(f"Spitzenbelegung GPU: {torch.cuda.max_memory_allocated()/1e9:.1f} GB")
    print(f"\nFertig in {dauer/60:.1f} Minuten.")

    with io.open(os.path.join(DATEN, "trainingslaeufe.jsonl"), "a",
                 encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({
            "name": name, "basis": args.basis, "epochen": args.epochen,
            "batch": args.batch, "lr": args.lr, "paare": len(paare),
            "schritte": schritte, "minuten": round(dauer / 60, 1),
            "zeit": time.strftime("%Y-%m-%d %H:%M:%S"),
        }, ensure_ascii=False) + "\n")
    print(f"Messen mit:  python 07_retrieval_messen.py --modelle {ziel} --gpu")


if __name__ == "__main__":
    main()
