#!/usr/bin/env python3
"""
Rechnet den Verfahrensvergleich: Zu jeder Anfrage wird das passende
Template im Beschreibungstext gesucht. Gemessen werden MRR, Recall@10
und Recall@50.

Verglichen werden:

  tfidf-char   Zeichen-n-Gramme, 3 bis 5  (lexikalische Vergleichsmarke)
  tfidf-wort   Wortebene
  <modell>     beliebige sentence-transformers-Modelle

Gleichstaende: Gleich bewertete Dokumente erhalten den mittleren Rang
ihrer Gruppe, statt willkuerlich aufgeloest zu werden (Kap. 3.7, nach
Yang et al., 2026).

Aufruf:
    python 07_retrieval_messen.py --modelle tfidf-char,tfidf-wort
    python 07_retrieval_messen.py --modelle intfloat/e5-base-v2 --gpu
    python 07_retrieval_messen.py --alle-anfragen   (mit Leckage, nur Vergleich)

Die Ergebnisse werden an daten/messungen.jsonl angehaengt, eine Zeile je
Verfahren und Lauf.
"""
import argparse
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


def ist_test(template_id, anteil=0.3):
    h = hashlib.sha256(template_id.encode("utf-8")).digest()
    return (int.from_bytes(h[:4], "big") % 10000) < anteil * 10000


def raenge_mit_gleichstand(werte, ziel_index):
    """Rang des Ziels, Gleichstaende auf den mittleren Rang gelegt.

    werte: Aehnlichkeiten, absteigend zu werten.
    Rueckgabe: Rang ab 1.
    """
    ziel_wert = werte[ziel_index]
    groesser = int(np.sum(werte > ziel_wert))
    gleich = int(np.sum(werte == ziel_wert))
    # Mittlerer Rang der Gleichstandsgruppe
    return groesser + (gleich + 1) / 2.0


def bewerten(aehnlichkeit, ziel_indizes):
    """MRR, Recall@10, Recall@50 ueber alle Anfragen."""
    rr = []
    r10 = r50 = 0
    for i, ziel in enumerate(ziel_indizes):
        werte = aehnlichkeit[i]
        rang = raenge_mit_gleichstand(werte, ziel)
        rr.append(1.0 / rang)
        if rang <= 10:
            r10 += 1
        if rang <= 50:
            r50 += 1
    n = len(ziel_indizes)
    return {"mrr": float(np.mean(rr)),
            "recall_10": r10 / n,
            "recall_50": r50 / n,
            "anfragen": n}


def tfidf_aehnlichkeit(anfragen_text, korpus_text, art):
    from sklearn.feature_extraction.text import TfidfVectorizer
    if art == "char":
        vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                              min_df=2, max_features=300000,
                              sublinear_tf=True)
    else:
        vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                              min_df=1, sublinear_tf=True,
                              token_pattern=r"[A-Za-z0-9_.-]{2,}")
    X = vec.fit_transform(korpus_text)
    Q = vec.transform(anfragen_text)
    from sklearn.preprocessing import normalize
    X = normalize(X)
    Q = normalize(Q)
    return (Q @ X.T).toarray()


def embedding_aehnlichkeit(modellname, anfragen_text, korpus_text, gpu,
                           batch=64):
    from sentence_transformers import SentenceTransformer
    import torch
    geraet = "cuda" if (gpu and torch.cuda.is_available()) else "cpu"
    m = SentenceTransformer(modellname, device=geraet)
    # e5-Modelle erwarten die Praefixe "query:" und "passage:".
    if "e5" in modellname.lower():
        a_text = ["query: " + t for t in anfragen_text]
        k_text = ["passage: " + t for t in korpus_text]
    else:
        a_text, k_text = anfragen_text, korpus_text
    K = m.encode(k_text, batch_size=batch, convert_to_numpy=True,
                 normalize_embeddings=True, show_progress_bar=False)
    Q = m.encode(a_text, batch_size=batch, convert_to_numpy=True,
                 normalize_embeddings=True, show_progress_bar=False)
    return Q @ K.T


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--modelle", default="tfidf-char,tfidf-wort")
    ap.add_argument("--gpu", action="store_true")
    ap.add_argument("--alle-anfragen", action="store_true",
                    help="auch Anfragen auf Trainings-Templates auswerten "
                         "(mit Leckage, nur zum Vergleich)")
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--datenart", default="pfade",
                    choices=["pfade", "zugangsdaten", "kommandos",
                             "ports"],
                    help="welche Anfragedatei ausgewertet wird")
    args = ap.parse_args()

    korpus = laden("korpus.jsonl")
    if args.datenart == "pfade":
        anfragen = laden("anfragen.jsonl")
        feld = "pfad"
    else:
        anfragen = laden(f"anfragen_{args.datenart}.jsonl")
        feld = "anfrage"

    if not args.alle_anfragen:
        anfragen = [a for a in anfragen if ist_test(a["template_id"])]
        vermerk = "nur Test-Templates"
    else:
        vermerk = "alle Anfragen (Leckage)"

    korpus_text = [k["text"] for k in korpus]
    index_je_id = {k["template_id"]: i for i, k in enumerate(korpus)}
    anfragen = [a for a in anfragen if a["template_id"] in index_je_id]
    anfragen_text = [a[feld] for a in anfragen]
    ziele = [index_je_id[a["template_id"]] for a in anfragen]

    print(f"Datenart {args.datenart}: Korpus {len(korpus)}, "
          f"Anfragen {len(anfragen)} ({vermerk})")
    print()

    ergebnisse = []
    for modell in [m.strip() for m in args.modelle.split(",") if m.strip()]:
        t0 = time.time()
        print(f"--- {modell}")
        if modell == "tfidf-char":
            S = tfidf_aehnlichkeit(anfragen_text, korpus_text, "char")
        elif modell == "tfidf-wort":
            S = tfidf_aehnlichkeit(anfragen_text, korpus_text, "wort")
        else:
            S = embedding_aehnlichkeit(modell, anfragen_text, korpus_text,
                                       args.gpu, args.batch)
        werte = bewerten(S, ziele)
        werte.update({"modell": modell, "vermerk": vermerk,
                      "datenart": args.datenart,
                      "korpus": len(korpus),
                      "sekunden": round(time.time() - t0, 1),
                      "zeit": time.strftime("%Y-%m-%d %H:%M:%S")})
        ergebnisse.append(werte)
        print(f"    MRR {werte['mrr']:.4f}   R@10 {werte['recall_10']:.3f}   "
              f"R@50 {werte['recall_50']:.3f}   ({werte['sekunden']} s)")

    with io.open(os.path.join(DATEN, "messungen.jsonl"), "a",
                 encoding="utf-8", newline="\n") as fh:
        for e in ergebnisse:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")

    print()
    print("=" * 68)
    print(f"{'Modell':<34}{'MRR':>9}{'R@10':>9}{'R@50':>9}")
    print("=" * 68)
    for e in sorted(ergebnisse, key=lambda x: -x["mrr"]):
        print(f"{e['modell'][:33]:<34}{e['mrr']:>9.4f}"
              f"{e['recall_10']:>9.3f}{e['recall_50']:>9.3f}")


if __name__ == "__main__":
    main()
