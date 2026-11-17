#!/usr/bin/env python3
"""
Laedt die von 01_nuclei_parsen.py erzeugten Templates und Muster in die
Datenbank.

Die Uebertragung laeuft ueber SSH und COPY: PostgreSQL ist auf dem
Datenserver nur lokal erreichbar, und COPY ist deutlich schneller als
einzelne INSERTs.

Idempotent: Die Daten gehen zuerst in temporaere Tabellen und werden
per INSERT ... ON CONFLICT uebernommen. Ein erneuter Lauf aendert nur
das Ladeprotokoll; ein neuerer Repo-Stand aktualisiert die Templates.

Aufruf:
    python 03_nuclei_laden.py [--host ba-db-vps] [--trocken]
"""
import argparse
import io
import json
import os
import subprocess
import sys

DATEN = "daten"
REPO = os.path.join(DATEN, "nuclei-templates")


def repo_stand():
    """Commit und Datum des Template-Repos. Beides wird im Ladeprotokoll
    festgehalten, damit der Referenzbestand nachvollziehbar bleibt."""
    def git(*args):
        return subprocess.run(["git", "-C", REPO] + list(args),
                              capture_output=True, text=True,
                              encoding="utf-8").stdout.strip()
    return git("rev-parse", "HEAD"), git("log", "-1", "--format=%cd",
                                         "--date=short")


def pg_array(werte):
    """Python-Liste -> Postgres-Array-Literal fuer COPY (Textformat)."""
    if not werte:
        return "{}"
    teile = []
    for w in werte:
        s = str(w).replace("\\", "\\\\").replace('"', '\\"')
        teile.append('"' + s + '"')
    return "{" + ",".join(teile) + "}"


import re as _re

# PostgreSQL-Textfelder koennen kein NUL-Byte aufnehmen, einzelne
# Nuclei-Beschreibungen enthalten aber Steuerzeichen (z. B. das Template
# zu CVE-2021-32030). Sie werden vor dem COPY entfernt und gezaehlt.
STEUERZEICHEN_RE = _re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

nul_bereinigt = 0


def copy_feld(wert):
    """Escaping fuer das COPY-Textformat, inklusive NUL-Bereinigung."""
    global nul_bereinigt
    if wert is None:
        return "\\N"
    s = str(wert)
    sauber = STEUERZEICHEN_RE.sub("", s)
    if sauber != s:
        nul_bereinigt += 1
    return (sauber.replace("\\", "\\\\")
                  .replace("\t", "\\t")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r"))


def zeilen_templates(commit):
    with io.open(os.path.join(DATEN, "templates.jsonl"), encoding="utf-8") as fh:
        for z in fh:
            if not z.strip():
                continue
            t = json.loads(z)
            cvss = t.get("cvss_score")
            try:
                cvss = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss = None
            yield "\t".join(copy_feld(x) for x in (
                t["template_id"], t["name"], t["description"],
                t.get("severity") or None, pg_array(t.get("tags")),
                t.get("cve_id"), cvss, t.get("datei"),
                pg_array(t.get("protokolle")), commit))


def zeilen_muster():
    with io.open(os.path.join(DATEN, "muster.jsonl"), encoding="utf-8") as fh:
        for z in fh:
            if not z.strip():
                continue
            m = json.loads(z)
            yield "\t".join(copy_feld(x) for x in (
                m["template_id"], m.get("methode") or "GET", m["muster"],
                "true" if m.get("hat_platzhalter") else "false",
                "true" if m.get("diskriminierend") else "false"))


SQL = """
BEGIN;

CREATE TEMP TABLE t_tpl (
    template_id TEXT, name TEXT, description TEXT, severity TEXT,
    tags TEXT[], cve_id TEXT, cvss_score REAL, datei TEXT,
    protokolle TEXT[], repo_commit TEXT
) ON COMMIT DROP;

CREATE TEMP TABLE t_mus (
    template_id TEXT, methode TEXT, muster TEXT,
    hat_platzhalter BOOLEAN, diskriminierend BOOLEAN
) ON COMMIT DROP;

\\copy t_tpl FROM 'TPL_DATEI' WITH (FORMAT text, NULL '\\N')
\\copy t_mus FROM 'MUS_DATEI' WITH (FORMAT text, NULL '\\N')

INSERT INTO nuclei_template AS z
    (template_id, name, description, severity, tags, cve_id,
     cvss_score, datei, protokolle, repo_commit)
SELECT template_id, name, description, severity, tags, cve_id,
       cvss_score, datei, protokolle, repo_commit
FROM t_tpl
ON CONFLICT (template_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    severity = EXCLUDED.severity,
    tags = EXCLUDED.tags,
    cve_id = EXCLUDED.cve_id,
    cvss_score = EXCLUDED.cvss_score,
    datei = EXCLUDED.datei,
    protokolle = EXCLUDED.protokolle,
    repo_commit = EXCLUDED.repo_commit,
    geladen_at = now()
WHERE z.repo_commit IS DISTINCT FROM EXCLUDED.repo_commit;

-- Muster, die es im neuen Stand nicht mehr gibt, verschwinden. Sonst
-- bliebe Bodenwahrheit stehen, die das Repo laengst zurueckgezogen hat.
DELETE FROM nuclei_pattern p
WHERE NOT EXISTS (
    SELECT 1 FROM t_mus m
    WHERE m.template_id = p.template_id
      AND m.methode = p.methode
      AND m.muster = p.muster);

INSERT INTO nuclei_pattern
    (template_id, methode, muster, hat_platzhalter, diskriminierend)
SELECT template_id, methode, muster, hat_platzhalter, diskriminierend
FROM t_mus
ON CONFLICT (template_id, methode, muster) DO UPDATE SET
    hat_platzhalter = EXCLUDED.hat_platzhalter,
    diskriminierend = EXCLUDED.diskriminierend;

INSERT INTO nuclei_ladelauf
    (repo_commit, repo_datum, templates, muster, diskriminierend, bemerkung)
SELECT 'COMMIT_KURZ', 'REPO_DATUM'::date,
       (SELECT count(*) FROM nuclei_template),
       (SELECT count(*) FROM nuclei_pattern),
       (SELECT count(*) FROM nuclei_pattern WHERE diskriminierend),
       'geladen durch 03_nuclei_laden.py';

COMMIT;

SELECT 'templates' AS was, count(*) FROM nuclei_template
UNION ALL SELECT 'muster', count(*) FROM nuclei_pattern
UNION ALL SELECT 'diskriminierend', count(*) FROM nuclei_pattern WHERE diskriminierend
UNION ALL SELECT 'verwaiste muster', count(*) FROM nuclei_pattern p
    WHERE NOT EXISTS (SELECT 1 FROM nuclei_template t WHERE t.template_id = p.template_id);
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="ba-db-vps")
    ap.add_argument("--trocken", action="store_true")
    args = ap.parse_args()

    commit, datum = repo_stand()
    if not commit:
        sys.exit("Repo-Stand nicht ermittelbar -- liegt daten/nuclei-templates?")
    print(f"Repo-Stand: {commit[:12]}  vom {datum}")

    tpl_pfad = os.path.join(DATEN, "_copy_templates.tsv")
    mus_pfad = os.path.join(DATEN, "_copy_muster.tsv")
    n_t = n_m = 0
    with io.open(tpl_pfad, "w", encoding="utf-8", newline="\n") as fh:
        for z in zeilen_templates(commit[:12]):
            fh.write(z + "\n")
            n_t += 1
    with io.open(mus_pfad, "w", encoding="utf-8", newline="\n") as fh:
        for z in zeilen_muster():
            fh.write(z + "\n")
            n_m += 1
    print(f"Zwischendateien: {n_t} Templates, {n_m} Muster")
    if nul_bereinigt:
        print(f"Steuerzeichen bereinigt in {nul_bereinigt} Feldern")

    if args.trocken:
        print("Trockenlauf -- nichts uebertragen.")
        return

    # Dateien auf den DB-VPS legen, dort psql mit \copy laufen lassen.
    ziel = "~/ba-db/_laden"
    subprocess.run(["ssh", args.host, f"mkdir -p {ziel}"], check=True)
    for lokal, name in ((tpl_pfad, "templates.tsv"), (mus_pfad, "muster.tsv")):
        with io.open(lokal, "rb") as fh:
            subprocess.run(["ssh", args.host, f"cat > {ziel}/{name}"],
                           stdin=fh, check=True)
    print("Dateien uebertragen.")

    sql = (SQL.replace("TPL_DATEI", f"{ziel}/templates.tsv".replace("~", "/home/rafael"))
              .replace("MUS_DATEI", f"{ziel}/muster.tsv".replace("~", "/home/rafael"))
              .replace("COMMIT_KURZ", commit[:12])
              .replace("REPO_DATUM", datum))

    # `docker cp` kopiert ein Verzeichnis in ein bereits vorhandenes Ziel
    # hinein, statt es zu ersetzen. Das Ziel im Container wird deshalb
    # vorher geloescht, damit psql immer die aktuellen Dateien liest.
    befehl = (
        "set -a; . ~/ba-db/.env; set +a; "
        "cat > /tmp/_laden.sql && "
        "docker exec ba-postgres rm -rf /tmp/_laden && "
        "docker cp /home/rafael/ba-db/_laden ba-postgres:/tmp/_laden >/dev/null && "
        "docker cp /tmp/_laden.sql ba-postgres:/tmp/_laden.sql && "
        "docker exec -e PGPASSWORD=$POSTGRES_PASSWORD ba-postgres "
        "psql -U $POSTGRES_USER -d $POSTGRES_DB -v ON_ERROR_STOP=1 -f /tmp/_laden.sql"
    )
    sql_im_container = sql.replace("/home/rafael/ba-db/_laden", "/tmp/_laden")
    ergebnis = subprocess.run(["ssh", args.host, befehl],
                              input=sql_im_container.encode("utf-8"),
                              capture_output=True)
    sys.stdout.write(ergebnis.stdout.decode("utf-8", "replace"))
    if ergebnis.returncode != 0:
        sys.stderr.write(ergebnis.stderr.decode("utf-8", "replace"))
        sys.exit("Laden fehlgeschlagen.")


if __name__ == "__main__":
    main()
