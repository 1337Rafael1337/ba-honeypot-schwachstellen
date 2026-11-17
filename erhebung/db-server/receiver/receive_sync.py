#!/usr/bin/env python3
"""
Empfaenger fuer den Ereignis-Sync (erzwungener SSH-Befehl, siehe
run_receiver.sh).

Liest je Zeile ein base64-kodiertes JSON-Dokument von stdin und schreibt
es in captured_events. Der Inhalt stammt vom Honeypot und ist damit
angreiferkontrolliert; er wird ausschliesslich ueber parametrisierte
Abfragen geschrieben, nie in SQL eingesetzt.

Je Zeile wird ein SAVEPOINT gesetzt, damit ein fehlerhafter Datensatz
nicht die uebrigen der Transaktion zuruecknimmt. Dubletten verhindert
der eindeutige Schluessel es_doc_id.
"""
import sys
import os
import json
import base64
import psycopg2

conn = psycopg2.connect(
    host="ba-postgres",
    port=5432,
    user=os.environ["POSTGRES_USER"],
    password=os.environ["POSTGRES_PASSWORD"],
    dbname=os.environ["POSTGRES_DB"],
)
conn.autocommit = False
cur = conn.cursor()

def strip_nul(obj):
    """
    PostgreSQL kann keine NUL-Bytes in text/jsonb speichern. Sie werden
    durch die sichtbare Markierung <NUL> ersetzt, statt den Datensatz zu
    verwerfen; die Ersetzung bleibt in den Daten erkennbar.
    """
    if isinstance(obj, str):
        return obj.replace("\x00", "<NUL>")
    if isinstance(obj, dict):
        return {strip_nul(k): strip_nul(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [strip_nul(v) for v in obj]
    return obj


inserted = 0
duplicate = 0
failed = 0
nul_cleaned = 0

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        doc = json.loads(base64.b64decode(line).decode("utf-8"))
    except Exception as e:
        print(f"SKIP (decode error): {e}", file=sys.stderr)
        failed += 1
        continue

    raw_json = json.dumps(doc.get("raw", {}))
    if "\\u0000" in raw_json:
        doc["raw"] = strip_nul(doc.get("raw", {}))
        raw_json = json.dumps(doc["raw"])
        nul_cleaned += 1

    cur.execute("SAVEPOINT row_sp")
    try:
        cur.execute(
            """
            INSERT INTO captured_events
                (source_module, event_time, src_ip, raw, es_doc_id)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (es_doc_id) DO NOTHING
            """,
            (
                doc.get("source_module", "unknown"),
                doc.get("event_time"),
                doc.get("src_ip") or None,
                raw_json,
                doc["es_doc_id"],
            ),
        )
        if cur.rowcount:
            inserted += 1
        else:
            duplicate += 1
        cur.execute("RELEASE SAVEPOINT row_sp")
    except Exception as e:
        cur.execute("ROLLBACK TO SAVEPOINT row_sp")
        print(
            f"FAIL (es_doc_id={doc.get('es_doc_id')}, "
            f"module={doc.get('source_module')}, src_ip={doc.get('src_ip')!r}): {e}",
            file=sys.stderr,
        )
        failed += 1

conn.commit()
cur.close()
conn.close()
print(
    f"OK inserted={inserted} duplicate={duplicate} failed={failed} "
    f"nul_bereinigt={nul_cleaned}"
)
