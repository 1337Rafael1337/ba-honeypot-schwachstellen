#!/usr/bin/env python3
"""
Empfaenger fuer die Glutton-Nutzlastdateien (erzwungener SSH-Befehl,
siehe run_payload_receiver.sh).

Eingabeformat je Zeile: base64(JSON) mit den Feldern
  sha256, size_bytes, mtime (ISO 8601), content_b64

Wie beim Ereignis-Empfaenger wird ausschliesslich parametrisiert
geschrieben und je Zeile ein SAVEPOINT gesetzt. Zusaetzlich:

1. Integritaetspruefung: Der SHA-256 wird ueber die empfangenen Bytes
   neu berechnet und mit dem mitgesendeten Wert verglichen. Abweichende
   Dateien werden verworfen und gezaehlt.

2. Ablage als BYTEA: Die Nutzlasten sind ueberwiegend binaer und
   enthalten NUL-Bytes. `content` haelt die Originalbytes, `content_text`
   eine lesbare Fassung mit der Ersatzmarkierung <NUL>.
"""
import sys
import os
import json
import base64
import hashlib
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

inserted = 0
duplicate = 0
failed = 0
hash_mismatch = 0

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        doc = json.loads(base64.b64decode(line).decode("utf-8"))
        content = base64.b64decode(doc["content_b64"])
    except Exception as e:
        print(f"SKIP (decode error): {e}", file=sys.stderr)
        failed += 1
        continue

    sha = doc.get("sha256", "")
    tatsaechlich = hashlib.sha256(content).hexdigest()
    if tatsaechlich != sha:
        print(
            f"FAIL (Pruefsumme weicht ab): gemeldet={sha} "
            f"berechnet={tatsaechlich} groesse={len(content)}",
            file=sys.stderr,
        )
        hash_mismatch += 1
        failed += 1
        continue

    content_text = content.decode("utf-8", errors="replace").replace("\x00", "<NUL>")

    cur.execute("SAVEPOINT row_sp")
    try:
        cur.execute(
            """
            INSERT INTO glutton_payloads
                (sha256, size_bytes, content, content_text, file_mtime)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (sha256) DO NOTHING
            """,
            (
                sha,
                len(content),
                psycopg2.Binary(content),
                content_text,
                doc.get("mtime"),
            ),
        )
        if cur.rowcount:
            inserted += 1
        else:
            duplicate += 1
        cur.execute("RELEASE SAVEPOINT row_sp")
    except Exception as e:
        cur.execute("ROLLBACK TO SAVEPOINT row_sp")
        print(f"FAIL (sha256={sha}): {e}", file=sys.stderr)
        failed += 1

conn.commit()
cur.execute("SELECT count(*), coalesce(sum(size_bytes), 0) FROM glutton_payloads")
gesamt, bytes_gesamt = cur.fetchone()
cur.close()
conn.close()
print(
    f"OK inserted={inserted} duplicate={duplicate} failed={failed} "
    f"pruefsumme_abweichend={hash_mismatch} bestand={gesamt} "
    f"bytes={bytes_gesamt}"
)
