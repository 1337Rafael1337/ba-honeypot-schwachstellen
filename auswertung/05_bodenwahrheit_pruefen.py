#!/usr/bin/env python3
"""
Gegenpruefung zu 04_bodenwahrheit.py: Liegt eine niedrige Trefferquote
am Referenzwissen oder daran, dass der Abgleich vorhandene Treffer
nicht findet?

  1. Pfade, fuer die erkennbar ein Template existieren muss
     (/.env, /.git/config, /wp-login.php ...): werden sie zugeordnet?
  2. Die haeufigsten Pfade ohne Zuordnung.
  3. Anfragen zum Model Context Protocol (MCP): gibt es Templates dafuer?
  4. Mehrdeutigkeit: wie oft passt ein Pfad auf mehrere Templates?

Aufruf:  python 05_bodenwahrheit_pruefen.py
"""
import collections
import io
import json
import subprocess
import sys

HOST = "ba-db-vps"
TAB = chr(9)


def psql(sql):
    befehl = (
        "set -a; . ~/ba-db/.env; set +a; "
        "docker exec -i -e PGPASSWORD=$POSTGRES_PASSWORD ba-postgres "
        "psql -U $POSTGRES_USER -d $POSTGRES_DB -tA -F'" + TAB + "' -f -"
    )
    p = subprocess.run(["ssh", HOST, befehl], input=sql.encode("utf-8"),
                       capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        sys.exit("Abfrage fehlgeschlagen")
    return [z.split(TAB) for z in p.stdout.decode("utf-8", "replace").splitlines()
            if z.strip()]


def main():
    treffer = [json.loads(z) for z in
               io.open("daten/bodenwahrheit.jsonl", encoding="utf-8")]
    zugeordnet = {t["pfad"] for t in treffer}

    print("=" * 66)
    print("1. Gegenprobe: Pfade, fuer die ein Template existieren sollte")
    print("=" * 66)
    kandidaten = ["/.env", "/.git/config", "/wp-login.php", "/phpinfo.php",
                  "/.aws/credentials", "/server-status", "/actuator/health",
                  "/.DS_Store", "/config.json", "/telescope/requests"]
    liste = ",".join("'" + k + "'" for k in kandidaten)
    vorhanden = {}
    for z in psql(f"""
        SELECT lower(muster), count(*), min(template_id)
        FROM nuclei_pattern WHERE lower(muster) IN ({liste})
        GROUP BY 1;"""):
        vorhanden[z[0]] = (int(z[1]), z[2])
    print(f"{'Pfad':<26}{'Template da?':<16}{'beobachtet?':<14}{'zugeordnet?'}")
    for k in kandidaten:
        tpl = vorhanden.get(k.lower())
        beob = psql(f"""
            WITH web AS (SELECT CASE WHEN source_module='Glutton'
                           THEN raw->>'path'
                           ELSE coalesce(raw->>'request_uri', raw->>'path') END AS p
                         FROM captured_events
                         WHERE source_module IN ('Glutton','Log4pot','H0neytr4p'))
            SELECT count(*) FROM web WHERE lower(p) = '{k.lower()}';""")
        n_beob = int(beob[0][0]) if beob else 0
        print(f"{k:<26}"
              f"{(tpl[1][:14] if tpl else 'NEIN'):<16}"
              f"{(str(n_beob) if n_beob else '-'):<14}"
              f"{'ja' if k in zugeordnet else ('NEIN' if n_beob else '-')}")

    print()
    print("=" * 66)
    print("2. Haeufigste Nichttreffer")
    print("=" * 66)
    alle = psql("""
        WITH web AS (
          SELECT CASE WHEN source_module='Glutton' THEN raw->>'path'
                      ELSE coalesce(raw->>'request_uri', raw->>'path') END AS p
          FROM captured_events
          WHERE source_module IN ('Glutton','Log4pot','H0neytr4p'))
        SELECT p, count(*) FROM web
        WHERE p IS NOT NULL AND p <> '' AND p NOT LIKE '/data/glutton%'
        GROUP BY p ORDER BY 2 DESC LIMIT 400;""")
    ohne = [(z[0], int(z[1])) for z in alle if z[0] not in zugeordnet]
    print(f"(von den 400 haeufigsten Pfaden sind {len(ohne)} ohne Treffer)")
    for p, n in ohne[:22]:
        print(f"  {n:>7}  {p[:66]}")

    print()
    print("=" * 66)
    print("3. Anfragen zum Model Context Protocol (MCP)")
    print("=" * 66)
    mcp = psql("""
        WITH web AS (
          SELECT CASE WHEN source_module='Glutton' THEN raw->>'path'
                      ELSE coalesce(raw->>'request_uri', raw->>'path') END AS p,
                 src_ip
          FROM captured_events
          WHERE source_module IN ('Glutton','Log4pot','H0neytr4p'))
        SELECT p, count(*), count(DISTINCT src_ip) FROM web
        WHERE p ILIKE '%mcp%' GROUP BY p ORDER BY 2 DESC;""")
    print(f"{'Pfad':<44}{'Events':>8}{'Quellen':>9}  Template")
    for z in mcp:
        p, n, q = z[0], z[1], z[2]
        t = [x for x in treffer if x["pfad"] == p]
        print(f"  {p[:42]:<42}{n:>8}{q:>9}  "
              f"{t[0]['template_id'][:24] if t else 'KEINES'}")
    hat = psql("""SELECT count(*) FROM nuclei_pattern
                  WHERE muster ILIKE '%mcp%' AND diskriminierend;""")
    print(f"\nMuster mit 'mcp' im Referenzbestand: {hat[0][0]}")

    print()
    print("=" * 66)
    print("4. Mehrdeutigkeit und Verteilung")
    print("=" * 66)
    mehr = collections.Counter(t["vielfachheit"] for t in treffer)
    print("Pfade je Trefferzahl:", dict(sorted(mehr.items())))
    art = collections.Counter(t["art"] for t in treffer)
    print("Zuordnungsart       :", dict(art))
    tpl = collections.Counter(t["template_id"] for t in treffer)
    print(f"verschiedene Templates getroffen: {len(tpl)}")
    print("haeufigste Templates:")
    for tid, n in tpl.most_common(8):
        ev = sum(t["events"] for t in treffer if t["template_id"] == tid)
        print(f"  {n:>4} Pfade, {ev:>7} Events  {tid[:50]}")


if __name__ == "__main__":
    main()
