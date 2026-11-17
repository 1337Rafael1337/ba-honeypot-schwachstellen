#!/usr/bin/env bash
# Korrigiert source_module in captured_events anhand des Logdateipfads.
#
# Hintergrund: T-Pots Feld "type" ist nicht verlaesslich. Cowries
# cowrie.client.fingerprint-Events ueberschreiben es mit dem
# SSH-Schluesselalgorithmus (ssh-rsa, kuenftig auch ssh-ed25519 usw.).
# Dieselbe Regel wie in sync_to_db.py: Pfad schlaegt type, ausser bei
# Glutton-HTTP-Dokumenten, deren "path" den Anfragepfad traegt.
#
# Idempotent: mehrfaches Ausfuehren aendert nach dem ersten Lauf nichts.
# Aufruf:  ./repair_module_names.sh          (nur anzeigen)
#          ./repair_module_names.sh --apply  (wirklich schreiben)
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

SQL_WHERE="raw->>'path' ~ '^/data/[a-z0-9]+/log/'
   AND source_module IS DISTINCT FROM (
     CASE substring(raw->>'path' from '^/data/([a-z0-9]+)/log/')
       WHEN 'cowrie' THEN 'Cowrie'          WHEN 'glutton' THEN 'Glutton'
       WHEN 'dionaea' THEN 'Dionaea'        WHEN 'log4pot' THEN 'Log4pot'
       WHEN 'h0neytr4p' THEN 'H0neytr4p'    WHEN 'adbhoney' THEN 'Adbhoney'
       WHEN 'redishoneypot' THEN 'Redishoneypot'
       WHEN 'nginx' THEN 'NGINX'            WHEN 'elasticpot' THEN 'ElasticPot'
     END)
   AND substring(raw->>'path' from '^/data/([a-z0-9]+)/log/') IN
       ('cowrie','glutton','dionaea','log4pot','h0neytr4p','adbhoney',
        'redishoneypot','nginx','elasticpot')"

echo "== Betroffene Zeilen vor dem Lauf =="
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" ba-postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
SELECT source_module AS falsch,
       substring(raw->>'path' from '^/data/([a-z0-9]+)/log/') AS laut_pfad,
       count(*)
FROM captured_events WHERE $SQL_WHERE GROUP BY 1,2 ORDER BY 3 DESC;"

if [ "$APPLY" -eq 1 ]; then
  echo "== Korrektur wird geschrieben =="
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" ba-postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
  UPDATE captured_events SET source_module =
     CASE substring(raw->>'path' from '^/data/([a-z0-9]+)/log/')
       WHEN 'cowrie' THEN 'Cowrie'          WHEN 'glutton' THEN 'Glutton'
       WHEN 'dionaea' THEN 'Dionaea'        WHEN 'log4pot' THEN 'Log4pot'
       WHEN 'h0neytr4p' THEN 'H0neytr4p'    WHEN 'adbhoney' THEN 'Adbhoney'
       WHEN 'redishoneypot' THEN 'Redishoneypot'
       WHEN 'nginx' THEN 'NGINX'            WHEN 'elasticpot' THEN 'ElasticPot'
     END
  WHERE $SQL_WHERE;"
  echo "== Kontrolle nach dem Lauf (muss leer sein) =="
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" ba-postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
  SELECT count(*) AS noch_offen FROM captured_events WHERE $SQL_WHERE;"
else
  echo
  echo "Trockenlauf. Zum Schreiben: $0 --apply"
fi
