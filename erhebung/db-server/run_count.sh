#!/bin/bash
# Erzwungener SSH-Befehl fuer den taeglichen Vollstaendigkeitsabgleich:
# liefert die Ereignisse je Modul bis zu einem Stichtag (eine Stunde vor
# jetzt, wegen der Sync-Verzoegerung von 15 Minuten), die Plattenbelegung
# dieses Servers und den Bestand der Nutzlastdateien.
#
# Eingaben werden vollstaendig verworfen: Der aufrufende Sensor gilt als
# angreifbar, von dort darf nichts in eine SQL-Abfrage gelangen.
cat > /dev/null

# Stichtag einmal hier bestimmen und an den Sensor melden, damit beide
# Seiten denselben Zeitraum zaehlen. Die Richtung ist so gewaehlt, dass
# kein Wert vom Sensor in diese Abfrage einfliesst.
STICHTAG=$(docker exec ba-postgres psql -U ba_thesis -d bachelorarbeit -t -A \
  -c "SELECT to_char((now() - interval '1 hour') AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"');" \
  | tr -dc '0-9TZ:-')
echo "__STICHTAG__|${STICHTAG}"

docker exec ba-postgres psql -U ba_thesis -d bachelorarbeit -t -A -F'|' \
  -c "SELECT source_module, count(*) FROM captured_events WHERE event_time < '${STICHTAG}' GROUP BY source_module ORDER BY source_module;"

# Plattenbelegung. Format: __DISK__|<belegt_prozent>|<frei_MB>|<db_MB>
DISK_PCT=$(df --output=pcent / | tail -1 | tr -dc '0-9')
DISK_FREE_MB=$(df -m --output=avail / | tail -1 | tr -dc '0-9')
DB_MB=$(docker exec ba-postgres psql -U ba_thesis -d bachelorarbeit -t -A \
  -c "SELECT round(pg_database_size(current_database())/1024.0/1024.0);" | tr -dc '0-9')
echo "__DISK__|${DISK_PCT}|${DISK_FREE_MB}|${DB_MB}"

# Bestand der Nutzlastdateien in glutton_payloads (eigener
# Uebertragungsweg). Format: __PAYLOADS__|<anzahl>|<bytes>
PL=$(docker exec ba-postgres psql -U ba_thesis -d bachelorarbeit -t -A -F"|" \
  -c "SELECT count(*), coalesce(sum(size_bytes),0) FROM glutton_payloads;")
echo "__PAYLOADS__|${PL}"
