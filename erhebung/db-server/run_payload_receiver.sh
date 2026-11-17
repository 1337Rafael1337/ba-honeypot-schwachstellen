#!/bin/bash
# Forced command: nimmt Glutton-Nutzlastdateien entgegen (siehe
# receive_payloads.py). Eigener Kanal und eigener Schluessel, damit
# der Event-Sync davon unberuehrt bleibt.
exec docker run --rm -i --network ba-db_default --env-file /home/rafael/ba-db/.env --entrypoint python3 ba-sync-receiver /app/receive_payloads.py
