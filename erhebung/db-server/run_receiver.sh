#!/bin/bash
exec docker run --rm -i --network ba-db_default --env-file /home/rafael/ba-db/.env ba-sync-receiver
