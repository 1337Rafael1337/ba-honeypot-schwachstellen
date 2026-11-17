-- Sicht beobachtete_pfade: einzige Definition eines beobachteten
-- HTTP-Anfragepfades (Datenart 1, Kap. 3.3).
--
-- Log4pot legt in `request_uri` die vollstaendige Anfragezeile ab
-- (`GET /.env HTTP/1.1`), Glutton dagegen nur den Pfad. Die Sicht loest
-- die Anfragezeile in Methode und Pfad auf, damit derselbe Pfad aus
-- beiden Sensoren nicht als zwei verschiedene Muster zaehlt. Alle
-- Auswertungen lesen aus dieser Sicht.

DROP VIEW IF EXISTS beobachtete_pfade CASCADE;

CREATE VIEW beobachtete_pfade AS
WITH roh AS (
    SELECT
        e.id,
        e.event_time,
        e.src_ip,
        e.source_module,
        -- Glutton fuehrt den Anfragepfad in `path`; Log4pot und
        -- H0neytr4p in `request_uri`.
        CASE WHEN e.source_module = 'Glutton' THEN e.raw->>'path'
             ELSE coalesce(e.raw->>'request_uri', e.raw->>'path') END AS feld,
        e.raw->>'method' AS methode_feld
    FROM captured_events e
    -- Nur Module, deren Feld einen HTTP-Anfragepfad traegt. Cowrie,
    -- Dionaea und die uebrigen fuehren dort den Pfad ihrer eigenen
    -- Logdatei; NGINX erfasst nur den eigenen Administrationszugang.
    WHERE e.source_module IN ('Glutton', 'Log4pot', 'H0neytr4p')
)
SELECT
    id,
    event_time,
    src_ip,
    network(set_masklen(src_ip::cidr, 24)) AS quellnetz,
    source_module,
    -- Anfragezeile -> Methode, sonst das Methodenfeld
    CASE WHEN feld ~ '^[A-Z]+ .* HTTP/'
         THEN substring(feld from '^([A-Z]+) ')
         ELSE upper(coalesce(methode_feld, 'GET')) END AS methode,
    -- Anfragezeile -> Pfad, sonst das Feld unveraendert
    CASE WHEN feld ~ '^[A-Z]+ .* HTTP/'
         THEN substring(feld from '^[A-Z]+ (.*) HTTP/')
         ELSE feld END AS pfad
FROM roh
WHERE feld IS NOT NULL
  AND feld <> ''
  -- Gluttons eigene Logzeilen, kein Angriffsverkehr.
  AND feld NOT LIKE '/data/glutton%'
  -- Stichtag der Auswertung, siehe schema_stichtag.sql.
  AND event_time < (SELECT bis FROM auswertungsstichtag);

COMMENT ON VIEW beobachtete_pfade IS
    'Verbindliche Definition des beobachteten HTTP-Anfragepfades. '
    'Loest Log4pots vollstaendige Anfragezeile in Methode und Pfad auf.';
