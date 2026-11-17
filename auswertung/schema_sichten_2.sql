-- Sichten der Datenarten 2 bis 4 (Kap. 3.3). Wie beobachtete_pfade
-- (schema_sichten.sql) sind sie die einzige Definition der jeweiligen
-- Datenart; alle Auswertungen lesen aus ihnen.

-- ---------------------------------------------------------------
-- Datenart 2: Kommandos aus abgefangenen Sitzungen
-- ---------------------------------------------------------------
DROP VIEW IF EXISTS beobachtete_kommandos CASCADE;

CREATE VIEW beobachtete_kommandos AS
SELECT
    id,
    event_time,
    src_ip,
    network(set_masklen(src_ip::cidr, 24)) AS quellnetz,
    source_module,
    raw->>'session' AS sitzung,
    btrim(raw->>'input') AS kommando
FROM captured_events
WHERE raw->>'input' IS NOT NULL
  AND btrim(raw->>'input') <> ''
  -- Cowrie und Adbhoney fangen Sitzungen ab; beide fuehren das
  -- eingegebene Kommando in `input`.
  AND source_module IN ('Cowrie', 'Adbhoney')
  -- Vom Honeypot selbst erzeugt, nicht vom Angreifer gesendet: Cowries
  -- passwd-Nachbildung protokolliert diese Eingabeaufforderung als
  -- `cowrie.command.input`, mit demselben Zeitstempel wie das
  -- ausloesende passwd-Kommando (636 Ereignisse).
  AND btrim(raw->>'input') <> 'Enter new UNIX password:'
  -- Stichtag der Auswertung, siehe schema_stichtag.sql.
  AND event_time < (SELECT bis FROM auswertungsstichtag);

COMMENT ON VIEW beobachtete_kommandos IS
    'Einzelne Kommandos aus abgefangenen Sitzungen. Datenart 2. Ohne '
    'die vom Honeypot selbst erzeugte passwd-Eingabeaufforderung.';

-- Bekannte Eigenschaft dieser Sicht (Kap. 3.3, 4.4): Cowrie zerlegt
-- zusammengesetzte Befehlszeilen und protokolliert die Teile zusaetzlich
-- zur vollstaendigen Zeile; `ls -lh $(which ls)` erzeugt auch einen
-- Eintrag `which ls`. Diese Kommandos sind damit doppelt gezaehlt.
--
-- Eine verlaessliche maschinelle Bereinigung gibt es nicht: Ein Abgleich
-- ueber Teilzeichenketten erfasst auch echte Kommandos (`w` steckt in
-- `which ls`), ebenso ein Abgleich ueber gleiche Zeitstempel (Bots senden
-- mehrere echte Kommandos in einem Paket). Die engste pruefbare
-- Abgrenzung betrifft hoechstens 15,0 Prozent der Ereignisse und
-- 0,7 Prozent der eindeutigen Kommandos. Der Effekt ist in der Arbeit
-- ausgewiesen und nicht herausgerechnet.

-- ---------------------------------------------------------------
-- Datenart 3: Zugangsdatenpaare
-- ---------------------------------------------------------------
-- Leere Kennwoerter bleiben enthalten: Ein Anmeldeversuch mit leerem
-- Kennwort ist ein eigener Angriffsversuch, kein fehlender Wert. Nur
-- Zeilen ohne Benutzernamen fallen heraus.
DROP VIEW IF EXISTS beobachtete_zugangsdaten CASCADE;

CREATE VIEW beobachtete_zugangsdaten AS
SELECT
    id,
    event_time,
    src_ip,
    network(set_masklen(src_ip::cidr, 24)) AS quellnetz,
    source_module,
    raw->>'username' AS benutzer,
    coalesce(raw->>'password', '') AS kennwort,
    (raw->>'username') || ':' || coalesce(raw->>'password', '') AS paar
FROM captured_events
WHERE raw->>'username' IS NOT NULL
  AND source_module IN ('Cowrie', 'Dionaea')
  -- Stichtag der Auswertung, siehe schema_stichtag.sql.
  AND event_time < (SELECT bis FROM auswertungsstichtag);

COMMENT ON VIEW beobachtete_zugangsdaten IS
    'Paare aus Benutzername und Kennwort. Datenart 3. Leeres Kennwort '
    'ist ein gueltiger Wert, kein fehlender.';

-- ---------------------------------------------------------------
-- Datenart 4: Profile der angesteuerten Zielports
-- ---------------------------------------------------------------
-- Bewusst ohne Dienstnamen: Die Datenart ist rein numerisch. Ein
-- beigefuegter Dienstname wuerde ihr Text hinzufuegen, den die
-- beobachteten Daten nicht enthalten.
DROP VIEW IF EXISTS beobachtete_ports CASCADE;

CREATE VIEW beobachtete_ports AS
SELECT
    id,
    event_time,
    src_ip,
    network(set_masklen(src_ip::cidr, 24)) AS quellnetz,
    source_module,
    (raw->>'dest_port')::int AS zielport
FROM captured_events
WHERE raw->>'dest_port' ~ '^[0-9]{1,5}$'
  AND (raw->>'dest_port')::int BETWEEN 1 AND 65535
  -- Stichtag der Auswertung, siehe schema_stichtag.sql.
  AND event_time < (SELECT bis FROM auswertungsstichtag);

COMMENT ON VIEW beobachtete_ports IS
    'Angesteuerte Zielports. Datenart 4, rein numerisch und bewusst '
    'ohne beigefuegten Dienstnamen.';
