-- Vollstaendige Nutzlasten aus Glutton (Kap. 3.1).
--
-- Glutton schneidet jede TCP-Nutzlast bis 4096 Byte mit und legt sie als
-- Datei ab, benannt nach ihrem SHA-256. Im Ereignis selbst steht nur ein
-- gekuerzter Hexdump; die Dateien werden deshalb ueber einen eigenen
-- Kanal uebertragen (receiver/receive_payloads.py).
--
-- Die Verknuepfung zu Quelle und Zeitpunkt erfolgt ueber das Feld
-- payload_hash in captured_events.raw.

CREATE TABLE IF NOT EXISTS glutton_payloads (
    sha256       TEXT PRIMARY KEY,        -- zugleich Dateiname auf dem Honeypot
    size_bytes   INTEGER NOT NULL,
    content      BYTEA NOT NULL,          -- Originalbytes, binaersicher
    content_text TEXT,                    -- lesbare Fassung, NUL als <NUL>
    file_mtime   TIMESTAMPTZ,             -- Zeitpunkt der Ablage durch Glutton
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_glutton_payloads_mtime
    ON glutton_payloads (file_mtime);
CREATE INDEX IF NOT EXISTS idx_glutton_payloads_size
    ON glutton_payloads (size_bytes);

-- Verknuepfung von Nutzlast und Ereignis.
CREATE OR REPLACE VIEW payload_events AS
SELECT
    p.sha256,
    p.size_bytes,
    p.content_text,
    e.id           AS event_id,
    e.event_time,
    e.src_ip,
    e.raw ->> 'dest_port' AS dest_port,
    e.raw ->> 'handler'   AS handler
FROM glutton_payloads p
JOIN captured_events e
  ON e.raw ->> 'payload_hash' = p.sha256;
