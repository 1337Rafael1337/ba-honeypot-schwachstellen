-- Rohdaten der Erhebung (Kap. 3.1).
--
-- Jedes Ereignis wird als vollstaendiges Elasticsearch-Dokument in JSONB
-- abgelegt, weil jedes Honeypot-Modul ein eigenes Schema liefert. Die
-- Auswertung greift ueber Sichten darauf zu (auswertung/schema_sichten*.sql).
--
-- Die Erweiterung vector wird fuer nuclei_embedding benoetigt
-- (auswertung/schema_nuclei.sql).

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS captured_events (
    id BIGSERIAL PRIMARY KEY,
    source_module TEXT NOT NULL,       -- 'Log4pot', 'Glutton', 'Dionaea', ...
    event_time TIMESTAMPTZ NOT NULL,
    src_ip INET,
    raw JSONB NOT NULL,                -- vollstaendiges Elasticsearch-Dokument
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    es_doc_id TEXT UNIQUE              -- Elasticsearch-_id, verhindert Dubletten beim Sync
);

CREATE INDEX IF NOT EXISTS idx_captured_events_module ON captured_events (source_module);
CREATE INDEX IF NOT EXISTS idx_captured_events_time ON captured_events (event_time);
CREATE INDEX IF NOT EXISTS idx_captured_events_raw_gin ON captured_events USING GIN (raw);
