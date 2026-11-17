-- Referenzwissen aus den Nuclei-Templates (Kap. 3.4).
--
--   nuclei_template  Textseite: Beschreibung, mit der gesucht wird
--   nuclei_pattern   Musterseite: Pfadmuster, nur fuer die Ground Truth
--
-- Gesucht wird nur mit dem Text, bewertet nur ueber die Muster.
--
-- Wiederholbar: alle Tabellen mit CREATE IF NOT EXISTS, der Ladevorgang
-- (03_nuclei_laden.py) arbeitet mit ON CONFLICT.

-- ---------------------------------------------------------------
-- Textseite
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nuclei_template (
    template_id   TEXT PRIMARY KEY,
    name          TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    severity      TEXT,
    tags          TEXT[] NOT NULL DEFAULT '{}',
    cve_id        TEXT,
    cvss_score    REAL,
    datei         TEXT,              -- Pfad im Repo, fuer Nachvollzug
    protokolle    TEXT[] NOT NULL DEFAULT '{}',
    repo_commit   TEXT,              -- Stand des Repos beim Laden
    geladen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS nuclei_template_cve_idx
    ON nuclei_template (cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS nuclei_template_tags_idx
    ON nuclei_template USING gin (tags);

-- ---------------------------------------------------------------
-- Musterseite
-- ---------------------------------------------------------------
-- `diskriminierend` kennzeichnet Muster, die nicht auf beliebigen
-- Verkehr passen. Viele Templates fragen nur die Wurzel ("/") ab; als
-- Ground Truth wuerden sie jeder Wurzelanfrage tausende Templates
-- zuordnen.
CREATE TABLE IF NOT EXISTS nuclei_pattern (
    id               BIGSERIAL PRIMARY KEY,
    template_id      TEXT NOT NULL REFERENCES nuclei_template(template_id)
                     ON DELETE CASCADE,
    methode          TEXT NOT NULL DEFAULT 'GET',
    muster           TEXT NOT NULL,
    hat_platzhalter  BOOLEAN NOT NULL DEFAULT false,
    diskriminierend  BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (template_id, methode, muster)
);
CREATE INDEX IF NOT EXISTS nuclei_pattern_tpl_idx
    ON nuclei_pattern (template_id);
CREATE INDEX IF NOT EXISTS nuclei_pattern_disk_idx
    ON nuclei_pattern (diskriminierend) WHERE diskriminierend;
-- Fuer den Abgleich beobachteter Pfade gegen die Muster.
CREATE INDEX IF NOT EXISTS nuclei_pattern_muster_idx
    ON nuclei_pattern (muster text_pattern_ops);

-- ---------------------------------------------------------------
-- Embeddings, je Modell getrennt
-- ---------------------------------------------------------------
-- Eigene Tabelle mit `modell` im Schluessel, damit Vektoren mehrerer
-- Modelle (allgemein und angepasst) nebeneinander liegen koennen.
-- 768 Dimensionen passen zu e5-base, bge-base und gte-base.
CREATE TABLE IF NOT EXISTS nuclei_embedding (
    template_id  TEXT NOT NULL REFERENCES nuclei_template(template_id)
                 ON DELETE CASCADE,
    modell       TEXT NOT NULL,
    quelle       TEXT NOT NULL DEFAULT 'text',  -- welcher Text eingebettet wurde
    vektor       vector(768) NOT NULL,
    erzeugt_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (template_id, modell, quelle)
);

-- ---------------------------------------------------------------
-- Ladeprotokoll
-- ---------------------------------------------------------------
-- Haelt fest, welcher Repo-Stand wann geladen wurde. Die Templates
-- aendern sich laufend; so bleibt nachvollziehbar, gegen welchen Bestand
-- gemessen wurde.
CREATE TABLE IF NOT EXISTS nuclei_ladelauf (
    id            BIGSERIAL PRIMARY KEY,
    repo_commit   TEXT NOT NULL,
    repo_datum    DATE,
    templates     INTEGER NOT NULL,
    muster        INTEGER NOT NULL,
    diskriminierend INTEGER NOT NULL,
    geladen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    bemerkung     TEXT
);
