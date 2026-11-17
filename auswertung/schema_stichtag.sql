-- Stichtag des ausgewerteten Datenbestands.
--
-- Erhebungszeitraum: 05.09.2026, 15:47 UTC, bis 05.10.2026, 00:00 UTC.
-- Die Erhebung lief ueber den Beginn der Bearbeitungszeit (01.10.2026)
-- hinaus; ausgewertet wurde ausschliesslich innerhalb der
-- Bearbeitungszeit. Der Schnitt liegt um Mitternacht, damit nur
-- vollstaendige Betriebstage eingehen. Ereignisse vom 05.10. bis zum
-- Ende der Uebertragung gegen Mittag bleiben in der Datenbank, gehen aber
-- in keine Auswertung ein.
--
-- Der Zeitpunkt steht nur hier. Alle Basissichten lesen ihn, alle
-- abgeleiteten Sichten und Skripte uebernehmen ihn damit.

DROP VIEW IF EXISTS auswertungsstichtag CASCADE;

CREATE VIEW auswertungsstichtag AS
    SELECT TIMESTAMPTZ '2026-10-05 00:00:00+00' AS bis;

COMMENT ON VIEW auswertungsstichtag IS
    'Ende des ausgewerteten Erhebungszeitraums (die Bearbeitungszeit '
    'begann am 01.10.2026). Von allen Basissichten gelesen.';
