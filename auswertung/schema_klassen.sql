-- Klassen beobachteter Anfragepfade und die Konzentration je Klasse
-- (Kap. 4.2.1).
--
-- Die Konzentration der Herkunftsnetze unterscheidet sich stark zwischen
-- den Zielklassen: Eine Klasse, deren Muster aus vielen Netzen kommen,
-- traegt eine andere Aussage als eine, deren Muster aus einer einzelnen
-- Absuchkampagne stammen.
--
-- Die Klassen sind bewusst grob. Sie benennen wiederkehrende Absuchziele
-- und teilen den Verkehr nicht vollstaendig ein; was nicht passt, faellt
-- unter 'sonstiges'.

DROP VIEW IF EXISTS pfadklassen CASCADE;

CREATE VIEW pfadklassen AS
SELECT
    p.*,
    CASE
      WHEN pfad ~* '(^|/)(mcp|sse)(/|$|\?)'
        OR pfad ~* 'mcp[._-]?(json|config)'          THEN 'mcp'
      WHEN pfad ~* '(^|/)\.env'                      THEN 'env'
      WHEN pfad ~* '(^|/)\.git(/|$)'                 THEN 'git'
      WHEN pfad ~* 'wp-(login|admin|content|includes)|xmlrpc\.php'
                                                     THEN 'wordpress'
      WHEN pfad ~* 'phpmyadmin|adminer|pma'          THEN 'db-oberflaeche'
      WHEN pfad ~* '(^|/)(admin|login|signin|manager)(/|$)'
                                                     THEN 'anmeldung'
      WHEN pfad ~* '\.(bak|sql|zip|tar|gz|old|save|swp)$'
                                                     THEN 'sicherungsdatei'
      WHEN pfad ~* '(^|/)(api|v1|v2|graphql|actuator|swagger)(/|$)'
                                                     THEN 'api'
      WHEN pfad ~* 'cgi-bin|boaform|goform|\.cgi$'   THEN 'geraet'
      WHEN pfad = '/' OR pfad = ''                   THEN 'wurzel'
      ELSE 'sonstiges'
    END AS klasse
FROM beobachtete_pfade p;

COMMENT ON VIEW pfadklassen IS
    'Beobachtete Pfade mit grober Klasse. Grundlage fuer die '
    'Konzentrationsangabe je Klasse statt nur global.';

-- ---------------------------------------------------------------
-- Konzentration je Klasse
-- ---------------------------------------------------------------
-- Musterzahl, Zahl der Netze und Anteil des groessten Netzes werden
-- zusammen ausgewiesen: Eine Musterzahl ohne Netzzahl ueberzeichnet die
-- Streuung, und eine Netzzahl ohne den Anteil des groessten Netzes
-- verdeckt, ob ein einzelner Scanner die Klasse allein traegt.
DROP VIEW IF EXISTS klassenkonzentration CASCADE;

CREATE VIEW klassenkonzentration AS
WITH je_klasse AS (
  SELECT klasse,
         count(DISTINCT pfad)      AS muster,
         count(*)                  AS ereignisse,
         count(DISTINCT quellnetz) AS netze
  FROM pfadklassen GROUP BY klasse
), groesstes AS (
  SELECT DISTINCT ON (klasse) klasse, quellnetz,
         count(DISTINCT pfad) AS muster_groesstes
  FROM pfadklassen GROUP BY klasse, quellnetz
  ORDER BY klasse, count(DISTINCT pfad) DESC, quellnetz
)
SELECT k.klasse, k.muster, k.ereignisse, k.netze,
       host(g.quellnetz)    AS groesstes_netz,
       g.muster_groesstes,
       round(100.0 * g.muster_groesstes / k.muster, 1) AS anteil_groesstes
FROM je_klasse k JOIN groesstes g USING (klasse);

COMMENT ON VIEW klassenkonzentration IS
    'Je Klasse: Muster, Ereignisse, beitragende Netze und der Anteil '
    'des groessten Einzelnetzes.';
