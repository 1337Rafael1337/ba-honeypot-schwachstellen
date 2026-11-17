-- Sicht nuclei_bodenwahrheit: Eignung jedes Pfadmusters als Ground Truth
-- (Kap. 3.4).
--
-- Massgeblich ist die Vielfachheit: Wie viele Templates beanspruchen
-- dasselbe Muster? Ein Muster, das genau einem Template gehoert, ordnet
-- einen beobachteten Pfad eindeutig zu; eines, das hunderten Templates
-- gehoert (etwa /wp-login.php), nur willkuerlich. Eine reine
-- Wortheuristik ist dafuer ungeeignet: Sie verwirft eindeutige Muster wie
-- /mcp und laesst /wp-login.php zu.
--
-- Hinzu kommt ein Anker: Ein Muster muss nach Abzug von Platzhaltern
-- genug woertlichen Text enthalten, um nicht auf beliebige Pfade zu
-- passen.

DROP VIEW IF EXISTS nuclei_bodenwahrheit CASCADE;

CREATE VIEW nuclei_bodenwahrheit AS
WITH vielfachheit AS (
    SELECT muster, count(DISTINCT template_id) AS templates
    FROM nuclei_pattern
    GROUP BY muster
),
anker AS (
    SELECT id,
           -- Woertlicher Anteil ohne Platzhalter, Trennzeichen und
           -- Dateiendung. Ohne den Abzug der Endung haette
           -- `/{{str}}.json` vier Ankerzeichen, passt aber auf jeden
           -- Pfad, der auf .json endet. `env` steht nicht in der Liste,
           -- weil /.env ein konkretes Ziel ist und kein Dateiformat.
           length(regexp_replace(
             regexp_replace(
               regexp_replace(muster, '\{\{[^}]*\}\}', '', 'g'),
               '(?i)\.(json|php[0-9]?|txt|xml|s?html?|aspx?|jsp|css|js|log|bak|old|zip|tar|gz|png|jpe?g|gif|ico|pdf|ya?ml|ini|cfg|conf|sql|bz2|rar|7z|swp|save|copy|orig|tmp)$',
               '', 'g'),
             '[^A-Za-z0-9]', '', 'g')) AS anker_zeichen,
           -- Zweiter Anker: zusaetzlich ohne generische
           -- Verzeichnisnamen. `/api/{{randstr}}` passt sonst auf jeden
           -- Pfad unterhalb von /api.
           length(regexp_replace(
             regexp_replace(
               regexp_replace(
                 regexp_replace(muster, '\{\{[^}]*\}\}', '', 'g'),
                 '(?i)\.(json|php[0-9]?|txt|xml|s?html?|aspx?|jsp|css|js|log|bak|old|zip|tar|gz|png|jpe?g|gif|ico|pdf|ya?ml|ini|cfg|conf|sql|bz2|rar|7z|swp|save|copy|orig|tmp)$',
                 '', 'g'),
               '(?i)(^|/)(api|admin|assets|app|apps|config|static|public|images|img|uploads|files|data|test|tmp|temp|cgi-bin|v[0-9]+|www|web|site|user|users|login|home|index|main|src|lib|bin|out|dist|build)(/|$)',
               '/', 'g'),
             '[^A-Za-z0-9]', '', 'g')) AS eigener_anker
    FROM nuclei_pattern
)
SELECT
    p.id,
    p.template_id,
    p.methode,
    p.muster,
    p.hat_platzhalter,
    v.templates AS vielfachheit,
    a.anker_zeichen,
    a.eigener_anker,
    -- Guetestufe:
    --   ankerlos   weniger als drei Ankerzeichen; schliesst Muster wie
    --              /{{bucket}}/{{object}} aus, die nur aus Platzhaltern
    --              bestehen. Drei statt vier, weil /.env und /mcp genau
    --              drei haben und trotzdem spezifisch sind.
    --   eindeutig  genau ein Template
    --   eng        zwei bis fuenf Templates
    --   weit       mehr als fuenf Templates
    CASE WHEN a.anker_zeichen < 3 OR a.eigener_anker < 3 THEN 'ankerlos'
         WHEN v.templates = 1 THEN 'eindeutig'
         WHEN v.templates <= 5 THEN 'eng'
         ELSE 'weit' END AS guete
FROM nuclei_pattern p
JOIN vielfachheit v USING (muster)
JOIN anker a ON a.id = p.id;

COMMENT ON VIEW nuclei_bodenwahrheit IS
    'Pfadmuster mit Vielfachheit und Guetestufe (eindeutig, eng, weit, '
    'ankerlos). Ground Truth sind die Stufen eindeutig und eng.';
