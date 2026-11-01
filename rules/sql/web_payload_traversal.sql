-- web-payload-traversal: URL-decoded-once directory traversal regexes,
-- per (src, dst, class) per 10 minutes, >= 10 events.
-- T1190 and T1083, Initial Access / Discovery.
WITH decoded AS (
    SELECT
        event_id,
        ts,
        src_ip,
        dst_ip,
        user,
        TRY_CAST(url_decode(COALESCE(url, '')) AS VARCHAR) AS d_url
    FROM events
    WHERE url IS NOT NULL
)
SELECT
    'web-payload-traversal' AS rule_id,
    'T1190+T1083' AS technique_id,
    'discovery' AS tactic,
    src_ip,
    dst_ip,
    arg_max(user, ts) AS user,
    min(ts) AS t_start,
    max(ts) AS t_end,
    list_sort(list_distinct(array_agg(event_id)))[1:20] AS event_ids,
    count(*) AS n_events,
    count(*) * 1.0 AS metric,
    8 AS severity
FROM decoded
WHERE regexp_matches(d_url, '(?i)(\.\./|php://)')
GROUP BY time_bucket(INTERVAL '10 MINUTE', ts), src_ip, dst_ip
HAVING count(*) >= 10
ORDER BY t_start ASC, src_ip ASC;

