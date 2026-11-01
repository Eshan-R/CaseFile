-- vpn-impossible-travel: one user, two source countries (or /16 if no country field) within 60 minutes;
-- MERGE overlapping windows into one detection per user.
-- T1078.004, Initial Access.
WITH vpn_logins AS (
    SELECT
        event_id,
        ts,
        user,
        src_ip,
        dst_ip,
        srccountry,
        COALESCE(NULLIF(srccountry, ''), regexp_extract(src_ip, '^([0-9]+\.[0-9]+)')) AS country_proxy
    FROM events
    WHERE (action IN ('tunnel-up', 'ssl-login') OR subtype = 'vpn')
      AND user IS NOT NULL
),
pairs AS (
    SELECT
        a.user,
        a.src_ip AS src_ip_a,
        b.src_ip AS src_ip_b,
        a.country_proxy AS country_a,
        b.country_proxy AS country_b,
        a.ts AS t_start,
        b.ts AS t_end,
        (epoch(b.ts) - epoch(a.ts)) / 60.0 AS diff_minutes,
        [a.event_id, b.event_id] AS eids
    FROM vpn_logins a
    JOIN vpn_logins b ON a.user = b.user AND a.ts < b.ts AND b.ts <= a.ts + INTERVAL 60 MINUTE
    WHERE a.country_proxy != b.country_proxy
)
SELECT
    'vpn-impossible-travel' AS rule_id,
    'T1078.004' AS technique_id,
    'initial_access' AS tactic,
    arg_min(src_ip_a, t_start) AS src_ip,
    CAST(NULL AS VARCHAR) AS dst_ip,
    user,
    min(t_start) AS t_start,
    max(t_end) AS t_end,
    list_sort(list_distinct(flatten(array_agg(eids))))[1:20] AS event_ids,
    count(*) AS n_events,
    round(min(diff_minutes), 2) AS metric,
    8 AS severity
FROM pairs
GROUP BY user, time_bucket(INTERVAL '60 MINUTE', t_start)
ORDER BY t_start ASC, user ASC;

