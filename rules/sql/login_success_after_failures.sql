-- login-success-after-failures: logid 0100032001 success whose source or /24 had >= 5 failures in the previous 60 minutes.
-- T1110.001 and T1078, Credential Access.
WITH succ AS (
    SELECT
        event_id,
        ts,
        src_ip,
        dst_ip,
        user,
        regexp_extract(src_ip, '^([0-9]+\.[0-9]+\.[0-9]+)') AS subnet_24
    FROM events
    WHERE logid = '0100032001'
),
evaluated AS (
    SELECT
        'login-success-after-failures' AS rule_id,
        'T1078.001' AS technique_id,
        'initial_access' AS tactic,
        s.src_ip,
        s.dst_ip,
        s.user,
        s.ts AS t_start,
        s.ts AS t_end,
        [s.event_id] AS event_ids,
        1 AS n_events,
        (
            SELECT count(*)
            FROM events f
            WHERE f.logid = '0100032002'
              AND (f.src_ip = s.src_ip OR regexp_extract(f.src_ip, '^([0-9]+\.[0-9]+\.[0-9]+)') = s.subnet_24)
              AND f.ts >= s.ts - INTERVAL 60 MINUTE
              AND f.ts < s.ts
        ) AS prior_fails,
        8 AS severity
    FROM succ s
)
SELECT
    rule_id,
    technique_id,
    tactic,
    src_ip,
    dst_ip,
    user,
    t_start,
    t_end,
    event_ids,
    n_events,
    prior_fails AS metric,
    severity
FROM evaluated
WHERE prior_fails >= 5
ORDER BY t_start ASC, src_ip ASC;

