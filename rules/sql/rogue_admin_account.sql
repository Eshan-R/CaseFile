-- rogue-admin-account: logid 0100044547 Add and a Delete of the same object within 60 minutes
-- (and any login by that account between them).
-- T1136.001 and T1098, Persistence.
WITH adds AS (
    SELECT
        event_id,
        ts,
        user,
        src_ip,
        dst_ip,
        COALESCE(
            NULLIF(regexp_extract(msg, 'system\.admin\s+([a-zA-Z0-9_\-\.]+)', 1), ''),
            split_part(msg, ' ', -1)
        ) AS target_admin
    FROM events
    WHERE logid = '0100044547' AND action = 'Add'
),
deletes AS (
    SELECT
        event_id,
        ts,
        user,
        src_ip,
        dst_ip,
        COALESCE(
            NULLIF(regexp_extract(msg, 'system\.admin\s+([a-zA-Z0-9_\-\.]+)', 1), ''),
            split_part(msg, ' ', -1)
        ) AS target_admin
    FROM events
    WHERE logid = '0100044547' AND action = 'Delete'
)
SELECT
    'rogue-admin-account' AS rule_id,
    'T1136.001+T1098' AS technique_id,
    'persistence' AS tactic,
    COALESCE(a.src_ip, d.src_ip) AS src_ip,
    COALESCE(a.dst_ip, d.dst_ip) AS dst_ip,
    COALESCE(NULLIF(a.target_admin, ''), a.user) AS user,
    a.ts AS t_start,
    d.ts AS t_end,
    [a.event_id, d.event_id] AS event_ids,
    2 AS n_events,
    (epoch(d.ts) - epoch(a.ts)) / 60.0 AS metric,
    8 AS severity
FROM adds a
JOIN deletes d ON a.target_admin = d.target_admin
              AND d.ts > a.ts
              AND d.ts <= a.ts + INTERVAL 60 MINUTE
ORDER BY a.ts ASC;

