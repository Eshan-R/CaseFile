-- config-logging-disabled: logid 0100044546 where cfgpath/msg mentions log and disable,
-- or >= 3 config Edit events by one admin within 6 hours.
-- T1562.002 and T1070, Defense Evasion.
WITH direct_disable AS (
    SELECT
        event_id,
        ts,
        user,
        src_ip,
        dst_ip,
        'direct_disable' AS branch
    FROM events
    WHERE logid = '0100044546'
      AND ((msg ILIKE '%log%' AND msg ILIKE '%disable%') OR msg ILIKE '%purge%')
),
frequent_edits AS (
    SELECT
        arg_min(event_id, ts) AS event_id,
        min(ts) AS t_start,
        max(ts) AS t_end,
        user,
        arg_min(src_ip, ts) AS src_ip,
        arg_min(dst_ip, ts) AS dst_ip,
        count(*) AS cnt,
        list_sort(list_distinct(array_agg(event_id)))[1:20] AS eids,
        'frequent_edits' AS branch
    FROM events
    WHERE logid = '0100044546'
      AND action = 'Edit'
      AND user IS NOT NULL
    GROUP BY user, time_bucket(INTERVAL '6 HOUR', ts)
    HAVING count(*) >= 3
)
SELECT
    'config-logging-disabled' AS rule_id,
    'T1562.002' AS technique_id,
    'defense_evasion' AS tactic,
    src_ip,
    dst_ip,
    user,
    ts AS t_start,
    ts AS t_end,
    [event_id] AS event_ids,
    1 AS n_events,
    1.0 AS metric,
    8 AS severity
FROM direct_disable
UNION ALL
SELECT
    'config-logging-disabled' AS rule_id,
    'T1562.002' AS technique_id,
    'defense_evasion' AS tactic,
    src_ip,
    dst_ip,
    user,
    t_start,
    t_end,
    eids AS event_ids,
    cnt AS n_events,
    cnt * 1.0 AS metric,
    8 AS severity
FROM frequent_edits
ORDER BY t_start ASC, user ASC;

