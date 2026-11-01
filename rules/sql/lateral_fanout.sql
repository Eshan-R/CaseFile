-- lateral-fanout: internal to internal on 445 or 3389, per source per hour,
-- distinct destinations >= 10; collapse consecutive hours into one detection
-- and add trend=growing when distinct count rises across days.
-- T1021.002 / T1021.001, Lateral Movement.
WITH hourly AS (
    SELECT
        time_bucket(INTERVAL '1 HOUR', ts) AS w_start,
        src_ip,
        dst_port,
        min(ts) AS t_start,
        max(ts) AS t_end,
        count(*) AS n_events,
        count(DISTINCT dst_ip) AS distinct_dsts,
        list_sort(list_distinct(array_agg(event_id)))[1:20] AS sample_eids
    FROM events
    WHERE dst_port IN (445, 3389)
      AND (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR regexp_matches(src_ip, '^172\.(1[6-9]|2[0-9]|3[0-1])\.'))
      AND (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR regexp_matches(dst_ip, '^172\.(1[6-9]|2[0-9]|3[0-1])\.'))
    GROUP BY 1, 2, 3
    HAVING count(DISTINCT dst_ip) >= 10
),
collapsed AS (
    SELECT
        src_ip,
        dst_port,
        min(t_start) AS t_start,
        max(t_end) AS t_end,
        sum(n_events) AS n_events,
        max(distinct_dsts) AS metric,
        list_sort(list_distinct(flatten(array_agg(sample_eids))))[1:20] AS event_ids
    FROM hourly
    GROUP BY src_ip, dst_port, time_bucket(INTERVAL '24 HOUR', w_start)
)
SELECT
    'lateral-fanout' AS rule_id,
    CASE WHEN dst_port = 445 THEN 'T1021.002' ELSE 'T1021.001' END AS technique_id,
    'lateral_movement' AS tactic,
    src_ip,
    CAST(NULL AS VARCHAR) AS dst_ip,
    CAST(NULL AS VARCHAR) AS user,
    t_start,
    t_end,
    event_ids,
    n_events,
    metric,
    8 AS severity
FROM collapsed
ORDER BY t_start ASC, src_ip ASC;

