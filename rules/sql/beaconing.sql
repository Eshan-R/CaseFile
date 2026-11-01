-- beaconing: per (src, dst, port), internal to external, >= 100 events over >= 6 hours,
-- inter-arrival CV <= 0.15 and sentbyte CV <= 0.15.
-- T1071.001 and T1573, Command and Control.
WITH deltas AS (
    SELECT
        src_ip,
        dst_ip,
        dst_port,
        ts,
        sentbyte,
        event_id,
        epoch(ts) - epoch(lag(ts) OVER (PARTITION BY src_ip, dst_ip, dst_port ORDER BY ts)) AS delta
    FROM events
    WHERE (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR regexp_matches(src_ip, '^172\.(1[6-9]|2[0-9]|3[0-1])\.'))
      AND NOT (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR regexp_matches(dst_ip, '^172\.(1[6-9]|2[0-9]|3[0-1])\.'))
      AND dst_port IS NOT NULL
),
stats AS (
    SELECT
        src_ip,
        dst_ip,
        dst_port,
        count(*) AS cnt,
        min(ts) AS t_start,
        max(ts) AS t_end,
        epoch(max(ts)) - epoch(min(ts)) AS timespan,
        stddev_samp(delta) / NULLIF(avg(delta), 0) AS cv_interval,
        stddev_samp(sentbyte) / NULLIF(avg(sentbyte), 0) AS cv_bytes,
        list_sort(list_distinct(array_agg(event_id)))[1:20] AS sample_eids
    FROM deltas
    WHERE delta IS NOT NULL
    GROUP BY 1, 2, 3
    HAVING count(*) >= 100
       AND (epoch(max(ts)) - epoch(min(ts))) >= 21600
)
SELECT
    'beaconing' AS rule_id,
    'T1071.001' AS technique_id,
    'command_and_control' AS tactic,
    src_ip,
    dst_ip,
    CAST(NULL AS VARCHAR) AS user,
    t_start,
    t_end,
    sample_eids AS event_ids,
    cnt AS n_events,
    round(cv_interval, 4) AS metric,
    8 AS severity
FROM stats
WHERE cv_interval <= 0.15 AND cv_bytes <= 0.15
ORDER BY t_start ASC, src_ip ASC;

