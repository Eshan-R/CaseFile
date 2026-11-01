-- http-flood: per (dst, 443, minute) >= 1000 events from >= 100 distinct sources.
-- T1498.001 and T1499.002, Impact.
SELECT
    'http-flood' AS rule_id,
    'T1498.001+T1499.002' AS technique_id,
    'impact' AS tactic,
    CAST(NULL AS VARCHAR) AS src_ip,
    dst_ip,
    CAST(NULL AS VARCHAR) AS user,
    min(ts) AS t_start,
    max(ts) AS t_end,
    list_sort(list_distinct(array_agg(event_id)))[1:20] AS event_ids,
    count(*) AS n_events,
    count(*) * 1.0 AS metric,
    8 AS severity
FROM events
WHERE dst_port = 443
GROUP BY time_bucket(INTERVAL '1 MINUTE', ts), dst_ip
HAVING count(*) >= 1000 AND count(DISTINCT src_ip) >= 100
ORDER BY t_start ASC, dst_ip ASC;

