-- port-scan: per (src, dst) per 5 minutes, distinct dstport >= 200 regardless of action.
-- T1046, Discovery. (Replaces the deny-only version).
SELECT
    'port-scan' AS rule_id,
    'T1046' AS technique_id,
    'discovery' AS tactic,
    src_ip,
    dst_ip,
    arg_max(user, ts) AS user,
    min(ts) AS t_start,
    max(ts) AS t_end,
    list_sort(list_distinct(array_agg(event_id)))[1:20] AS event_ids,
    count(*) AS n_events,
    count(DISTINCT dst_port) AS metric,
    5 AS severity
FROM events
WHERE dst_port IS NOT NULL
GROUP BY time_bucket(INTERVAL '5 MINUTE', ts), src_ip, dst_ip
HAVING count(DISTINCT dst_port) >= 200
ORDER BY t_start ASC, src_ip ASC;

