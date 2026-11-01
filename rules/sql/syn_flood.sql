-- syn-flood: per (dst, dport, minute), >= 2000 events from one /16 with sentpkt <= 1 and rcvdpkt = 0.
-- T1498.001, Impact.
SELECT
    'syn-flood' AS rule_id,
    'T1498.001' AS technique_id,
    'impact' AS tactic,
    regexp_extract(src_ip, '^([0-9]+\.[0-9]+)') || '.0.0/16' AS src_ip,
    dst_ip,
    CAST(NULL AS VARCHAR) AS user,
    min(ts) AS t_start,
    max(ts) AS t_end,
    list_sort(list_distinct(array_agg(event_id)))[1:20] AS event_ids,
    count(*) AS n_events,
    count(*) * 1.0 AS metric,
    8 AS severity
FROM events
WHERE sentpkt <= 1 AND rcvdpkt = 0
GROUP BY time_bucket(INTERVAL '1 MINUTE', ts), dst_ip, dst_port, regexp_extract(src_ip, '^([0-9]+\.[0-9]+)')
HAVING count(*) >= 2000
ORDER BY t_start ASC, dst_ip ASC;

