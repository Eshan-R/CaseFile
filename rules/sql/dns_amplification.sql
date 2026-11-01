-- dns-amplification: inbound udp source port 53, >= 500 events with average rcvdbyte >= 1000.
-- T1498.002, Impact.
SELECT
    'dns-amplification' AS rule_id,
    'T1498.002' AS technique_id,
    'impact' AS tactic,
    src_ip,
    dst_ip,
    CAST(NULL AS VARCHAR) AS user,
    min(ts) AS t_start,
    max(ts) AS t_end,
    list_sort(list_distinct(array_agg(event_id)))[1:20] AS event_ids,
    count(*) AS n_events,
    avg(rcvdbyte) AS metric,
    8 AS severity
FROM events
WHERE src_port = 53 AND (proto = 17 OR service ILIKE '%udp%' OR service ILIKE '%dns%')
GROUP BY time_bucket(INTERVAL '1 MINUTE', ts), src_ip, dst_ip
HAVING count(*) >= 500 AND avg(rcvdbyte) >= 1000
ORDER BY t_start ASC, dst_ip ASC;

