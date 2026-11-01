-- failed-admin-burst: logid 0100032002, one source, >= 500 failures in 10 minutes.
-- T1110.001, Credential Access.
SELECT
    'failed-admin-burst' AS rule_id,
    'T1110.001' AS technique_id,
    'credential_access' AS tactic,
    src_ip,
    arg_max(dst_ip, ts) AS dst_ip,
    arg_max(user, ts) AS user,
    min(ts) AS t_start,
    max(ts) AS t_end,
    list_sort(list_distinct(array_agg(event_id)))[1:20] AS event_ids,
    count(*) AS n_events,
    count(*) AS metric,
    8 AS severity
FROM events
WHERE logid = '0100032002'
GROUP BY time_bucket(INTERVAL '10 MINUTE', ts), src_ip
HAVING count(*) >= 500
ORDER BY t_start ASC, src_ip ASC;

