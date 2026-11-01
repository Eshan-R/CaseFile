-- dns-tunnel: dns query name first label >= 32 characters,
-- per (source, registered domain) distinct names >= 50.
-- T1071.004 and T1048.003, Exfiltration.
WITH dns_queries AS (
    SELECT
        src_ip,
        hostname,
        length(regexp_extract(hostname, '^([^.]+)\.')) AS first_label_len,
        regexp_extract(hostname, '([^.]+\.[^.]+)$') AS reg_domain,
        ts,
        event_id
    FROM events
    WHERE hostname IS NOT NULL
      AND length(regexp_extract(hostname, '^([^.]+)\.')) >= 32
)
SELECT
    'dns-tunnel' AS rule_id,
    'T1071.004+T1048.003' AS technique_id,
    'exfiltration' AS tactic,
    src_ip,
    CAST(NULL AS VARCHAR) AS dst_ip,
    CAST(NULL AS VARCHAR) AS user,
    min(ts) AS t_start,
    max(ts) AS t_end,
    list_sort(list_distinct(array_agg(event_id)))[1:20] AS event_ids,
    count(*) AS n_events,
    count(DISTINCT hostname) AS metric,
    8 AS severity
FROM dns_queries
GROUP BY src_ip, reg_domain
HAVING count(DISTINCT hostname) >= 50
ORDER BY t_start ASC, src_ip ASC;

