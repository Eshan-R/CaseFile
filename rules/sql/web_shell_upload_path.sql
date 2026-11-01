-- web-shell-upload-path: POSTs (or requests) to a URL path requested by
-- exactly one persistent source, path contains upload, >= 20 requests.
-- T1505.003 and T1071.001, Persistence.
SELECT
    'web-shell-upload-path' AS rule_id,
    'T1505.003+T1071.001' AS technique_id,
    'persistence' AS tactic,
    src_ip,
    dst_ip,
    arg_max(user, ts) AS user,
    min(ts) AS t_start,
    max(ts) AS t_end,
    list_sort(list_distinct(array_agg(event_id)))[1:20] AS event_ids,
    count(*) AS n_events,
    count(*) * 1.0 AS metric,
    8 AS severity
FROM events
WHERE url IS NOT NULL AND url ILIKE '%upload%'
GROUP BY url, src_ip, dst_ip
HAVING count(*) >= 20
ORDER BY t_start ASC, src_ip ASC;

