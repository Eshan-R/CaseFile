-- staged-exfil: internal source to one external destination over >= 24 hours,
-- sum(sentbyte)/sum(rcvdbyte) >= 1.5 and >= 500 events.
-- T1048.002 and T1030, Exfiltration. Host with virus/beaconing gets severity +2 (10).
WITH candidates AS (
    SELECT
        src_ip,
        dst_ip,
        count(*) AS cnt,
        min(ts) AS t_start,
        max(ts) AS t_end,
        (epoch(max(ts)) - epoch(min(ts))) AS timespan_sec,
        sum(sentbyte) AS total_sent,
        sum(rcvdbyte) AS total_rcvd,
        sum(sentbyte) * 1.0 / NULLIF(sum(rcvdbyte), 0) AS ratio,
        list_sort(list_distinct(array_agg(event_id)))[1:20] AS sample_eids
    FROM events
    WHERE (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR regexp_matches(src_ip, '^172\.(1[6-9]|2[0-9]|3[0-1])\.'))
      AND NOT (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR regexp_matches(dst_ip, '^172\.(1[6-9]|2[0-9]|3[0-1])\.'))
    GROUP BY 1, 2
    HAVING count(*) >= 500
       AND (epoch(max(ts)) - epoch(min(ts))) >= 86400
       AND sum(sentbyte) * 1.0 / NULLIF(sum(rcvdbyte), 0) >= 1.5
)
SELECT
    'staged-exfil' AS rule_id,
    'T1048.002' AS technique_id,
    'exfiltration' AS tactic,
    src_ip,
    dst_ip,
    CAST(NULL AS VARCHAR) AS user,
    t_start,
    t_end,
    sample_eids AS event_ids,
    cnt AS n_events,
    round(ratio, 2) AS metric,
    CASE
        WHEN src_ip IN (
            SELECT src_ip FROM events WHERE subtype = 'virus' AND action NOT IN ('blocked', 'block', 'drop')
        ) THEN 10
        ELSE 8
    END AS severity
FROM candidates
ORDER BY t_start ASC, src_ip ASC;

