-- admin-login-external: any 0100032001 success from an external IP;
-- severity medium (5), and high (8) if local hour (+05:30) < 6.
-- T1078.001, Initial Access.
SELECT
    'admin-login-external' AS rule_id,
    'T1078.001' AS technique_id,
    'initial_access' AS tactic,
    src_ip,
    dst_ip,
    user,
    ts AS t_start,
    ts AS t_end,
    [event_id] AS event_ids,
    1 AS n_events,
    extract(hour from (ts at time zone 'UTC' + INTERVAL 5 HOUR + INTERVAL 30 MINUTE)) AS metric,
    CASE
        WHEN extract(hour from (ts at time zone 'UTC' + INTERVAL 5 HOUR + INTERVAL 30 MINUTE)) < 6 THEN 8
        ELSE 5
    END AS severity
FROM events
WHERE logid = '0100032001'
  AND src_ip IS NOT NULL
  AND NOT (
      src_ip LIKE '10.%'
      OR src_ip LIKE '192.168.%'
      OR src_ip LIKE '127.%'
      OR regexp_matches(src_ip, '^172\.(1[6-9]|2[0-9]|3[0-1])\.')
  )
ORDER BY ts ASC, src_ip ASC;

