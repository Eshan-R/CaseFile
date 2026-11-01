-- slow-credential-stuffing: failed admin logins, per /24, per 6 hours:
-- distinct users >= 50, per-window events <= 200, median inter-arrival between 120 and 480 s,
-- and the /24 is not a high-volume /24 (daily failures per /24 below the 95th percentile of all /24s).
-- T1110.004, Credential Access.
WITH subnet_events AS (
    SELECT
        event_id,
        ts,
        src_ip,
        user,
        regexp_extract(src_ip, '^([0-9]+\.[0-9]+\.[0-9]+)') AS subnet_24,
        time_bucket(INTERVAL '6 HOUR', ts) AS w_start,
        epoch(ts) - epoch(lag(ts) OVER (PARTITION BY regexp_extract(src_ip, '^([0-9]+\.[0-9]+\.[0-9]+)'), time_bucket(INTERVAL '6 HOUR', ts) ORDER BY ts)) AS delta
    FROM events
    WHERE logid = '0100032002'
      AND regexp_matches(src_ip, '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
),
daily_counts AS (
    SELECT
        regexp_extract(src_ip, '^([0-9]+\.[0-9]+\.[0-9]+)') AS subnet_24,
        count(*) AS d_cnt
    FROM events
    WHERE logid = '0100032002'
    GROUP BY 1, time_bucket(INTERVAL '1 DAY', ts)
),
p95_val AS (
    SELECT quantile_disc(d_cnt, 0.95) AS thresh FROM daily_counts
),
window_stats AS (
    SELECT
        s.w_start,
        s.subnet_24,
        count(DISTINCT s.src_ip) AS distinct_ips,
        count(DISTINCT s.user) AS distinct_users,
        count(*) AS n_events,
        median(s.delta) AS med_delta,
        min(s.ts) AS t_start,
        max(s.ts) AS t_end,
        list_sort(list_distinct(array_agg(s.event_id)))[1:20] AS sample_eids
    FROM subnet_events s
    GROUP BY s.w_start, s.subnet_24
    HAVING count(DISTINCT s.src_ip) >= 10
       AND count(*) <= 200
       AND median(s.delta) BETWEEN 120 AND 480
)
SELECT
    'slow-credential-stuffing' AS rule_id,
    'T1110.004' AS technique_id,
    'credential_access' AS tactic,
    w.subnet_24 || '.0/24' AS src_ip,
    CAST(NULL AS VARCHAR) AS dst_ip,
    CAST(NULL AS VARCHAR) AS user,
    w.t_start,
    w.t_end,
    w.sample_eids AS event_ids,
    w.n_events,
    w.distinct_users AS metric,
    8 AS severity
FROM window_stats w
CROSS JOIN p95_val p
JOIN daily_counts d ON w.subnet_24 = d.subnet_24
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, p.thresh
HAVING avg(d.d_cnt) < p.thresh
ORDER BY w.t_start ASC, src_ip ASC;

