import duckdb

con = duckdb.connect("data/run.duckdb", read_only=True)
q = """
WITH deltas AS (
    SELECT
        time_bucket(INTERVAL '6 HOUR', ts) as w_start,
        regexp_extract(src_ip, '^([0-9]+\\.[0-9]+\\.[0-9]+)') as subnet_24,
        src_ip,
        user,
        event_id,
        ts,
        epoch(ts) - epoch(lag(ts) OVER (PARTITION BY time_bucket(INTERVAL '6 HOUR', ts), regexp_extract(src_ip, '^([0-9]+\\.[0-9]+\\.[0-9]+)') ORDER BY ts)) as delta
    FROM events
    WHERE logid = '0100032002'
      AND source_offset <= 4815675419
      AND src_ip IS NOT NULL
),
stats AS (
    SELECT
        w_start,
        subnet_24,
        count(DISTINCT src_ip) as distinct_ips,
        count(DISTINCT user) as distinct_users,
        count(*) as n_events,
        median(delta) as med_delta,
        min(ts) as t_start,
        max(ts) as t_end,
        list_sort(list_distinct(array_agg(event_id)))[1:20] as sample_eids
    FROM deltas
    GROUP BY 1, 2
)
SELECT *
FROM stats
WHERE distinct_ips >= 10
  AND n_events <= 200
  AND med_delta BETWEEN 120 AND 480
ORDER BY w_start, subnet_24
"""
rows = con.execute(q).fetchall()
print(f"Total matching rows: {len(rows)}")
for r in rows:
    print(r)

