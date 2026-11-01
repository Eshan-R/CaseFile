import duckdb

con = duckdb.connect("data/run.duckdb", read_only=True)
q = """
SELECT
    time_bucket(INTERVAL '6 HOUR', ts) as w_start,
    regexp_extract(src_ip, '^([0-9]+\\.[0-9]+\\.[0-9]+)') as subnet_24,
    count(distinct src_ip) as distinct_ips,
    count(distinct user) as distinct_users,
    count(*) as n_events,
    min(ts) as t_start,
    max(ts) as t_end
FROM events
WHERE logid = '0100032002'
  AND src_ip LIKE '71.54.76.%'
  AND source_offset <= 4815675419
GROUP BY 1, 2
"""
rows = con.execute(q).fetchall()
for r in rows:
    print(r)

