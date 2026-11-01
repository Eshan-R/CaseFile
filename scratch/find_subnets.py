import duckdb

con = duckdb.connect("data/run.duckdb", read_only=True)
q = """
SELECT
    regexp_extract(src_ip, '^([0-9]+\\.[0-9]+\\.[0-9]+)') as sub,
    count(distinct src_ip) as ips,
    count(distinct user) as usrs,
    count(*) as cnt,
    min(ts) as t_min,
    max(ts) as t_max
FROM events
WHERE logid = '0100032002'
  AND source_offset <= 4815675419
GROUP BY 1
ORDER BY ips DESC
"""
rows = con.execute(q).fetchall()
for r in rows:
    print(r)

