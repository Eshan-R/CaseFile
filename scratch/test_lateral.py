import duckdb

con = duckdb.connect("data/run.duckdb", read_only=True)
q = """
SELECT
    time_bucket(INTERVAL '1 HOUR', ts) as w_start,
    src_ip,
    dst_port,
    min(ts) as t_start,
    max(ts) as t_end,
    count(*) as n_events,
    count(DISTINCT dst_ip) as distinct_dsts
FROM events
WHERE dst_port IN (445, 3389)
  AND (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR regexp_matches(src_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
  AND (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR regexp_matches(dst_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'))
  AND source_offset <= 4815675419
GROUP BY 1, 2, 3
HAVING count(DISTINCT dst_ip) >= 10
ORDER BY w_start, src_ip, dst_port
"""
rows = con.execute(q).fetchall()
print(f"Total lateral rows: {len(rows)}")
for r in rows[:10]:
    print(r)

