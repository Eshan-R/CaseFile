-- virus-detected-not-blocked: utm virus with action not blocked.
-- T1105 (and T1204.002 if the file is an executable). Command and Control / Execution.
SELECT
    'virus-detected-not-blocked' AS rule_id,
    'T1105' AS technique_id,
    'command_and_control' AS tactic,
    src_ip,
    dst_ip,
    user,
    ts AS t_start,
    ts AS t_end,
    [event_id] AS event_ids,
    1 AS n_events,
    1.0 AS metric,
    8 AS severity
FROM events
WHERE subtype = 'virus'
  AND action NOT IN ('blocked', 'block', 'drop')
ORDER BY ts ASC, src_ip ASC;

