# Comprehensive Incident Review & Verification Table

> [!NOTE]

> This table documents all formed clusters (both **PROMOTED** incidents and **LEAD** clusters) across the evaluated dataset. Timestamps are reported in both UTC and local time (+05:30).

## 1. Incidents Table (Promoted & Leads)

| ID | Status | Score | First Seen (UTC / +05:30) | Last Seen (UTC / +05:30) | Entities (max 5) | Rule Sequence (Techniques) | Tactic Stages | Active Dets | Oracle Behavior Match |
|---|---|---|---|---|---|---|---|---|---|
| `inc_ff192b44` | **PROMOTED** | 9.4 | 2026-10-23 10:52:40 UTC<br>(16:22:40 +05:30) | 2026-10-28 20:40:02 UTC<br>(02:10:02 +05:30) | `10.10.10.44`, `10.10.10.63`, `10.10.20.20`, `10.10.20.31`, `131.228.119.59` *(+6 more)* | step [T1190+T1595.002] &rarr; step [T1189+T1059.007] &rarr; step [T1190+T1059.004] &rarr; step [T1505.003+T1071.001] &rarr; step [T1046] &rarr; step [T1190+T1083] &rarr; step [T1021.001] &rarr; step [T1021.002] &rarr; step [T1048.002] | `initial_access` &rarr; `execution` &rarr; `persistence` &rarr; `discovery` &rarr; `lateral_movement` &rarr; `exfiltration` | 16 | `beacon`, `config_change`, `lateral_fanout`, `port_scan`, `staged_exfil`, `web_payload` |
| `inc_4332427f` | **PROMOTED** | 7.7 | 2026-10-26 02:52:00 UTC<br>(08:22:00 +05:30) | 2026-10-26 02:56:00 UTC<br>(08:26:00 +05:30) | `10.10.10.118` | step [T1105] &rarr; step [T1048.002] | `command_and_control` &rarr; `exfiltration` | 4 | `beacon`, `virus_detected_not_blocked` |
| `inc_c68b7436` | **PROMOTED** | 7.1 | 2026-10-24 14:28:06 UTC<br>(19:58:06 +05:30) | 2026-10-24 14:28:06 UTC<br>(19:58:06 +05:30) | `10.10.10.88` | step [T1071.004+T1048.003] | `exfiltration` | 1 | `admin_success`, `beacon`, `dns_tunnel` |
| `inc_66e15644` | **PROMOTED** | 6.5 | 2026-10-28 22:25:43 UTC<br>(03:55:43 +05:30) | 2026-10-28 22:32:01 UTC<br>(04:02:01 +05:30) | `10.10.99.1`, `rakes`, `svc_backup30`, `203.228.177.117` | step [T1078.001] &rarr; step [T1136.001+T1098] | `initial_access` &rarr; `persistence` | 2 | `admin_success`, `beacon`, `config_change`, `lateral_fanout`, `staged_exfil` |
| `inc_9223e269` | **PROMOTED** | 5.3 | 2026-10-23 17:57:11 UTC<br>(23:27:11 +05:30) | 2026-10-23 17:57:11 UTC<br>(23:27:11 +05:30) | `10.10.10.112` | step [T1071.001] | `command_and_control` | 1 | `beacon` |
| `inc_f4f8f1e9` | **PROMOTED** | 5.3 | 2026-10-27 04:10:01 UTC<br>(09:40:01 +05:30) | 2026-10-27 04:10:01 UTC<br>(09:40:01 +05:30) | `71.54.76.0/24`, `admin`, `admin-it`, `ania`, `denis` *(+30 more)* | step [T1110.004] | `credential_access` | 1 | `beacon`, `slow_stuffing_24`, `staged_exfil` |
| `inc_59c30ca0` | **PROMOTED** | 5.3 | 2026-10-27 06:02:37 UTC<br>(11:32:37 +05:30) | 2026-10-27 06:02:37 UTC<br>(11:32:37 +05:30) | `71.54.76.0/24`, `adilson`, `admin`, `altere`, `amirhossein` *(+26 more)* | step [T1110.004] | `credential_access` | 1 | `beacon`, `slow_stuffing_24`, `staged_exfil` |
| `inc_9b809294` | **PROMOTED** | 5.3 | 2026-10-27 10:00:56 UTC<br>(15:30:56 +05:30) | 2026-10-27 10:00:56 UTC<br>(15:30:56 +05:30) | `10.10.10.44` | step [T1021.002] | `lateral_movement` | 1 | `beacon`, `lateral_fanout`, `slow_stuffing_24`, `staged_exfil` |
| `inc_4367722f` | **PROMOTED** | 5.3 | 2026-10-29 00:01:36 UTC<br>(05:31:36 +05:30) | 2026-10-29 00:01:36 UTC<br>(05:31:36 +05:30) | `10.10.10.44` | step [T1021.002] | `lateral_movement` | 1 | `beacon`, `lateral_fanout`, `staged_exfil` |
| `inc_6cdfeaf8` | **PROMOTED** | 5.3 | 2026-10-24 14:29:30 UTC<br>(19:59:30 +05:30) | 2026-10-24 14:29:30 UTC<br>(19:59:30 +05:30) | `10.10.99.1`, `parul.sinha`, `8.42.69.77` | step [T1078.001] | `initial_access` | 2 | `admin_success`, `beacon`, `dns_tunnel` |
| `inc_c4dcead4` | **PROMOTED** | 5.3 | 2026-10-27 20:35:37 UTC<br>(02:05:37 +05:30) | 2026-10-27 21:00:06 UTC<br>(02:30:06 +05:30) | `102.8.77.227`, `keerat.ghughal`, `9.222.114.167` | step [T1078.004] | `initial_access` | 2 | `beacon`, `lateral_fanout`, `staged_exfil`, `vpn_impossible_travel` |
| `inc_dfb8c001` | **PROMOTED** | 5.1 | 2026-10-27 21:47:00 UTC<br>(03:17:00 +05:30) | 2026-10-27 21:47:00 UTC<br>(03:17:00 +05:30) | `10.10.99.1`, `deepika.khan`, `171.104.84.193` | step [T1078.001] | `initial_access` | 1 | `admin_success`, `beacon`, `lateral_fanout`, `staged_exfil` |
| `inc_1792b455` | **PROMOTED** | 5.1 | 2026-10-27 22:17:39 UTC<br>(03:47:39 +05:30) | 2026-10-27 22:17:39 UTC<br>(03:47:39 +05:30) | `10.10.99.1`, `deepika.khan`, `171.104.84.193` | step [T1078.001] | `initial_access` | 1 | `admin_success`, `beacon`, `lateral_fanout`, `staged_exfil` |
| `inc_5996d302` | **PROMOTED** | 5.1 | 2026-10-27 22:47:51 UTC<br>(04:17:51 +05:30) | 2026-10-27 22:47:51 UTC<br>(04:17:51 +05:30) | `10.10.99.1`, `deepika.khan`, `171.104.84.193` | step [T1078.001] | `initial_access` | 1 | `admin_success`, `beacon`, `lateral_fanout`, `staged_exfil` |
| `inc_2123e0f3` | **PROMOTED** | 4.6 | 2026-10-23 11:01:43 UTC<br>(16:31:43 +05:30) | 2026-10-23 11:01:43 UTC<br>(16:31:43 +05:30) | `10.10.99.1`, `tejas.roy`, `78.120.139.0` | step [T1562.002] | `defense_evasion` | 1 | `config_change`, `web_payload` |
| `inc_88b013f3` | **PROMOTED** | 4.6 | 2026-10-23 12:58:52 UTC<br>(18:28:52 +05:30) | 2026-10-23 12:58:52 UTC<br>(18:28:52 +05:30) | `10.10.99.1`, `tejas.roy`, `78.120.139.0` | step [T1562.002] | `defense_evasion` | 1 | `config_change` |
| `inc_38806d1c` | **PROMOTED** | 4.6 | 2026-10-23 15:06:18 UTC<br>(20:36:18 +05:30) | 2026-10-23 15:06:18 UTC<br>(20:36:18 +05:30) | `10.10.99.1`, `tejas.roy`, `78.120.139.0` | step [T1562.002] | `defense_evasion` | 1 | `config_change` |

---

## 2. Uncovered Merged Oracle Behaviors

> [!NOTE]

> Independent SQL oracle behaviors that have NO matching active detection within a PROMOTED incident (status='open').

| Oracle Class | Entity | Window Start (UTC) | Window End (UTC) | Expected Technique | Expected Tactic | Uncovered Reason |
|---|---|---|---|---|---|---|
| `failed_admin_burst` | `None` | 2026-10-27T07:30:00+00:00 | 2026-10-27T07:38:37+00:00 | `T1110.001` | `Credential Access` | No active detection fired |

---

## 3. Multi-Class Incidents: Chronological Detections & Tactic Progression

> [!NOTE]

> Incidents spanning $\ge 2$ distinct tactics. Detections are listed in strict chronological order with tactic order breaks annotated.


### Incident `inc_ff192b44` (PROMOTED) &mdash; Web Cross-Site Scripting Attack (+8 stages) on 10.10.10.44

| Time (UTC) | Rule ID | Technique ID | Tactic | Stage Order Transition |
|---|---|---|---|---|
| 2026-10-23 10:52:40 UTC (16:22:40 +05:30) | `web-payload-xss` | `T1189+T1059.007` | `execution` | Sequential / Concurrent |
| 2026-10-24 20:34:06 UTC (02:04:06 +05:30) | `lateral-fanout` | `T1021.001` | `lateral_movement` | OK (`execution` &rarr; `lateral_movement`) |
| 2026-10-24 20:34:11 UTC (02:04:11 +05:30) | `lateral-fanout` | `T1021.002` | `lateral_movement` | Sequential / Concurrent |
| 2026-10-25 14:34:39 UTC (20:04:39 +05:30) | `web-payload-sqli` | `T1190+T1595.002` | `initial_access` | **[BREAK: Backwards]** `lateral_movement` &rarr; `initial_access` (Stage 9 &rarr; 2) |
| 2026-10-25 14:40:00 UTC (20:10:00 +05:30) | `web-payload-sqli` | `T1190+T1595.002` | `initial_access` | Sequential / Concurrent |
| 2026-10-26 04:38:34 UTC (10:08:34 +05:30) | `staged-exfil` | `T1048.002` | `exfiltration` | OK (`initial_access` &rarr; `exfiltration`) |
| 2026-10-26 11:30:13 UTC (17:00:13 +05:30) | `web-payload-cmdi` | `T1190+T1059.004` | `execution` | **[BREAK: Backwards]** `exfiltration` &rarr; `execution` (Stage 12 &rarr; 3) |
| 2026-10-27 01:17:15 UTC (06:47:15 +05:30) | `web-shell-upload-path` | `T1505.003+T1071.001` | `persistence` | OK (`execution` &rarr; `persistence`) |
| 2026-10-27 01:22:34 UTC (06:52:34 +05:30) | `web-shell-upload-path` | `T1505.003+T1071.001` | `persistence` | Sequential / Concurrent |
| 2026-10-27 15:37:50 UTC (21:07:50 +05:30) | `port-scan` | `T1046` | `discovery` | OK (`persistence` &rarr; `discovery`) |
| 2026-10-28 00:00:30 UTC (05:30:30 +05:30) | `lateral-fanout` | `T1021.002` | `lateral_movement` | OK (`discovery` &rarr; `lateral_movement`) |
| 2026-10-28 05:45:26 UTC (11:15:26 +05:30) | `web-payload-traversal` | `T1190+T1083` | `discovery` | **[BREAK: Backwards]** `lateral_movement` &rarr; `discovery` (Stage 9 &rarr; 8) |
| 2026-10-28 05:50:05 UTC (11:20:05 +05:30) | `web-payload-traversal` | `T1190+T1083` | `discovery` | Sequential / Concurrent |
| 2026-10-28 20:21:23 UTC (01:51:23 +05:30) | `port-scan` | `T1046` | `discovery` | Sequential / Concurrent |
| 2026-10-28 20:37:14 UTC (02:07:14 +05:30) | `web-payload-sqli` | `T1190+T1595.002` | `initial_access` | **[BREAK: Backwards]** `discovery` &rarr; `initial_access` (Stage 8 &rarr; 2) |
| 2026-10-28 20:40:02 UTC (02:10:02 +05:30) | `web-payload-sqli` | `T1190+T1595.002` | `initial_access` | Sequential / Concurrent |

### Incident `inc_4332427f` (PROMOTED) &mdash; Staged Asymmetric Data Exfiltration (+1 stages) on 10.10.10.118

| Time (UTC) | Rule ID | Technique ID | Tactic | Stage Order Transition |
|---|---|---|---|---|
| 2026-10-26 02:52:00 UTC (08:22:00 +05:30) | `virus-detected-not-blocked` | `T1105` | `command_and_control` | Sequential / Concurrent |
| 2026-10-26 02:52:00 UTC (08:22:00 +05:30) | `staged-exfil` | `T1048.002` | `exfiltration` | OK (`command_and_control` &rarr; `exfiltration`) |
| 2026-10-26 02:54:00 UTC (08:24:00 +05:30) | `virus-detected-not-blocked` | `T1105` | `command_and_control` | **[BREAK: Backwards]** `exfiltration` &rarr; `command_and_control` (Stage 12 &rarr; 11) |
| 2026-10-26 02:56:00 UTC (08:26:00 +05:30) | `virus-detected-not-blocked` | `T1105` | `command_and_control` | Sequential / Concurrent |

### Incident `inc_66e15644` (PROMOTED) &mdash; Ephemeral Rogue Administrator Account (+1 stages) on 10.10.99.1

| Time (UTC) | Rule ID | Technique ID | Tactic | Stage Order Transition |
|---|---|---|---|---|
| 2026-10-28 22:25:43 UTC (03:55:43 +05:30) | `rogue-admin-account` | `T1136.001+T1098` | `persistence` | Sequential / Concurrent |
| 2026-10-28 22:32:01 UTC (04:02:01 +05:30) | `admin-login-external` | `T1078.001` | `initial_access` | **[BREAK: Backwards]** `persistence` &rarr; `initial_access` (Stage 4 &rarr; 2) |

---

## 4. Chain Check: Independent Promoted Incidents Within 72h

> [!NOTE]

> For each pair of promoted incidents sharing an internal host IP or external destination within 72 hours, explains why the incident linking engine kept them separate without modifying graph linking logic.

| Incident Pair | Shared Entity | Time Gap | Reason Kept Separate |
|---|---|---|---|
| `inc_ff192b44` &amp; `inc_9b809294` | `10.10.20.14`, `10.10.20.17`, `10.10.20.10` | 0.0h | Distinct attack stages across non-overlapping execution paths |
| `inc_ff192b44` &amp; `inc_4367722f` | `10.10.20.25`, `10.10.20.23`, `10.10.20.31` | 3.4h | Same rule/tactic window exceeded (> 30 min) |
| `inc_66e15644` &amp; `inc_f4f8f1e9` | `10.10.99.1` | 42.3h | Distinct attack stages across non-overlapping execution paths |
| `inc_66e15644` &amp; `inc_59c30ca0` | `10.10.99.1` | 40.4h | Distinct attack stages across non-overlapping execution paths |
| `inc_66e15644` &amp; `inc_dfb8c001` | `10.10.99.1` | 24.6h | Same rule/tactic window exceeded (> 30 min) |
| `inc_66e15644` &amp; `inc_1792b455` | `10.10.99.1` | 24.1h | Same rule/tactic window exceeded (> 30 min) |
| `inc_66e15644` &amp; `inc_5996d302` | `10.10.99.1` | 23.6h | Same rule/tactic window exceeded (> 30 min) |
| `inc_f4f8f1e9` &amp; `inc_59c30ca0` | `10.10.99.1`, `71.54.76.98` | 1.9h | Same rule/tactic window exceeded (> 30 min) |
| `inc_f4f8f1e9` &amp; `inc_6cdfeaf8` | `10.10.99.1` | 61.7h | Distinct attack stages across non-overlapping execution paths |
| `inc_f4f8f1e9` &amp; `inc_dfb8c001` | `10.10.99.1` | 17.6h | Distinct attack stages across non-overlapping execution paths |
| `inc_f4f8f1e9` &amp; `inc_1792b455` | `10.10.99.1` | 18.1h | Distinct attack stages across non-overlapping execution paths |
| `inc_f4f8f1e9` &amp; `inc_5996d302` | `10.10.99.1` | 18.6h | Distinct attack stages across non-overlapping execution paths |
| `inc_59c30ca0` &amp; `inc_6cdfeaf8` | `10.10.99.1` | 63.6h | Distinct attack stages across non-overlapping execution paths |
| `inc_59c30ca0` &amp; `inc_dfb8c001` | `10.10.99.1` | 15.7h | Distinct attack stages across non-overlapping execution paths |
| `inc_59c30ca0` &amp; `inc_1792b455` | `10.10.99.1` | 16.3h | Distinct attack stages across non-overlapping execution paths |
| `inc_59c30ca0` &amp; `inc_5996d302` | `10.10.99.1` | 16.8h | Distinct attack stages across non-overlapping execution paths |
| `inc_9b809294` &amp; `inc_4367722f` | `10.10.10.44`, `10.10.20.16` | 38.0h | Same rule/tactic window exceeded (> 30 min) |
| `inc_6cdfeaf8` &amp; `inc_2123e0f3` | `10.10.99.1` | 27.5h | Distinct attack stages across non-overlapping execution paths |
| `inc_6cdfeaf8` &amp; `inc_88b013f3` | `10.10.99.1` | 25.5h | Distinct attack stages across non-overlapping execution paths |
| `inc_6cdfeaf8` &amp; `inc_38806d1c` | `10.10.99.1` | 23.4h | Distinct attack stages across non-overlapping execution paths |
| `inc_dfb8c001` &amp; `inc_1792b455` | `10.10.99.1`, `171.104.84.193` | 0.5h | Same rule/tactic window exceeded (> 30 min) |
| `inc_dfb8c001` &amp; `inc_5996d302` | `10.10.99.1`, `171.104.84.193` | 1.0h | Same rule/tactic window exceeded (> 30 min) |
| `inc_1792b455` &amp; `inc_5996d302` | `10.10.99.1`, `171.104.84.193` | 0.5h | Same rule/tactic window exceeded (> 30 min) |
| `inc_2123e0f3` &amp; `inc_88b013f3` | `10.10.99.1`, `78.120.139.0` | 2.0h | Same rule/tactic window exceeded (> 30 min) |
| `inc_2123e0f3` &amp; `inc_38806d1c` | `10.10.99.1`, `78.120.139.0` | 4.1h | Same rule/tactic window exceeded (> 30 min) |
| `inc_88b013f3` &amp; `inc_38806d1c` | `10.10.99.1`, `78.120.139.0` | 2.1h | Same rule/tactic window exceeded (> 30 min) |