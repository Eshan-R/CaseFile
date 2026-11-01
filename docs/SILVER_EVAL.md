> [!IMPORTANT]
> **SILVER STANDARD: agreement with independent SQL oracles on firex-10G.log. No organizer ground truth exists for this file. Not a measure of true accuracy.**

# Silver-Standard Agreement Evaluation Report

- **Dataset Evaluated**: `firex-10G.log` telemetry (clean region $\le 4,815,675,419$ bytes)
- **Evaluation Methodology**: 13 Independent SQL Oracles (Zero detection engine / manifest coupling)
- **Total Oracle Rows Extracted**: **79**
- **Total Merged Behaviors Extracted**: **27**
- **Total Active Detections Evaluated**: **38**
- **Total Active Behaviors (Collapsed)**: **29**
- **Behavior Recall (Merged)**: **96.30%** (26 / 27)
- **Row Recall (Raw Windows)**: **53.16%** (42 / 79)
- **Precision Proxy (Detection Level)**: **94.74%** (36 / 38)
- **Precision Proxy (Behavior Level)**: **96.55%** (28 / 29)
- **Label Accuracy (Exact)**: **97.22%**
- **Label Accuracy (Family)**: **97.22%**
- **Multi-Class Incidents (>= 2 Oracle Classes)**: **3**
- **Multi-Class Incidents Sharing Entity**: **3**
- **Multi-Class Incidents Ordered by Tactic**: **1**

---

## 1. Per-Class Agreement & Metric Distributions

| Oracle Class | Oracle Rows | Row Matched | Row Recall | Behaviors | Beh Matched | Beh Recall | Exact Acc | Family Acc | Metric (p50) | Metric (Max) |
|---|---|---|---|---|---|---|---|---|---|---|
| `admin_success` | 5 | 5 | 100.0% | 3 | 3 | 100.0% | 85.7% | 85.7% | 0.0 | 29.0 |
| `beacon` | 1 | 1 | 100.0% | 1 | 1 | 100.0% | 100.0% | 100.0% | 0.18 | 3.46 |
| `config_change` | 5 | 5 | 100.0% | 5 | 5 | 100.0% | 57.1% | 57.1% | 1.0 | 1.0 |
| `dns_tunnel` | 1 | 1 | 100.0% | 1 | 1 | 100.0% | 100.0% | 100.0% | 1500.0 | 1500.0 |
| `failed_admin_burst` | 1 | 0 | 0.0% | 1 | 0 | 0.0% | N/A | N/A | 3.0 | 4855.0 |
| `lateral_fanout` | 43 | 7 | 16.3% | 3 | 3 | 100.0% | 77.8% | 100.0% | 22.5 | 39.0 |
| `port_scan` | 2 | 2 | 100.0% | 2 | 2 | 100.0% | 100.0% | 100.0% | 1.0 | 1024.0 |
| `slow_stuffing_24` | 2 | 2 | 100.0% | 1 | 1 | 100.0% | 100.0% | 100.0% | 75.0 | 956.0 |
| `staged_exfil` | 2 | 2 | 100.0% | 2 | 2 | 100.0% | 100.0% | 100.0% | 12.75 | 41.17 |
| `virus_detected_not_blocked` | 3 | 3 | 100.0% | 1 | 1 | 100.0% | 100.0% | 100.0% | 1.0 | 1.0 |
| `vpn_impossible_travel` | 6 | 6 | 100.0% | 2 | 2 | 100.0% | 100.0% | 100.0% | 12.24 | 31.78 |
| `web_payload` | 8 | 8 | 100.0% | 5 | 5 | 100.0% | 100.0% | 100.0% | 32.5 | 73.0 |

---

## 2. Suppressed Population Windows

> [!NOTE]

> In accordance with Rule 7 (Population Guard), any time window where $\ge 10$ distinct sources trip or $\ge 30\%$ of all active internal hosts trip the same oracle condition simultaneously is flagged as a sensor/network population anomaly and excluded from the accepted answer key.

| Oracle | Window Start | Duration | Tripping Entities | Status / Reason |
|---|---|---|---|---|
| `failed_admin_burst` | 2026-10-30T03:10:00+00:00 | 600s | 157 | **SUPPRESSED** (Population artifact: 157 distinct sources in window >= 10) |
| `flood` | 2026-10-30T03:18:00+00:00 | 120s | 231 | **SUPPRESSED** (1540.0% of active internal hosts) |

---

## 3. Unconfirmed Detections (Precision Proxy)

> [!NOTE]

> Detections in our database that did not match an independent SQL oracle row. These represent a precision proxy and are **unconfirmed detections**, NOT ground-truth false alarms (since oracles cover specific behavioral patterns, not the entire detection rule surface).

| Rule ID | Unconfirmed Firing Count |
|---|---|
| `web-shell-upload-path` | 2 |

---

## 4. Missed Oracle Rows (Top Opportunities for Detection Tuning)

| # | Oracle ID | Expected Technique | Tactic | Entity | Window Start | Window End | Metric | Sample Evidence Event IDs |
|---|---|---|---|---|---|---|---|---|
| 1 | `failed_admin_burst` | `T1110.001` | Credential Access | `15.199.16.197` | 2026-10-27T07:30:00+00:00 | 2026-10-27T07:38:37+00:00 | 1719.0 | ev_0_1228570175<br>ev_0_1228571325 |
| 2 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T11:00:49+00:00 | 2026-10-27T11:59:25+00:00 | 11.0 | ev_0_1291473041<br>ev_0_1292018143 |
| 3 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T12:00:54+00:00 | 2026-10-27T12:59:07+00:00 | 13.0 | ev_0_1320632976<br>ev_0_1321293519 |
| 4 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T13:00:18+00:00 | 2026-10-27T13:59:12+00:00 | 13.0 | ev_0_1341876888<br>ev_0_1342229029 |
| 5 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T14:00:34+00:00 | 2026-10-27T14:58:33+00:00 | 15.0 | ev_0_1358164688<br>ev_0_1358552220 |
| 6 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T15:00:05+00:00 | 2026-10-27T15:59:30+00:00 | 16.0 | ev_0_1372119808<br>ev_0_1372445053 |
| 7 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T16:00:11+00:00 | 2026-10-27T16:59:06+00:00 | 16.0 | ev_0_1385154509<br>ev_0_1385446265 |
| 8 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T17:00:45+00:00 | 2026-10-27T17:59:50+00:00 | 18.0 | ev_0_1396187867<br>ev_0_1396426807 |
| 9 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T18:00:31+00:00 | 2026-10-27T18:59:17+00:00 | 18.0 | ev_0_1405528959<br>ev_0_1405732342 |
| 10 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T19:00:19+00:00 | 2026-10-27T19:59:38+00:00 | 19.0 | ev_0_1413364500<br>ev_0_1413479247 |
| 11 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T20:00:54+00:00 | 2026-10-27T20:58:37+00:00 | 21.0 | ev_0_1419382602<br>ev_0_1419475350 |
| 12 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T21:00:14+00:00 | 2026-10-27T21:59:08+00:00 | 21.0 | ev_0_1423626748<br>ev_0_1423684621 |
| 13 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-27T22:00:00+00:00 | 2026-10-27T22:59:38+00:00 | 21.0 | ev_0_1427553425<br>ev_0_1427663980 |
| 14 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-28T01:00:17+00:00 | 2026-10-28T01:59:20+00:00 | 26.0 | ev_0_1448949071<br>ev_0_1449112585 |
| 15 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-28T02:00:19+00:00 | 2026-10-28T02:59:03+00:00 | 23.0 | ev_0_1467538304<br>ev_0_1468165992 |
| 16 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-28T03:00:32+00:00 | 2026-10-28T03:59:11+00:00 | 22.0 | ev_0_1482674181<br>ev_0_1482836562 |
| 17 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-28T04:00:45+00:00 | 2026-10-28T04:59:47+00:00 | 28.0 | ev_0_1488513111<br>ev_0_1488575328 |
| 18 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-28T05:00:27+00:00 | 2026-10-28T05:59:17+00:00 | 27.0 | ev_0_1492791200<br>ev_0_1492906885 |
| 19 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-28T06:00:41+00:00 | 2026-10-28T06:59:13+00:00 | 25.0 | ev_0_1496817311<br>ev_0_1496882969 |
| 20 | `lateral_fanout` | `T1021.002` | Lateral Movement | `10.10.10.44` | 2026-10-28T07:00:46+00:00 | 2026-10-28T07:59:55+00:00 | 27.0 | ev_0_1501166780<br>ev_0_1501224371 |

---

## 5. Confusion List (Active Detections vs Matched Oracle Expectations)

| Oracle Class | Expected Technique | Emitted Technique | Firing Count |
|---|---|---|---|
| `config_change` | `T1098` | `T1562.002` | 1 |