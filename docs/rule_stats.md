# Detection Rules Execution Statistics

- **Total Rules Configured:** 30
- **Total Raw Detections Generated:** 0
- **Active (Unsuppressed) Detections:** 0
- **Suppressed Detections (Background / Artifacts):** 0
- **Total Engine Runtime:** 1.15s

| Rule ID | Rule Name | Type | Technique | Tactic | Stage | Runtime (s) | Matches | Suppressed | Distinct Sources | Prevalence (%) | Entropy | Decision | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `account-discovery` | Account Discovery Activity | `match` | `T1087` | discovery | Discovery | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | SKIPPED | Format does not apply (['windows_event', 'edr']) |
| `admin-login-external` | External Administrative Authentication | `sql` | `T1078.001` | initial_access | Initial Access | 0.009 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `beaconing` | Command and Control Periodic Beaconing | `sql` | `T1071.001` | command_and_control | Command and Control | 0.010 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `brute-force-failed-logins` | High-Velocity Authentication Failures | `threshold` | `T1110.001` | credential_access | Exploitation | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | DISABLED | Disabled (superseded by failed-admin-burst) |
| `config-logging-disabled` | Security Logging Impairment or Frequent Edits | `sql` | `T1562.002` | defense_evasion | Defense Evasion | 0.054 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `credential-dumping-indicators` | OS Credential Dumping Indicators | `match` | `T1003.001` | credential_access | Credential Access | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | SKIPPED | Format does not apply (['windows_event', 'edr']) |
| `dns-amplification` | DNS Reflection Amplification Flood | `sql` | `T1498.002` | impact | Impact | 0.057 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `dns-tunnel` | DNS Tunneling and Data Exfiltration | `sql` | `T1071.004` | exfiltration | Exfiltration | 0.056 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `dns-tunneling` | DNS Tunneling Query | `match` | `T1071.004` | command_and_control | Command and Control | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | DISABLED | Disabled (superseded by dns-tunnel) |
| `failed-admin-burst` | Failed Admin Authentication Burst | `sql` | `T1110.001` | credential_access | Exploitation | 0.014 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `http-flood` | HTTP Distributed Denial of Service Flood | `sql` | `T1498.001` | impact | Impact | 0.042 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | Error: Catalog Error: Table with name events does not exist!
Did you mean "patterns"?
LINE 16: FROM events
              ^ |
| `large-outbound-transfer` | Large Outbound Data Transfer | `match` | `T1048.002` | exfiltration | Exfiltration | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | DISABLED | Disabled (superseded by staged-exfil) |
| `lateral-fanout` | Internal Lateral Service Fanout | `sql` | `T1021.002` | lateral_movement | Lateral Movement | 0.057 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `login-success-after-failures` | Login Success Following Credential Access Failures | `sql` | `T1078.001` | initial_access | Initial Access | 0.022 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `malware-detection` | Malware Detection | `match` | `T1204.002` | execution | Execution | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | SKIPPED | Format does not apply (['windows_event', 'edr']) |
| `port-scan` | Network Port Enumeration Scan | `sql` | `T1046` | discovery | Discovery | 0.102 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | Error: Catalog Error: Table with name events does not exist!
Did you mean "pg_views"?
LINE 16: FROM events
              ^ |
| `remote-logon-between-hosts` | Remote Logon Between Internal Hosts | `match` | `T1021.001` | lateral_movement | Lateral Movement | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | DISABLED | Disabled (superseded by lateral-fanout) |
| `rogue-admin-account` | Ephemeral Rogue Administrator Account | `sql` | `T1136.001` | persistence | Persistence | 0.075 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `slow-credential-stuffing` | Distributed Slow Credential Stuffing (/24 Subnet) | `sql` | `T1110.004` | credential_access | Exploitation | 0.021 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `staged-exfil` | Staged Asymmetric Data Exfiltration | `sql` | `T1048.002` | exfiltration | Exfiltration | 0.011 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `syn-flood` | SYN Flood Denial of Service | `sql` | `T1498.001` | impact | Impact | 0.148 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | Error: Catalog Error: Table with name events does not exist!
Did you mean "pg_views"?
LINE 16: FROM events
              ^ |
| `targeted-web-attack` | Targeted Web Application Attack | `match` | `T1190` | initial_access | Exploitation | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | DISABLED | Disabled (superseded by web-payload-sqli, web-payload-xss, web-payload-cmdi, web-payload-traversal) |
| `valid-account-misuse` | Valid Account External Logon | `match` | `T1078.001` | initial_access | Initial Access | 0.000 | 0 | 0 | 0 | 0.00% | 0.0000 | DISABLED | Disabled (superseded by admin-login-external, login-success-after-failures) |
| `virus-detected-not-blocked` | Malicious File Detected Without Block | `sql` | `T1105` | command_and_control | Command and Control | 0.013 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `vpn-impossible-travel` | Impossible Geographic Travel via VPN | `sql` | `T1078.004` | initial_access | Initial Access | 0.111 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | Error: Catalog Error: Table with name events does not exist!
Did you mean "pg_views"?
LINE 13:     FROM events
                  ^ |
| `web-payload-cmdi` | Web Command Injection Attack | `sql` | `T1190` | execution | Execution | 0.079 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `web-payload-sqli` | Web SQL Injection Attack | `sql` | `T1190` | initial_access | Exploitation | 0.095 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | Error: Catalog Error: Table with name events does not exist!
Did you mean "pg_views"?
LINE 12:     FROM events
                  ^ |
| `web-payload-traversal` | Web Path Traversal Attack | `sql` | `T1190` | discovery | Discovery | 0.059 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `web-payload-xss` | Web Cross-Site Scripting Attack | `sql` | `T1189` | execution | Execution | 0.056 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
| `web-shell-upload-path` | Web Shell Upload Path Access | `sql` | `T1505.003` | persistence | Persistence | 0.061 | 0 | 0 | 0 | 0.00% | 0.0000 | ACTIVE | OK |
