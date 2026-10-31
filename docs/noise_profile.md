# Security Log Noise & Detection Signals Profile
## 1. IPS Attack Signatures (Uniform vs Targeted)
| Signature | Alert Count | Distinct Sources | Nature |
|---|---|---|---|
| Eicar.Virus.Test.File | 1,496 | 914 | Broad Background Noise |
| Mirai.Botnet.Command.Traffic | 1,469 | 892 | Broad Background Noise |
| Fortinet.FortiOS.SSLVPN.Path.Traversal | 1,463 | 913 | Broad Background Noise |
| SSH.Connection.Brute.Force | 1,458 | 894 | Broad Background Noise |
| DNS.Zone.Transfer.Request | 1,453 | 888 | Broad Background Noise |
| Generic.SQL.Injection.Attempt | 1,450 | 897 | Broad Background Noise |
| Backdoor.Cobalt.Strike.Beacon | 1,440 | 919 | Broad Background Noise |
| Citrix.ADC.Gateway.Directory.Traversal | 1,439 | 902 | Broad Background Noise |
| Apache.Log4j.Error.Log.Remote.Code.Execution | 1,422 | 883 | Broad Background Noise |
| HTTP.Server.Authorization.Buffer.Overflow | 1,422 | 900 | Broad Background Noise |
| MS.Windows.HTTP.sys.Request.Handling | 1,410 | 895 | Broad Background Noise |
| PHP.CGI.Query.String.Parameter.Handling | 1,402 | 874 | Broad Background Noise |
| MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure | 1,399 | 872 | Broad Background Noise |
| Linux.Kernel.Netfilter.Privilege.Escalation | 1,394 | 863 | Broad Background Noise |
| ZeroLogon.Netlogon.Privilege.Escalation | 1,387 | 876 | Broad Background Noise |
| Web.Server.Password.Files.Access | 1,384 | 894 | Broad Background Noise |
| Oracle.WebLogic.Server.wls9-async.Deserialization | 1,383 | 875 | Broad Background Noise |
| VMware.vCenter.Server.File.Upload | 1,375 | 850 | Broad Background Noise |
| RDP.Connection.Brute.Force | 1,350 | 870 | Broad Background Noise |
| Atlassian.Confluence.OGNL.Injection | 1,311 | 817 | Broad Background Noise |
| Apache.security.SSL-protection | 707 | 552 | Broad Background Noise |
| Citrix.security.AD-Prevent-Insider-Access | 670 | 520 | Broad Background Noise |
| Splunk.security.VW | 654 | 523 | Broad Background Noise |
| Splunk.security.SA | 650 | 517 | Broad Background Noise |
| Apache.security.Protection | 650 | 540 | Broad Background Noise |

## 2. Failed Admin Logins (Top 10-Minute Bursts)
| Source IP | Window (UTC) | Failed Attempts | Note |
|---|---|---|---|
| 87.251.64.122 | 2026-10-23 16:30:00 | 25 | Planted Brute Force Burst |
| 104.207.63.107 | 2026-10-24 16:00:00 | 23 | Planted Brute Force Burst |
| 77.91.71.25 | 2026-10-24 16:40:00 | 22 | Planted Brute Force Burst |
| 45.74.28.225 | 2026-10-24 16:10:00 | 22 | Planted Brute Force Burst |
| 211.206.124.40 | 2026-10-23 16:00:00 | 22 | Planted Brute Force Burst |
| 45.74.28.246 | 2026-10-23 16:40:00 | 22 | Planted Brute Force Burst |
| 87.251.64.124 | 2026-10-24 16:50:00 | 22 | Planted Brute Force Burst |
| 77.91.71.25 | 2026-10-24 16:20:00 | 21 | Planted Brute Force Burst |
| 45.74.28.215 | 2026-10-24 16:10:00 | 21 | Planted Brute Force Burst |
| 45.74.28.229 | 2026-10-24 16:10:00 | 21 | Planted Brute Force Burst |
| 45.74.28.175 | 2026-10-24 16:10:00 | 21 | Planted Brute Force Burst |
| 185.136.15.80 | 2026-10-23 16:20:00 | 21 | Planted Brute Force Burst |
| 216.26.238.23 | 2026-10-24 16:50:00 | 21 | Planted Brute Force Burst |
| 45.74.28.183 | 2026-10-23 16:40:00 | 21 | Planted Brute Force Burst |
| 45.74.28.208 | 2026-10-23 15:20:00 | 21 | Planted Brute Force Burst |
| 185.136.15.66 | 2026-10-24 16:40:00 | 21 | Planted Brute Force Burst |
| 45.74.28.181 | 2026-10-25 16:10:00 | 21 | Planted Brute Force Burst |
| 45.74.28.232 | 2026-10-23 16:50:00 | 20 | Planted Brute Force Burst |
| 45.74.28.242 | 2026-10-23 16:30:00 | 20 | Planted Brute Force Burst |
| 65.111.6.208 | 2026-10-24 16:20:00 | 20 | Planted Brute Force Burst |

## 3. Port Scan Signals (Distinct Ports/IPs per Minute)
| Source IP | Minute Bucket | Distinct Dst Ports | Distinct Dst IPs | Total Events |
|---|---|---|---|---|

## 4. High-Frequency Connections (Beacon Candidates)
| Source IP | Destination IP | Port | Event Count | Mean Bytes Out | StdDev Bytes Out |
|---|---|---|---|---|---|
| 10.10.10.88 | 8.8.8.8 | 53 | 1,500 | 109.1 | 12.0 |
| 10.10.10.112 | 198.79.124.52 | 443 | 776 | 559.6 | 28.3 |
| 131.228.119.59 | 10.10.20.20 | 443 | 220 | 1117.9 | 422.8 |

## 5. DNS Query Name Lengths & Long Domains
*(Field holding DNS query name: `hostname`)*

| Domain Hostname | Length | Total Queries | Distinct Sources |
|---|---|---|---|
| `fjbj626mmqg5mocj4654ky71thmy7kc3kwedyaz0.doqotobitum.com` | 56 | 1 | 1 |
| `atxx2r2t1fex3ru9o364mwez70thrzlqjyniznme.doqotobitum.com` | 56 | 1 | 1 |
| `thel95wm08oqfj0269u5yun1u9w5dfnzh0tlo9hz.doqotobitum.com` | 56 | 1 | 1 |
| `mvcy5ogbu02avn9amyr6md59da352vngc3x8a4ax.doqotobitum.com` | 56 | 1 | 1 |
| `dg2kew28wb9lrc0aa2svunscdieq00333h9goynh.doqotobitum.com` | 56 | 1 | 1 |
| `lxp8xx30ammj7vew3mu31mz7tywpcmqswbhchflh.doqotobitum.com` | 56 | 1 | 1 |
| `3bp4fdpjw4qz45elfbw8hmssxbiob0445zuxk10u.doqotobitum.com` | 56 | 1 | 1 |
| `6jmxxmcnmods6mrx0st5du5la8hge58bfnovmqqx.doqotobitum.com` | 56 | 1 | 1 |
| `fdail3q27peeyfiomhzgvwfpaizqo2tclz59fp2n.doqotobitum.com` | 56 | 1 | 1 |
| `ipj90ormpuo93qbrlz4alltlrhe71kxgo7i5f6os.doqotobitum.com` | 56 | 1 | 1 |
| `ruob17fx6z622p9492w3ufsi7nu7thqt7lp3781f.doqotobitum.com` | 56 | 1 | 1 |
| `j7429cf7sw8s40km4ajl8frya2kooizlu27hh2yt.doqotobitum.com` | 56 | 1 | 1 |
| `w41kii6wfpqj2yg4izaakn1hdaqhbt59o35ew87m.doqotobitum.com` | 56 | 1 | 1 |
| `vpk3mz9k3ihbidkdqsy7ej2t4dez86of0i7uppcs.doqotobitum.com` | 56 | 1 | 1 |
| `upr4b37hfbw1a349aspndhkfpr4nbexy8brh0xro.doqotobitum.com` | 56 | 1 | 1 |
| `xvsddc8mmnmwbwz7okfukhl6thq4g56mppznmc6t.doqotobitum.com` | 56 | 1 | 1 |
| `om4irs98p9i04e7b94a1no4iygnnc22ood9q4yt4.doqotobitum.com` | 56 | 1 | 1 |
| `0de5842i6y411venh4zvbu9fl59bqj7gve8mvouf.doqotobitum.com` | 56 | 1 | 1 |
| `6845ltjlstj9uyotwtwa6edq71l7bzkawd9n06pr.doqotobitum.com` | 56 | 1 | 1 |
| `2u88iffp7j4xucrs3j4z6wsu5dl48o357sor2j3w.doqotobitum.com` | 56 | 1 | 1 |

## 6. Daily Bytes Out & Sent/Received Ratio
| Source IP | Date | Total Sent (Bytes) | Total Rcvd (Bytes) | Sent/Rcvd Ratio |
|---|---|---|---|---|
| 10.10.20.103 | 2026-10-24 | 195,918,496 | 1,297,382,104 | 0.15 |
| 10.10.20.214 | 2026-10-24 | 195,579,767 | 1,464,619,055 | 0.13 |
| 10.10.99.111 | 2026-10-24 | 189,764,335 | 1,485,597,546 | 0.13 |
| 10.10.40.204 | 2026-10-24 | 188,946,211 | 1,531,114,006 | 0.12 |
| 10.10.20.138 | 2026-10-24 | 182,637,927 | 1,403,850,236 | 0.13 |
| 10.10.10.229 | 2026-10-24 | 182,326,663 | 1,512,551,991 | 0.12 |
| 10.10.40.88 | 2026-10-24 | 181,297,645 | 1,269,763,650 | 0.14 |
| 10.10.99.174 | 2026-10-24 | 180,557,588 | 1,415,169,441 | 0.13 |
| 10.10.99.38 | 2026-10-24 | 180,000,265 | 1,414,287,560 | 0.13 |
| 10.10.40.25 | 2026-10-24 | 179,216,251 | 1,347,212,465 | 0.13 |
| 10.10.50.165 | 2026-10-24 | 179,123,805 | 1,392,556,030 | 0.13 |
| 10.10.99.122 | 2026-10-24 | 177,381,859 | 1,130,914,429 | 0.16 |
| 10.10.99.181 | 2026-10-24 | 176,533,019 | 1,347,669,384 | 0.13 |
| 10.10.10.129 | 2026-10-24 | 176,215,629 | 1,308,288,640 | 0.13 |
| 10.10.30.183 | 2026-10-24 | 175,992,552 | 1,650,940,146 | 0.11 |
| 10.10.20.87 | 2026-10-24 | 175,608,506 | 1,405,414,441 | 0.12 |
| 10.10.40.206 | 2026-10-24 | 174,912,107 | 1,023,302,543 | 0.17 |
| 10.10.20.99 | 2026-10-24 | 174,401,138 | 1,238,080,098 | 0.14 |
| 10.10.20.97 | 2026-10-24 | 174,231,195 | 985,498,212 | 0.18 |
| 10.10.99.87 | 2026-10-24 | 173,186,918 | 1,258,181,360 | 0.14 |

## 7. Lateral Movement Signals (Ports 445 & 3389 Fan-out)
| Source IP | Target Port | Distinct Targets | Connection Attempts |
|---|---|---|---|
| 10.10.10.63 | 445 | 15 | 90 |
| 10.10.10.63 | 3389 | 15 | 90 |

## 8. Web Exploitation & URL Pattern Counts
| Attack Vector | Detected Count |
|---|---|
| SQL Keywords (union/select/drop) | 94 |
| Path Traversal (`../`) | 0 |
| PHP Wrappers (`php://`) | 0 |
| Script Tags (`<script`) | 0 |
| Shell Metacharacters (`;`, `&`, `|`, `$`) | 32 |
| **Blocked Web Requests** | **0** |
| **Allowed Web Requests** | **0** |

## 9. Event Logs (type='event') Distribution
| Log ID | Description | Count |
|---|---|---|
| 0100032002 | Admin login failed | 261,687 |
| 0101037141 | None | 27,890 |
| 0100032101 | DHCP statistics | 17,178 |
| 0105048901 | HA device status | 17,147 |
| 0100032101 | Performance statistics | 17,061 |
| 0100032101 | None | 17,059 |
| 0102043008 | DHCP Ack log | 17,042 |
| 0113022923 | SD-WAN health-check status | 16,991 |
| 0100044546 | Attribute configured | 3 |
| 0100032001 | Admin login successful | 1 |
