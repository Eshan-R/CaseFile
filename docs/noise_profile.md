# Security Log Noise & Detection Signals Profile
## 1. IPS Attack Signatures (Uniform vs Targeted)
| Signature | Alert Count | Distinct Sources | Nature |
|---|---|---|---|
| Eicar.Virus.Test.File | 7,035 | 1,375 | Broad Background Noise |
| Fortinet.FortiOS.SSLVPN.Path.Traversal | 7,007 | 1,380 | Broad Background Noise |
| Apache.Log4j.Error.Log.Remote.Code.Execution | 6,943 | 1,375 | Broad Background Noise |
| Backdoor.Cobalt.Strike.Beacon | 6,892 | 1,381 | Broad Background Noise |
| SSH.Connection.Brute.Force | 6,884 | 1,374 | Broad Background Noise |
| MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure | 6,870 | 1,374 | Broad Background Noise |
| Citrix.ADC.Gateway.Directory.Traversal | 6,862 | 1,375 | Broad Background Noise |
| MS.Windows.HTTP.sys.Request.Handling | 6,847 | 1,380 | Broad Background Noise |
| Generic.SQL.Injection.Attempt | 6,847 | 1,370 | Broad Background Noise |
| DNS.Zone.Transfer.Request | 6,843 | 1,377 | Broad Background Noise |
| Atlassian.Confluence.OGNL.Injection | 6,835 | 1,377 | Broad Background Noise |
| Web.Server.Password.Files.Access | 6,823 | 1,376 | Broad Background Noise |
| Mirai.Botnet.Command.Traffic | 6,813 | 1,374 | Broad Background Noise |
| PHP.CGI.Query.String.Parameter.Handling | 6,800 | 1,377 | Broad Background Noise |
| ZeroLogon.Netlogon.Privilege.Escalation | 6,799 | 1,380 | Broad Background Noise |
| Oracle.WebLogic.Server.wls9-async.Deserialization | 6,785 | 1,381 | Broad Background Noise |
| Linux.Kernel.Netfilter.Privilege.Escalation | 6,775 | 1,374 | Broad Background Noise |
| VMware.vCenter.Server.File.Upload | 6,747 | 1,372 | Broad Background Noise |
| RDP.Connection.Brute.Force | 6,646 | 1,373 | Broad Background Noise |
| HTTP.Server.Authorization.Buffer.Overflow | 6,634 | 1,372 | Broad Background Noise |
| MikroTik.security.strongswiptunnel | 3,208 | 1,248 | Broad Background Noise |
| Apache.security.SSL-protection | 3,144 | 1,246 | Broad Background Noise |
| SolarWinds.security.AD-Secure-Presence | 3,124 | 1,241 | Broad Background Noise |
| Splunk.security.DNS | 3,113 | 1,244 | Broad Background Noise |
| SolarWinds.security.AD-Insider-Encryption | 3,091 | 1,236 | Broad Background Noise |

## 2. Failed Admin Logins (Top 10-Minute Bursts)
| Source IP | Window (UTC) | Failed Attempts | Note |
|---|---|---|---|
| 173.243.132.130 | 2026-10-30 08:40:00 | 4,855 | Planted Brute Force Burst |
| 87.251.64.126 | 2026-10-30 08:40:00 | 4,849 | Planted Brute Force Burst |
| 45.74.28.185 | 2026-10-30 08:40:00 | 4,843 | Planted Brute Force Burst |
| 118.130.231.254 | 2026-10-30 08:40:00 | 4,842 | Planted Brute Force Burst |
| 45.74.28.239 | 2026-10-30 08:40:00 | 4,833 | Planted Brute Force Burst |
| 1.213.180.29 | 2026-10-30 08:40:00 | 4,828 | Planted Brute Force Burst |
| 104.207.45.25 | 2026-10-30 08:40:00 | 4,824 | Planted Brute Force Burst |
| 45.74.28.232 | 2026-10-30 08:40:00 | 4,824 | Planted Brute Force Burst |
| 65.111.2.114 | 2026-10-30 08:40:00 | 4,815 | Planted Brute Force Burst |
| 185.136.15.80 | 2026-10-30 08:40:00 | 4,807 | Planted Brute Force Burst |
| 45.74.28.226 | 2026-10-30 08:40:00 | 4,805 | Planted Brute Force Burst |
| 45.74.28.249 | 2026-10-30 08:40:00 | 4,795 | Planted Brute Force Burst |
| 45.74.28.188 | 2026-10-30 08:40:00 | 4,795 | Planted Brute Force Burst |
| 45.74.28.172 | 2026-10-30 08:40:00 | 4,794 | Planted Brute Force Burst |
| 45.74.28.191 | 2026-10-30 08:40:00 | 4,790 | Planted Brute Force Burst |
| 45.74.28.212 | 2026-10-30 08:40:00 | 4,790 | Planted Brute Force Burst |
| 45.74.28.211 | 2026-10-30 08:40:00 | 4,787 | Planted Brute Force Burst |
| 209.50.165.143 | 2026-10-30 08:40:00 | 4,785 | Planted Brute Force Burst |
| 45.74.28.247 | 2026-10-30 08:40:00 | 4,785 | Planted Brute Force Burst |
| 45.74.28.182 | 2026-10-30 08:40:00 | 4,781 | Planted Brute Force Burst |

## 3. Port Scan Signals (Distinct Ports/IPs per Minute)
| Source IP | Minute Bucket | Distinct Dst Ports | Distinct Dst IPs | Total Events |
|---|---|---|---|---|
| 194.102.163.167 | 2026-10-27 21:08:00 | 568 | 1 | 568 |
| 10.10.40.223 | 2026-10-30 08:48:00 | 433 | 2646 | 2646 |
| 10.10.20.30 | 2026-10-30 08:48:00 | 427 | 2582 | 2582 |
| 10.10.10.229 | 2026-10-30 08:48:00 | 424 | 2608 | 2608 |
| 10.10.10.202 | 2026-10-30 08:48:00 | 421 | 2603 | 2603 |
| 10.10.40.93 | 2026-10-30 08:48:00 | 420 | 2704 | 2704 |
| 10.10.20.67 | 2026-10-30 08:48:00 | 419 | 2676 | 2676 |
| 10.10.50.101 | 2026-10-30 08:48:00 | 419 | 2671 | 2671 |
| 10.10.50.207 | 2026-10-30 08:48:00 | 419 | 2643 | 2643 |
| 10.10.40.156 | 2026-10-30 08:48:00 | 419 | 2637 | 2637 |
| 10.10.50.136 | 2026-10-30 08:48:00 | 419 | 2621 | 2621 |
| 10.10.20.77 | 2026-10-30 08:48:00 | 419 | 2613 | 2613 |
| 10.10.50.87 | 2026-10-30 08:48:00 | 419 | 2553 | 2553 |
| 10.10.50.221 | 2026-10-30 08:48:00 | 418 | 2598 | 2598 |
| 10.10.99.220 | 2026-10-30 08:48:00 | 418 | 2578 | 2578 |
| 10.10.50.38 | 2026-10-30 08:48:00 | 417 | 2607 | 2607 |
| 10.10.30.26 | 2026-10-30 08:48:00 | 417 | 2592 | 2592 |
| 10.10.10.42 | 2026-10-30 08:48:00 | 417 | 2572 | 2572 |
| 10.10.20.229 | 2026-10-30 08:48:00 | 416 | 2657 | 2657 |
| 10.10.10.185 | 2026-10-30 08:48:00 | 415 | 2659 | 2659 |

## 4. High-Frequency Connections (Beacon Candidates)
| Source IP | Destination IP | Port | Event Count | Mean Bytes Out | StdDev Bytes Out |
|---|---|---|---|---|---|
| 10.10.20.31 | 7.93.184.183 | 443 | 2,000 | 20536.8 | 864.6 |
| 10.10.10.112 | 198.79.124.52 | 443 | 1,612 | 559.5 | 27.8 |
| 10.10.10.88 | 8.8.8.8 | 53 | 1,500 | 109.1 | 12.0 |
| 10.10.10.118 | 7.154.5.35 | 443 | 803 | 10529.8 | 9997.1 |
| 32.127.48.11 | 10.10.20.20 | 443 | 700 | 17771.2 | 6803.6 |
| 131.228.119.59 | 10.10.20.20 | 443 | 220 | 1117.9 | 422.8 |

## 5. DNS Query Name Lengths & Long Domains
*(Field holding DNS query name: `hostname`)*

| Domain Hostname | Length | Total Queries | Distinct Sources |
|---|---|---|---|
| `9hrdz764h5lc89p2j3zaratiiom507zgsx7shogz.doqotobitum.com` | 56 | 1 | 1 |
| `7pbxsy585kiv7kjn1oxxzsheolq5tjhvfvnnyr8s.doqotobitum.com` | 56 | 1 | 1 |
| `eqzutrn0qlt6zusv8nl466pqwfqnmlj6av1f5cs5.doqotobitum.com` | 56 | 1 | 1 |
| `wf6bva0j7385i0u3sghogrq9dg38dq96mwhwkyrz.doqotobitum.com` | 56 | 1 | 1 |
| `jey2jub053gguhb9p7eo81ohfo2gq01h1xv0kj70.doqotobitum.com` | 56 | 1 | 1 |
| `k32d5r4486shzd0ep3zhhbfjbvtfz2murb5y7e06.doqotobitum.com` | 56 | 1 | 1 |
| `bz79xkz0a4gdl97oigunx6b4jq87r80ec4mujrs3.doqotobitum.com` | 56 | 1 | 1 |
| `dnjdeywbnl7ffarsgic3k4gcs7jyljzwi4buia79.doqotobitum.com` | 56 | 1 | 1 |
| `lptoi43tgtv8wbi5xspcpalltdpaehb4ekvib58y.doqotobitum.com` | 56 | 1 | 1 |
| `yi1ao57i7o8o0d851llr7yju9bm46ofupwkxa7mk.doqotobitum.com` | 56 | 1 | 1 |
| `hnwflbs96yjdjbdt12es8lo11d2f3qkvif5z78g3.doqotobitum.com` | 56 | 1 | 1 |
| `7xox1p63szlkjcg6ic72d0qjz48igp6qjtrxaf0w.doqotobitum.com` | 56 | 1 | 1 |
| `t5d1y9mhhbeo7578mag1f3w2h0cs9l3h968dpt1j.doqotobitum.com` | 56 | 1 | 1 |
| `gciamx41zwjjs89wck95h6j88v1m2jvvbhsj69rz.doqotobitum.com` | 56 | 1 | 1 |
| `gusju3kowru2yuaemnzhx7ulz3va7asysohfdhov.doqotobitum.com` | 56 | 1 | 1 |
| `6qyuscdbb8s4f8p8i45zdbt957sh1qgm2ycwo3by.doqotobitum.com` | 56 | 1 | 1 |
| `dcffbrd4pu194ead1qk5yapx2o3900318i6inagb.doqotobitum.com` | 56 | 1 | 1 |
| `f7jmc3snhvxodtp4j8djkq9k6elrrvc3uzck2i3o.doqotobitum.com` | 56 | 1 | 1 |
| `hkk4auyiq2nypr68i1b9rlxbigv2htd1gx8uuapo.doqotobitum.com` | 56 | 1 | 1 |
| `ombn7f0r8pyy7tb40l4o8blpunsjn1n8jlkbm6te.doqotobitum.com` | 56 | 1 | 1 |

## 6. Daily Bytes Out & Sent/Received Ratio
| Source IP | Date | Total Sent (Bytes) | Total Rcvd (Bytes) | Sent/Rcvd Ratio |
|---|---|---|---|---|
| 10.10.10.128 | 2026-10-30 | 1,199,835,279 | 9,151,157,573 | 0.13 |
| 10.10.30.101 | 2026-10-30 | 1,191,019,405 | 9,016,048,541 | 0.13 |
| 10.10.99.181 | 2026-10-30 | 1,190,574,831 | 8,879,688,250 | 0.13 |
| 10.10.50.204 | 2026-10-30 | 1,170,659,438 | 8,565,362,604 | 0.14 |
| 10.10.50.80 | 2026-10-30 | 1,166,950,142 | 8,689,273,935 | 0.13 |
| 10.10.20.203 | 2026-10-30 | 1,158,599,083 | 8,590,319,372 | 0.13 |
| 10.10.99.171 | 2026-10-30 | 1,156,471,109 | 9,001,235,287 | 0.13 |
| 10.10.40.151 | 2026-10-30 | 1,146,930,203 | 8,522,849,397 | 0.13 |
| 10.10.20.59 | 2026-10-30 | 1,145,387,670 | 8,449,252,763 | 0.14 |
| 10.10.99.132 | 2026-10-30 | 1,145,107,762 | 8,872,254,072 | 0.13 |
| 10.10.40.87 | 2026-10-30 | 1,144,453,482 | 8,879,381,440 | 0.13 |
| 10.10.50.34 | 2026-10-30 | 1,135,728,383 | 8,074,519,003 | 0.14 |
| 10.10.30.230 | 2026-10-30 | 1,135,248,627 | 8,577,101,097 | 0.13 |
| 10.10.30.82 | 2026-10-30 | 1,134,202,198 | 8,148,686,572 | 0.14 |
| 10.10.50.227 | 2026-10-30 | 1,132,384,999 | 8,067,771,663 | 0.14 |
| 10.10.30.59 | 2026-10-30 | 1,131,680,037 | 8,026,081,302 | 0.14 |
| 10.10.99.201 | 2026-10-30 | 1,129,422,567 | 8,846,448,102 | 0.13 |
| 10.10.50.43 | 2026-10-30 | 1,127,764,590 | 8,545,027,919 | 0.13 |
| 10.10.20.106 | 2026-10-30 | 1,126,547,656 | 8,107,535,514 | 0.14 |
| 10.10.40.162 | 2026-10-30 | 1,124,518,172 | 8,417,295,260 | 0.13 |

## 7. Lateral Movement Signals (Ports 445 & 3389 Fan-out)
| Source IP | Target Port | Distinct Targets | Connection Attempts |
|---|---|---|---|
| 10.10.10.44 | 445 | 60 | 2,400 |
| 10.10.10.63 | 3389 | 15 | 90 |
| 10.10.10.63 | 445 | 15 | 90 |

## 8. Web Exploitation & URL Pattern Counts
| Attack Vector | Detected Count |
|---|---|
| SQL Keywords (union/select/drop) | 119 |
| Path Traversal (`../`) | 27 |
| PHP Wrappers (`php://`) | 0 |
| Script Tags (`<script`) | 0 |
| Shell Metacharacters (`;`, `&`, `|`, `$`) | 41 |
| **Blocked Web Requests** | **0** |
| **Allowed Web Requests** | **0** |

## 9. Event Logs (type='event') Distribution
| Log ID | Description | Count |
|---|---|---|
| 0100032002 | Admin login failed | 1,272,524 |
| 0101037141 | None | 136,303 |
| 0113022923 | SD-WAN health-check status | 83,520 |
| 0100032101 | DHCP statistics | 83,455 |
| 0105048901 | HA device status | 83,321 |
| 0100032101 | Performance statistics | 83,304 |
| 0100032101 | None | 83,238 |
| 0102043008 | DHCP Ack log | 83,009 |
| 0100032001 | Admin login successful | 5 |
| 0101039947 | SSL VPN tunnel up | 4 |
| 0100044546 | Attribute configured | 3 |
| 0100044547 | Object attribute configured | 2 |
