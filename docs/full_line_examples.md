# Full Line Examples and Coverage
## Top (type, subtype, logid, action) Combinations
| Type | Subtype | LogID | Action | Count | Example Raw Line |
|---|---|---|---|---|---|
| traffic | forward | 0000000013 | accept | 5,430,318 | `date=2026-10-23 time=08:48:26 eventtime=1792745306423348000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" ...` |
| event | system | 0100032002 | login | 1,272,524 | `date=2026-10-23 time=08:48:26 eventtime=1792745306564464000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logd...` |
| traffic | forward | 0000000013 | deny | 422,103 | `date=2026-10-23 time=08:48:33 eventtime=1792745313196916000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" ...` |
| utm | webfilter | 0316013056 | passthrough | 367,778 | `date=2026-10-23 time=08:48:35 eventtime=1792745315878120000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0316013056" type="utm" subtype="webfilter" level="notice" vd="root" sr...` |
| utm | dns | 1501054600 | pass | 273,937 | `date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1501054600" type="utm" subtype="dns" level="information" vd="root" src...` |
| utm | app-ctrl | 1059028704 | pass | 272,902 | `date=2026-10-23 time=08:48:29 eventtime=1792745309245668000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="1059028704" type="utm" subtype="app-ctrl" level="information" vd="root...` |
| utm | ips | 0419016384 | dropped | 218,604 | `date=2026-10-23 time=08:48:32 eventtime=1792745312632452000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=10....` |
| utm | virus | 0211008192 | blocked | 135,620 | `date=2026-10-23 time=08:48:49 eventtime=1792745329566372000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" srcip...` |
| event | sdwan | 0113022923 | N/A | 83,520 | `date=2026-10-23 time=08:48:41 eventtime=1792745321099412000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0113022923" type="event" subtype="sdwan" level="notice" vd="root" logd...` |
| event | system | 0100032101 | N/A | 83,455 | `date=2026-10-23 time=08:48:32 eventtime=1792745312773568000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root...` |
| event | ha | 0105048901 | N/A | 83,321 | `date=2026-10-23 time=08:48:36 eventtime=1792745316160352000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0105048901" type="event" subtype="ha" level="notice" vd="root" logdesc...` |
| event | system | 0100032101 | perf-stats | 83,304 | `date=2026-10-23 time=08:49:03 eventtime=1792745343960204000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root...` |
| event | connector | 0100032101 | connect | 83,238 | `date=2026-10-23 time=08:48:53 eventtime=1792745333940968000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="r...` |
| event | dhcp | 0102043008 | N/A | 83,009 | `date=2026-10-23 time=08:49:00 eventtime=1792745340291188000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0102043008" type="event" subtype="dhcp" level="information" vd="root" ...` |
| event | vpn | 0101037141 | negotiate | 54,634 | `date=2026-10-23 time=08:48:58 eventtime=1792745338033332000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0101037141" type="event" subtype="vpn" level="notice" vd="root" srcip=...` |
| utm | ips | 0419016384 | detected | 54,572 | `date=2026-10-23 time=08:49:48 eventtime=1792745388129512000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=10....` |
| utm | webfilter | 0316013056 | blocked | 40,857 | `date=2026-10-23 time=08:48:27 eventtime=1792745307128928000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0316013056" type="utm" subtype="webfilter" level="notice" vd="root" sr...` |
| event | vpn | 0101037141 | tunnel-stats | 27,282 | `date=2026-10-23 time=08:48:52 eventtime=1792745332106460000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0101037141" type="event" subtype="vpn" level="notice" vd="root" srcip=...` |
| event | vpn | 0101037141 | install_sa | 27,232 | `date=2026-10-23 time=08:50:19 eventtime=1792745419598380000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0101037141" type="event" subtype="vpn" level="notice" vd="root" srcip=...` |
| event | vpn | 0101037141 | ssl-login | 27,155 | `date=2026-10-23 time=08:49:22 eventtime=1792745362305284000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0101037141" type="event" subtype="vpn" level="notice" vd="root" user="...` |
| event | system | 0100032001 | login | 5 | `date=2026-10-24 time=19:59:30 eventtime=1792871970559031000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032001" type="event" subtype="system" level="information" vd="root...` |
| event | vpn | 0101039947 | tunnel-up | 4 | `date=2026-10-28 time=02:15:27 eventtime=1793153727926430000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0101039947" type="event" subtype="vpn" level="information" vd="root" l...` |
| event | system | 0100044546 | Edit | 3 | `date=2026-10-23 time=16:31:43 eventtime=1792773103224622000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100044546" type="event" subtype="system" level="warning" vd="root" lo...` |
| utm | virus | 0211008192 | detected | 3 | `date=2026-10-26 time=08:22:00 eventtime=1793002920642422000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" srcip...` |
| event | system | 0100044547 | Delete | 1 | `date=2026-10-29 time=04:07:25 eventtime=1793246845292480000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100044547" type="event" subtype="system" level="warning" vd="root" lo...` |
| traffic | forward | 0000000013 | None | 1 | `date=2026-10-30 time=08:48:25 eventtime=1793350105999999000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" ...` |
| event | system | 0100044547 | Add | 1 | `date=2026-10-29 time=03:55:43 eventtime=1793246143452976000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100044547" type="event" subtype="system" level="warning" vd="root" lo...` |

## Top 40 Rare Log IDs (< 1,000 occurrences)
| LogID | LogDesc | Msg | Count | Example Full Line |
|---|---|---|---|---|
| 0100032101 | Performance statistics | Performance statistics: average CPU: 9   | 1 | `date=2026-10-25 time=16:35:26 eventtime=1792946126992375000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 9  ...` |
| 0100032101 | None | Connected to FortiGate Cloud 72.253.124. | 1 | `date=2026-10-25 time=16:36:58 eventtime=1792946218418443000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 72.253.124.90"` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 2   | 1 | `date=2026-10-25 time=16:52:25 eventtime=1792947145558663000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 2  ...` |
| 0100032002 | Admin login failed | Administrator remote1 login failed from  | 1 | `date=2026-10-25 time=16:27:46 eventtime=1792945666987471000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="remote1" ui="ssh(45.3.45.245)" method="ssh" srcip=45.3.45.245 srcintf...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 45  | 1 | `date=2026-10-25 time=16:52:41 eventtime=1792947161387431000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 45 ...` |
| 0100032101 | None | Failed to connect to FortiGate Cloud 66. | 1 | `date=2026-10-25 time=16:47:08 eventtime=1792946828759311000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Failed to connect to FortiGate Cloud 66.17.135.55"` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 3   | 1 | `date=2026-10-25 time=16:48:29 eventtime=1792946909023111000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 3  ...` |
| 0100032101 | None | Connected to FortiGate Cloud 220.106.201 | 1 | `date=2026-10-25 time=16:35:56 eventtime=1792946156185999000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 220.106.201.51"` |
| 0100032002 | Admin login failed | Administrator sken login failed from ssh | 1 | `date=2026-10-25 time=16:53:11 eventtime=1792947191141035000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="sken" ui="ssh(45.74.28.174)" method="ssh" srcip=45.74.28.174 srcintf=...` |
| 0100032101 | None | Failed to connect to FortiGate Cloud 36. | 1 | `date=2026-10-25 time=16:24:12 eventtime=1792945452328471000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Failed to connect to FortiGate Cloud 36.149.85.123"` |
| 0100032101 | None | Failed to connect to FortiGate Cloud 45. | 1 | `date=2026-10-25 time=17:13:07 eventtime=1792948387272419000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Failed to connect to FortiGate Cloud 45.51.24.125"` |
| 0100032002 | Admin login failed | Administrator vereecke login failed from | 1 | `date=2026-10-25 time=16:29:27 eventtime=1792945767559879000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="vereecke" ui="https(45.74.28.239)" method="https" srcip=45.74.28.239 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 29  | 1 | `date=2026-10-25 time=16:57:09 eventtime=1792947429916507000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 29 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 35  | 1 | `date=2026-10-25 time=16:37:43 eventtime=1792946263515499000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 35 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 17  | 1 | `date=2026-10-25 time=17:09:31 eventtime=1792948171488019000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 17 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 6   | 1 | `date=2026-10-25 time=16:25:43 eventtime=1792945543045231000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 6  ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 34  | 1 | `date=2026-10-25 time=16:48:07 eventtime=1792946887669207000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 34 ...` |
| 0100032101 | None | Connected to FortiGate Cloud 157.117.214 | 1 | `date=2026-10-25 time=16:24:47 eventtime=1792945487719207000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 157.117.214.189"` |
| 0100032101 | None | Connected to FortiGate Cloud 48.70.211.1 | 1 | `date=2026-10-25 time=16:52:40 eventtime=1792947160566127000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 48.70.211.120"` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 6   | 1 | `date=2026-10-25 time=17:09:08 eventtime=1792948148933179000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 6  ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 40  | 1 | `date=2026-10-25 time=17:10:42 eventtime=1792948242667579000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 40 ...` |
| 0100032101 | None | Connected to FortiGate Cloud 148.185.191 | 1 | `date=2026-10-25 time=16:28:57 eventtime=1792945737246295000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 148.185.191.2"` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 44  | 1 | `date=2026-10-25 time=17:17:42 eventtime=1792948662421939000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 44 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 34  | 1 | `date=2026-10-25 time=16:29:13 eventtime=1792945753149727000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 34 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 11  | 1 | `date=2026-10-25 time=16:59:37 eventtime=1792947577265911000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 11 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 1   | 1 | `date=2026-10-25 time=16:29:43 eventtime=1792945783799299000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 1  ...` |
| 0100032101 | None | Connected to FortiGate Cloud 157.97.73.2 | 1 | `date=2026-10-25 time=17:09:15 eventtime=1792948155865619000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 157.97.73.233"` |
| 0100032101 | None | Connected to FortiGate Cloud 114.27.56.9 | 1 | `date=2026-10-25 time=16:54:47 eventtime=1792947287681587000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 114.27.56.98"` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 3   | 1 | `date=2026-10-25 time=16:54:57 eventtime=1792947297537235000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 3  ...` |
| 0100032101 | None | Connected to FortiGate Cloud 115.133.31. | 1 | `date=2026-10-25 time=16:26:54 eventtime=1792945614722671000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 115.133.31.40"` |
| 0100032002 | Admin login failed | Administrator epson login failed from ss | 1 | `date=2026-10-25 time=17:17:46 eventtime=1792948666718099000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="epson" ui="ssh(77.91.71.92)" method="ssh" srcip=77.91.71.92 srcintf="...` |
| 0100032002 | Admin login failed | Administrator lawyers login failed from  | 1 | `date=2026-10-25 time=16:31:58 eventtime=1792945918269163000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="lawyers" ui="ssh(45.74.28.173)" method="ssh" srcip=45.74.28.173 srcin...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 1   | 1 | `date=2026-10-25 time=16:41:14 eventtime=1792946474702623000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 1  ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 33  | 1 | `date=2026-10-25 time=16:27:24 eventtime=1792945644102955000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 33 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 16  | 1 | `date=2026-10-25 time=17:15:39 eventtime=1792948539444359000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 16 ...` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 41  | 1 | `date=2026-10-25 time=16:32:32 eventtime=1792945952203951000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 41 ...` |
| 0100032101 | None | Connected to FortiGate Cloud 40.114.148. | 1 | `date=2026-10-25 time=16:32:52 eventtime=1792945972736551000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 40.114.148.50"` |
| 0100032101 | None | Connected to FortiGate Cloud 16.243.226. | 1 | `date=2026-10-25 time=16:33:09 eventtime=1792945989311959000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 16.243.226.67"` |
| 0100032101 | Performance statistics | Performance statistics: average CPU: 40  | 1 | `date=2026-10-25 time=17:17:03 eventtime=1792948623951779000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="system" level="information" vd="root" logdesc="Performance statistics" action="perf-stats" msg="Performance statistics: average CPU: 40 ...` |
| 0100032101 | None | Connected to FortiGate Cloud 31.104.185. | 1 | `date=2026-10-25 time=17:18:05 eventtime=1792948685318519000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0100032101" type="event" subtype="connector" level="information" vd="root" action="connect" msg="Connected to FortiGate Cloud 31.104.185.116"` |

## Top 30 Reason Values
| Reason | Count |
|---|---|
| name_invalid | 1,272,524 |

## Top 30 Status Values
| Status | Count |
|---|---|
| failed | 1,272,524 |
| success | 9 |

## Top 30 Hostnames (URL Hosts)
| Hostname | Count |
|---|---|
| binance.us | 14,412 |
| digitally.com | 14,407 |
| square.com | 14,378 |
| bankofamerica.com | 14,354 |
| superdn.com | 14,351 |
| paypal.com | 14,321 |
| celsiusnetwork.com | 14,289 |
| microsoft.com | 14,280 |
| amazon.com | 14,275 |
| atlassian.net | 14,268 |
| redherr.com | 14,261 |
| docc.com | 14,260 |
| cachehero.com | 14,255 |
| citi.com | 14,247 |
| huobi.com | 14,242 |
| cnbc.com | 14,239 |
| softlayer.com | 14,231 |
| hsbc.com | 14,224 |
| zoom.com | 14,221 |
| binance.com | 14,200 |
| softwareupdate.com | 14,199 |
| coinbase.com | 14,191 |
| bloomberg.com | 14,188 |
| standardchartered.com | 14,186 |
| theverge.com | 14,183 |
| chase.com | 14,182 |
| adobe.com | 14,179 |
| niantic.com | 14,177 |
| salesforce.com | 14,172 |
| jpmorgan.com | 14,166 |
