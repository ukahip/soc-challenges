# SOC INCIDENT REPORT — INDICATORS OF COMPROMISE (IOC) SUMMARY

**AgentTesla Campaign — Globex Manufacturing Ltd.**
TLP:RED

| Field | Value |
|---|---|
| Incident Date | 04 December 2024 |
| Analyst | Ukah Paul |
| Classification | HIGH |
| Handling | TLP:RED — Restricted |

**Confidence Level Key**
- ● **HIGH** — Confirmed malicious, immediate action required
- ● **MED** — Suspicious, validate and monitor
- ● **LOW** — Informational, context only

---

## A — Email Sender & Authentication

Indicators extracted from raw email headers and authentication analysis.

| # | IOC Type | Value / Indicator | Source / Evidence | Confidence |
|---|---|---|---|---|
| 01 | Sender Address | sertan@acronas.com.tr | Email Header — From: | ● HIGH |
| 02 | Sending Domain | acronas.com.tr | Email Header | ● HIGH |
| 03 | Originating IP | 94.141.120.32 | Email Header — Received: | ● HIGH |
| 04 | SPF Result | softfail — sender IP not explicitly authorised | MXToolbox Header Analysis | ● HIGH |
| 05 | DKIM Result | none — no cryptographic signature present | MXToolbox Header Analysis | ● HIGH |
| 06 | DMARC Result | none — no enforcement policy configured on domain | MXToolbox Header Analysis | ● HIGH |
| 07 | Timezone Anomaly | -0800 (US Pacific) — Turkish sender claimed | Email Header — Date: field | ● HIGH |
| 08 | Email Subject | PURCHASE QUOTATION — supplier impersonation lure | Email Header — Subject: | ● HIGH |

---

## B — Attacker Infrastructure

WHOIS intelligence on sending IP — bulletproof-style hosting with anomalous registration dates.

| # | IOC Type | Value / Indicator | Source / Evidence | Confidence |
|---|---|---|---|---|
| 01 | IP Subnet | 94.141.120.0/24 | RIPE WHOIS — inetnum | ● HIGH |
| 02 | Subnet Name | DGTL-NETWORK-2024-12-11 | RIPE WHOIS — netname | ● HIGH |
| 03 | Subnet Created | 2024-12-11 — provisioned 7 days AFTER the attack | RIPE WHOIS — created field | ● HIGH |
| 04 | ASN | AS61087 — route object also created 2024-12-11 | RIPE WHOIS — route object | ● HIGH |
| 05 | Hosting Organisation | DGTL TECH UK LLP (ORG-DTUL2-RIPE) | RIPE WHOIS — org field | ● HIGH |
| 06 | Registered Address | 71-75 Shelton Street, WC2H 9JQ, London, UK — known virtual office address | RIPE WHOIS — address | ● HIGH |
| 07 | Abuse Contact | abuse@dgtl.tech | RIPE WHOIS — abuse-c | ● HIGH |
| 08 | Geographic Deception | Claimed Turkey · Timezone US Pacific · IP UK-hosted — 3-way mismatch | Header + WHOIS correlation | ● HIGH |

---

## C — Malicious Attachment & File

Static analysis of email attachment — file masquerading chain delivering AgentTesla payload.

| # | IOC Type | Value / Indicator | Source / Evidence | Confidence |
|---|---|---|---|---|
| 01 | Declared Filename | TECHNICAL SPECIFICATIONS.TAR | emldump.py — MIME part listing | ● HIGH |
| 02 | True File Format | RAR archive data v4, os: Win32 — extension spoofed | file command — magic bytes | ● HIGH |
| 03 | Evasion Technique | File Masquerading (MITRE T1036.008) — .TAR extension on RAR archive | vs declared MIME type | ● HIGH |
| 04 | Payload Filename | TECHNICAL SPECIFICATIONS.exe — inside RAR | unrar l — archive listing | ● HIGH |
| 05 | Payload Type | PE32 .NET executable (GUI) — Mono/.NET assembly | file command on extracted .exe | ● HIGH |
| 06 | Compile Timestamp | 2024-12-04 00:02 — compiled same day as delivery | PE header — compilation timestamp | ● HIGH |
| 07 | VirusTotal — RAR | MALICIOUS: Trojan/AgentTesla (Win32.AgentTesla Keylogger) | VirusTotal — SHA256 lookup | ● HIGH |
| 08 | VirusTotal — EXE | MALICIOUS: Trojan.msil/Strictor — multiple vendor detections | VirusTotal — SHA256 lookup | ● HIGH |

---

## D — File Hash IOCs

Cryptographic fingerprints for SIEM and EDR rule deployment — both artefacts confirmed malicious.

| # | IOC Type | Value / Indicator | Source / Evidence | Confidence |
|---|---|---|---|---|
| 01 | MD5 — RAR Container | `b7635c9cc63619099419c68a2bf0d390` | md5sum — TECHNICAL_SPECIFICATIONS.tar | ● HIGH |
| 02 | SHA256 — RAR Container | `5c98308c69c84a57214442e2cadc9f8f0fcdbab8e6050f9915ac336b6f1d59f0` | sha256sum — TECHNICAL_SPECIFICATIONS.tar | ● HIGH |
| 03 | MD5 — EXE Payload | `65feefe926eb3f734b6968b35c23acb3` | md5sum — TECHNICAL SPECIFICATIONS.exe | ● HIGH |
| 04 | SHA256 — EXE Payload | `d1b068b826e3a9527cddd09866886caba895f390af930a9b35c027eb1c2db34c` | sha256sum — TECHNICAL SPECIFICATIONS.exe | ● HIGH |

---

## E — Victim Host

Compromised workstation identity — extracted from PCAP traffic and AgentTesla exfil filenames.

| # | IOC Type | Value / Indicator | Source / Evidence | Confidence |
|---|---|---|---|---|
| 01 | Internal IP Address | 10.12.4.101 | tshark conv,ip — highest-traffic internal host | ● HIGH |
| 02 | Hostname | DESKTOP-VJCRXEB | AgentTesla exfil filenames — malware-embedded | ● HIGH |
| 03 | OS Username | gary.strickman | AgentTesla exfil filenames — malware-embedded | ● HIGH |
| 04 | Operating System | Microsoft Windows 11 Pro | PW_ exfil file content header | ● HIGH |
| 05 | Public IP Address | 173.66.46.97 | api.ipify.org response — malware IP discovery | ● HIGH |

---

## F — DNS & Network Indicators

DNS queries observed in PCAP — only 3 total queries confirm malware-only isolated execution environment.

| # | IOC Type | Value / Indicator | Source / Evidence | Confidence |
|---|---|---|---|---|
| 01 | IP Discovery Domain | api.ipify.org | tshark DNS — T+0.000s (first packet in PCAP) | ● HIGH |
| 02 | IP Discovery CDN IP | 172.67.74.152 | tshark DNS response — Cloudflare CDN | ● MED |
| 03 | FTP C2 Domain | ftp.ercolina-usa.com | tshark DNS — T+6.122s and T+1211.313s | ● HIGH |
| 04 | FTP C2 Server IP | 192.254.225.136 | tshark conv,ip + FTP stream correlation | ● HIGH |
| 05 | C2 Beacon Interval | ~20 minutes (1,211 seconds) — automated pattern | DNS re-query timestamp delta calculation | ● HIGH |

---

## G — FTP Exfiltration Channel

Cleartext FTP used as C2 and exfiltration channel — credentials and data fully exposed on wire.

| # | IOC Type | Value / Indicator | Source / Evidence | Confidence |
|---|---|---|---|---|
| 01 | FTP Port | Port 21 — cleartext, NO TLS encryption whatsoever | tshark FTP filter | ● HIGH |
| 02 | FTP Server Banner | Pure-FTPd [privsep] — server software fingerprinted | FTP 220 banner — tshark stream | ● HIGH |
| 03 | FTP Username | ben@ercolina-usa.com | FTP USER command — visible cleartext on wire | ● HIGH |
| 04 | FTP Password | [REDACTED — confirmed visible cleartext on port 21] | FTP PASS command — tshark FTP stream | ● HIGH |
| 05 | Total FTP Sessions | 2 sessions — consistent automated beacon pattern | tshark FTP session reconstruction | ● HIGH |
| 06 | Total Data Exfiltrated | ~38 KB across 4 files in 2 timed sessions | tshark FTP-DATA frames + export-objects | ● HIGH |

---

## H — Exfiltrated Files

All 4 files recovered in full from PCAP — browser credentials, cookie stores, and 20-minute keylog captured.

| # | IOC Type | Value / Indicator | Source / Evidence | Confidence |
|---|---|---|---|---|
| 01 | Password Dump (PW_) | PW_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_20_57.html · 392 B | FTP STOR — Session 1 · Saved Edge browser passwords | ● HIGH |
| 02 | Chrome Credentials (CO_) | CO_Chrome_Default.txt_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_21_03.txt · ~23 KB | FTP STOR — Session 1 · Chrome credential + cookie store | ● HIGH |
| 03 | Edge Credentials (CO_) | CO_Edge Chromium_Default.txt_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_21_04.txt · ~11 KB | FTP STOR — Session 1 · Edge Chromium credential store | ● HIGH |
| 04 | Keylog Dump (KL_) | KL_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_41_04.html · ~1.4 KB | FTP STOR — Session 2 · 20 min captured keystrokes | ● HIGH |

---

## I — MITRE ATT&CK Technique Mapping

Full kill chain coverage: Initial Access → Execution → Defense Evasion → Discovery → Collection → C2 → Exfiltration.

| # | Tactic | Technique · ID | Evidence |
|---|---|---|---|
| 01 | Initial Access | Spear Phishing Attachment · T1566.001 | Spoofed Turkish supplier email with malicious RAR attachment |
| 02 | Execution | User Execution: Malicious File · T1204.002 | Victim required to open attachment and manually run .exe |
| 03 | Defense Evasion | Masquerading: Wrong Extension · T1036.008 | .TAR extension on RAR archive; .exe inside — bypasses email filters |
| 04 | Defense Evasion | Obfuscated Files or Information · T1027 | .NET binary packed to evade static AV signatures |
| 05 | Discovery | System Network Config Discovery · T1016 | api.ipify.org queried at T+0 — malware retrieves public IP |
| 06 | Discovery | System Information Discovery · T1082 | Hostname and username auto-embedded into all exfil filenames |
| 07 | Collection | Input Capture: Keylogging · T1056.001 | KL_ file — 20-minute HTML keylog dump of victim keystrokes |
| 08 | Collection | Credentials from Web Browsers · T1555.003 | CO_ files — Chrome and Edge credential + cookie stores stolen |
| 09 | Collection | Credentials from Password Stores · T1555 | PW_ file — saved browser password vault extracted |
| 10 | Command & Control | Application Layer Protocol: FTP · T1071.002 | Port 21 used as C2 channel — cleartext, no encryption |
| 11 | Exfiltration | Exfiltration Over C2 Channel · T1041 | All stolen data uploaded via FTP STOR to 192.254.225.136 |
| 12 | Exfiltration | Automated Exfiltration · T1020 | Two timed sessions; 20-min hardcoded beacon; no user interaction |

---

*Ukah Paul · Incident Date: 04 December 2024 · TLP:RED*
