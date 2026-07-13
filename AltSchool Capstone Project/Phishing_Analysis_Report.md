# SOC INCIDENT REPORT — Phishing Email Analysis

**AgentTesla Malspam Campaign**
CONFIDENTIAL | HIGH

| Field | Value |
|---|---|
| Organisation | Globex Manufacturing Ltd. |
| Incident Date | 4 December 2024 |
| Classification | Phishing-based Malware Infection |
| Overall Risk Rating | HIGH |
| Report Phase | Phase 1: Static Email & Attachment Analysis |
| Report Author | Ukah Paul |

> **THREAT IDENTIFIED**
> AgentTesla Infostealer — Credential Harvesting & Keylogging Malware. Delivered via spear-phishing attachment using file masquerading (MITRE T1036.008). Payload compiled and delivered same day. All email authentication controls absent or failed.

---

## SECTION 1 | SUMMARY OF FINDINGS

On 4 December 2024, a staff member at Globex Manufacturing Ltd. received a targeted malspam email impersonating a Turkish supplier (Acron Su ve Çevre Teknolojileri A.Ş.). The email carried a malicious attachment disguised as a technical specification document. Static analysis of the email and attachment confirms delivery of the AgentTesla infostealer.

| Finding | Detail |
|---|---|
| Attack Type | Targeted malspam — spear phishing via malicious attachment |
| Sender | sertan@acronas.com.tr — originating IP 94.141.120.32 |
| Authentication Failures | SPF softfail, DKIM none, DMARC none — all three controls absent or failed |
| Social Engineering | Purchase quotation lure targeting manufacturing industry; real supplier branding used |
| Attachment | TECHNICAL SPECIFICATIONS.TAR — declared as TAR, actually RAR archive containing .exe |
| Payload | TECHNICAL SPECIFICATIONS.exe — PE32 .NET assembly (1.05 MB), consistent with AgentTesla |
| Key Evasion Technique | File masquerading (T1036.008) — .TAR extension conceals RAR archive hiding Windows executable |
| Confirmed Impact | Credential theft and keylogging confirmed by Phase 2 network (PCAP) analysis |
| Overall Severity | HIGH |

---

## SECTION 2 | EMAIL ANALYSIS RESULTS

### 2.1 Tools Used

| Tool | Purpose |
|---|---|
| Sublime Text | Opened raw .eml file as plain text; inspected full header block before the first blank line |
| MX Toolbox Header Analyzer | Pasted headers to evaluate SPF, DKIM, DMARC, relay chain, and spoofing indicators |
| emldump.py | Listed all MIME parts; extracted email body and attachment from the .eml file |
| whois (Kali Linux / RIPE DB) | Queried RIPE NCC for ownership, registration, and abuse contact of originating IP 94.141.120.32 |

### 2.2 Header Analysis Results

| Header Field | Value / Finding | Significance |
|---|---|---|
| From (display name) | Sertan ÇOKER (decoded from RFC 2047 Base64) | Turkish name — consistent with claimed identity |
| From (address) | sertan@acronas.com.tr | Sending domain is acronas.com.tr |
| Return-Path | sertan@acronas.com.tr | Matches From — no separate bounce redirection |
| Reply-To | (not set) | No reply diversion — entirely attachment-based attack |
| Originating IP | 94.141.120.32 | Direct single-hop connection — no relay anonymization |
| Sender Timestamp | 4 Dec 2024 04:51:17 -0800 (US Pacific) | Timezone mismatch — Turkish sender using US Pacific offset; suggests automated infrastructure |
| Received Timestamp | Wed, 04 Dec 2024 12:51:16 UTC | Recipient mail server receipt time |
| Subject | PURCHASE QUOTATION | Generic business subject — low suspicion for manufacturing company |
| SPF | softfail | Sending IP not explicitly authorized — possible compromised account or bulk mailer |
| DKIM | none | No digital signature — message integrity cannot be verified |
| DMARC | none | No enforcement policy — spoofed mail from this domain passes uninspected |

**Screenshot:**
![Decode the Sender Display Name py](<screenshots/Decode the Sender Display Name py.jpg>)

![Decode the Sender Display Name](<screenshots/Decode the Sender Display Name.jpg>)

**Screenshot:**
![Email Header](<screenshots/email header.jpg>)

**Screenshot:**
![Header analysis with mxtoolbox a](<screenshots/heaader analysis with mxtoolboxa.jpg>)

![Header analysis with mxtoolbox b](<screenshots/heaader analysis with mxtoolboxb.jpg>)

### 2.3 Originating IP Intelligence — WHOIS Analysis (94.141.120.32)

> **THREAT INTELLIGENCE FINDING**
> The sending IP resolves to a UK-based bulletproof-style hosting provider (DGTL TECH UK LLP) with a subnet created just 7 days after the attack. This is the third geographic mismatch in the evidence chain — the attacker claimed to be Turkish, used a US Pacific Timezone, and sent from UK-hosted infrastructure.

WHOIS data was retrieved from the RIPE NCC database for originating IP 94.141.120.32.

| WHOIS Field | Value | SOC Analysis / Significance |
|---|---|---|
| IP / Subnet | 94.141.120.0/24 (94.141.120.0 – 94.141.120.255) | Entire /24 block allocated to one organization — attacker controls the full range |
| Network Name | DGTL-NETWORK-2024-12-11 | Name contains date 2024-12-11 — subnet created 7 days AFTER the attack on 2024-12-04 |
| Subnet Created | 2024-12-11T14:22:23Z | Critical finding: IP block registered AFTER the attack date — freshly provisioned or re-registered infrastructure; consistent with throwaway/bulletproof hosting |
| Route / ASN Created | 2024-12-11T14:22:23Z via AS61087 | BGP route advertisement also created 2024-12-11 — entire routing entry is post-attack; suggests infrastructure cleanup or re-registration after use |
| Organisation | DGTL TECH UK LLP (ORG-DTUL2-RIPE) | Small UK LIR (Local Internet Registry) — allocates its own IP space via RIPE, giving tenants reduced scrutiny compared to major cloud providers |
| Org Created | 2021-01-20T10:18:39Z | Organisation pre-dates the attack by 3+ years — established entity providing hosting to potentially anonymous customers |
| Registered Address | 71-75 Shelton Street, WC2H 9JQ, London, UK | Well-known virtual office address in Covent Garden — used by thousands of UK-registered shell companies and mailbox businesses; not a physical data centre |
| Country | GB (United Kingdom) | Geographic mismatch #3 — attacker claimed Turkish identity, sent from US Pacific time zone infrastructure, but actual IP is UK-hosted |
| Abuse Contact | abuse@dgtl.tech | Provider-level abuse contact — small LIR with no major brand reputation risk; abuse reports may receive slow or no response |
| Status | ASSIGNED PA (Provider Aggregable) | IP space sub-allocated from DGTL TECH's parent block — attacker is a customer of this LIR, not a direct RIPE member |
| Last Modified | 2026-04-06T13:13:36Z | WHOIS record recently updated — infrastructure still active; block not abandoned after the attack |

#### 2.3.1 The Story This WHOIS Data Tells

| # | Intelligence Finding | What It Means |
|---|---|---|
| 1 | Subnet created 7 days after attack | The IP block 94.141.120.0/24 did not exist in RIPE until 2024-12-11 — 7 days after the December 4 attack. Either the subnet was freshly allocated post-attack as part of a cleanup/re-assignment, or the attacker used pre-provisioned infrastructure only formally RIPE-registered after deployment. Either scenario points to deliberate infrastructure management. |
| 2 | Virtual office address | 71-75 Shelton Street WC2H 9JQ is one of the UK's most commonly used registered-agent / virtual office addresses. DGTL TECH UK LLP operates as a small LIR from this address — a setup that offers legitimate IP allocation rights with minimal physical oversight. |
| 3 | Three-way geographic deception | The attacker constructed a false Turkish identity (supplier name, Turkish language, .com.tr domain) while operating from UK-hosted infrastructure (DGTL TECH, London) and using an automated sending system configured to US Pacific time (-0800). No element of the infrastructure matches the claimed origin. |
| 4 | Bulletproof-style hosting pattern | Small LIRs like DGTL TECH that allocate /24 blocks to anonymous customers are frequently used as bulletproof hosting — they handle abuse reports slowly or not at all, and customers can operate without standard KYC scrutiny required by major cloud providers (AWS, Azure, GCP). |
| 5 | AS61087 route advertisement | The BGP route for this /24 via AS61087 was also created on 2024-12-11. This means the network was not even globally routable before that date — the IP was reachable only because the sending was done via the provider's own routing before the RIPE route object was registered. |

#### 2.3.2 Geographic Mismatch Summary

| Evidence Layer | Claimed / Apparent | Actual (Verified) | Mismatch |
|---|---|---|---|
| Sender identity | Turkish company (Acron Su ve Çevre Teknolojileri A.Ş.) | Unverified — no confirmed Turkish infrastructure | YES |
| Email timestamp Timezone | Turkish business hours expected (UTC+3) | US Pacific time (-0800 / UTC-8) | YES |
| Sending IP infrastructure | Turkey or EU expected | UK-hosted via DGTL TECH LLP, London (GB) | YES |


**Screenshot:**
![whois output 1](<screenshots/whois output 1.jpg>)

![whois output 2](<screenshots/whois output 2.jpg>)


### 2.4 Email Content Analysis

| Element | Finding |
|---|---|
| Subject | PURCHASE QUOTATION — generic but contextually appropriate for manufacturing industry |
| Body Language | Formal business tone with non-native grammar errors ("Dea Sir", "We plan the purchase") |
| Embedded URLs | None — entirely attachment-based; bypasses URL reputation scanning and safe-link rewriting |
| Attachment Reference | "Please see technical specifications in the attached file" — direct instruction to open attachment |

**Screenshot:**
![Email Body](<screenshots/Email Body.jpg>)

**Screenshot:**
![List all mime parts](<screenshots/list all mime parts.jpg>)

**Screenshot:**
![Extract and Read the Email Body](<screenshots/Extract and Read the Email Body.jpg>)

### 2.5 Social Engineering Assessment

| Technique | Observation |
|---|---|
| Pretexting | Impersonates Acron Su ve Çevre Teknolojileri A.Ş.; real Turkish company with verifiable name, address, phone, and website; credibility is high |
| Authority | Sender presents as Purchase Manager, mid-level authority role that legitimises a quotation request without raising suspicion |
| Business Context Lure | Purchase quotation request is entirely routine in a manufacturing company, no unusual ask to trigger suspicion |
| No Urgency Tactic | Unlike many phishing emails this message uses no time pressure, it relies entirely on normalcy and routine business context |
| Grammar Anomalies | "Dea Sir" and "We plan the purchase the equipment" — non-native English; may increase perceived authenticity rather than alarm recipients |
| No Malicious URLs | No embedded hyperlinks — entirely attachment-based; bypasses all URL reputation filters and safe-link rewriting services |
| Attachment as Sole Payload | All malicious content is in the attachment — the body exists only to make opening it seem like a routine business action |

---

## SECTION 3 | ATTACHMENT ANALYSIS

The attachment passed through three layers of deception before the executable payload was revealed. No execution was performed — all findings are based on static analysis only.

### 3.1 Deception / Attachment Chain

| Layer | Appears To Be | Actually Is | MITRE Technique |
|---|---|---|---|
| 1 | TECHNICAL SPECIFICATIONS.TAR (application/x-tar) | RAR archive v4 (Win32) | T1036.008 — Masquerading: Wrong Extension |
| 2 | A document or specification file inside the archive | TECHNICAL SPECIFICATIONS.exe (Windows executable) | Extension confusion — spaces before .exe; Windows hides .exe by default |
| 3 | Unknown binary | PE32 .NET assembly — AgentTesla delivery format | T1027 — Obfuscated Files or Information (packed .NET payload) |

**Screenshot:**
![Extract the Attachment a](<screenshots/Extract the Attachmenta.jpg>)


![Extract the Attachment b](<screenshots/Extract the Attachmentb.jpg>)

**Screenshot:**
![Detect True File Type](<screenshots/Detect True File Type.jpg>)

**Screenshot:**
![List RAR Archive Contents](<screenshots/List RAR Archive Contents.jpg>)

### 3.2 File Properties

| Property | Value |
|---|---|
| Attachment name (as declared in email) | TECHNICAL SPECIFICATIONS.TAR |
| Declared MIME type | application/x-tar |
| True container format | RAR archive data, v4, os: Win32 |
| Payload filename inside archive | TECHNICAL SPECIFICATIONS.exe |
| Payload size | 1,096,704 bytes (1.05 MB) |
| Payload file type | PE32 executable (GUI) Intel 80386, Mono/.NET assembly, for MS Windows — 3 sections |
| Compilation timestamp | 2024-12-04 00:02 — compiled same day as delivery |
| .NET assembly confirmed | Yes — MZ magic bytes + _CorExeMain signature detected |

### 3.3 File Hash Values

| File | Algorithm | Hash Value |
|---|---|---|
| RAR Container (TECHNICAL_SPECIFICATIONS.tar) | MD5 | b7635c9cc63619099419c68a2bf0d390 |
| RAR Container (TECHNICAL_SPECIFICATIONS.tar) | SHA256 | 5c98308c69c84a57214442e2cadc9f8f0fcdbab8e6050f9915ac336b6f1d59f0 |
| TECHNICAL SPECIFICATIONS.exe | MD5 | 65feefe926eb3f734b6968b35c23acb3 |
| TECHNICAL SPECIFICATIONS.exe | SHA256 | d1b068b826e3a9527cddd09866886caba895f390af930a9b35c027eb1c2db34c |

**Screenshot:**
![Extract EXE and Generate Hashes](<screenshots/Extract EXE and Generate Hashes.jpg>)

### 3.4 Malware Indicators (Static String Analysis: No Execution)

Static string analysis of the PE binary revealed the following credential-harvesting indicators embedded in the .NET assembly:

| Indicator String | Significance |
|---|---|
| pbHidePassword | UI element for masking a password input field; credential capture form component |
| txtPassword | Password text box control, input field for capturing credentials |
| pbShowPassword_Click | Show/hide password toggle event handler, interactive credential harvesting UI |
| set_PasswordChar | .NET method for concealing typed characters, consistent with fake login form overlay |

These strings are consistent with a credential harvesting component — either a fake login form overlay or a browser password vault extractor. Combined with the .NET assembly delivery method, this is consistent with the AgentTesla infostealer family.

**Screenshot:**
![Malware Indicators](<screenshots/Malware Indicators.jpg>)

![Malware Indicators 1a](<screenshots/Malware Indicators1a.jpg>)

### 3.5 VirusTotal Hash Reputation Analysis

| File | VirusTotal Result | Notable Vendor Detection |
|---|---|---|
| TECHNICAL_SPECIFICATIONS.tar (RAR container) | MALICIOUS: Trojan/AgentTesla | Antiy-AVL: Trojan/Win32.AgentTesla (Keylogger) |
| TECHNICAL SPECIFICATIONS.exe | MALICIOUS: Trojan.msil/Strictor | Multiple vendors: confirmed infostealer payload |

**Screenshot:**
![SHA256 Hash Analysis of TAR using Virus Total Trojan Agent Tesla]
(<screenshots/SHA256 Hash Analysis of TAR using Virus Total Trojan Agent Tesla.jpg>)

**Screenshot:**
![SHA256 Hash Analysis on Virus Total on EXE file]
(<screenshots/SHA256 Hash Analysis on Virus Total on EXE file.jpg>)

---

## SECTION 4 | INDICATORS OF COMPROMISE (IOC) TABLE

### 4.1 Email Header IOCs

| IOC Type | Value | Source | Confidence |
|---|---|---|---|
| Sender email address | sertan@acronas.com.tr | Email header From: | High |
| Sending domain | acronas.com.tr | Email header | High |
| Originating IP address | 94.141.120.32 | Email header Received: | High |
| SPF result | softfail | MX Toolbox analysis | High |
| DKIM result | none — no signature | MX Toolbox analysis | High |
| DMARC result | none — no policy | MX Toolbox analysis | High |
| Timezone anomaly | -0800 (US Pacific) from Turkish sender | Header Date: field | High |

### 4.2 Infrastructure Intelligence IOCs (WHOIS — 94.141.120.32)

| IOC Type | Value | Source | Confidence |
|---|---|---|---|
| IP subnet | 94.141.120.0/24 | RIPE WHOIS query | High |
| Subnet name | DGTL-NETWORK-2024-12-11 | RIPE WHOIS — netname | High |
| Subnet creation date | 2024-12-11 — 7 days AFTER the attack | RIPE WHOIS — created field | High |
| ASN / Route | AS61087 — route created 2024-12-11 | RIPE WHOIS — route object | High |
| Hosting Organisation | DGTL TECH UK LLP (ORG-DTUL2-RIPE) | RIPE WHOIS — org field | High |
| Registered address | 71-75 Shelton Street, WC2H 9JQ, London, UK | RIPE WHOIS — address | High |
| Abuse contact | abuse@dgtl.tech | RIPE WHOIS — abuse-c | High |
| Geographic mismatch | Claimed Turkey / Timezone US Pacific / IP hosted UK | Cross-referencing header + WHOIS | High |

### 4.3 Attachment / Payload IOCs

| IOC Type | Value | Source |
|---|---|---|
| Declared attachment name | TECHNICAL SPECIFICATIONS.TAR | emldump.py |
| True container format | RAR archive data, v4, os: Win32 | file command (magic bytes) |
| Evasion technique | File masquerading — T1036.008 | file command vs declared MIME type |
| Payload filename | TECHNICAL SPECIFICATIONS.exe | unrar l |
| Payload file type | PE32 .NET executable (GUI) for MS Windows | file command |
| Compilation timestamp | 2024-12-04 00:02 (same day as delivery) | PE header compilation date |
| Embedded URLs | None — attachment-only attack | Email body analysis |
| VirusTotal classification | Trojan/AgentTesla (RAR), Trojan.msil/Strictor (EXE) | VirusTotal hash lookup |

### 4.4 File Hash IOCs

| File | Algorithm | Hash Value |
|---|---|---|
| RAR container | MD5 | b7635c9cc63619099419c68a2bf0d390 |
| RAR container | SHA256 | 5c98308c69c84a57214442e2cadc9f8f0fcdbab8e6050f9915ac336b6f1d59f0 |
| TECHNICAL SPECIFICATIONS.exe | MD5 | 65feefe926eb3f734b6968b35c23acb3 |
| TECHNICAL SPECIFICATIONS.exe | SHA256 | d1b068b826e3a9527cddd09866886caba895f390af930a9b35c027eb1c2db34c |

---

## SECTION 5 | RISK RATING

> **OVERALL RISK RATING: HIGH**
> Confirmed executable payload delivered. All authentication controls failed. File masquerading employed. Full credential exfiltration confirmed in Phase 2.

### 5.1 Risk Dimension Breakdown

| Dimension | Rating | Detail |
|---|---|---|
| Delivery Method | HIGH | File masquerading (.TAR → RAR → .EXE) bypasses extension-based email security; no malicious URLs to flag by reputation scanning |
| Payload Capability | HIGH | PE32 .NET binary with credential-harvesting strings; consistent with AgentTesla — keylogging, browser credential theft, and FTP exfiltration |
| Authentication Failures | HIGH | SPF softfail, DKIM none, DMARC none — domain has no controls that allow detection or rejection of spoofed email |
| Social Engineering | MEDIUM | Plausible business purchase pretext using real supplier branding; grammar anomalies reduce sophistication but increase perceived authenticity for non-native speakers |
| Victim Exposure | HIGH | Manufacturing company routinely receives supplier quotation requests — victim profile is well-matched to the lure; low suspicion threshold |

---

## SECTION 6 | INITIAL HYPOTHESIS OF ATTACK

The threat actor conducted a targeted malspam campaign against Globex Manufacturing Ltd., selecting the purchase quotation pretext as a high-credibility lure appropriate for a manufacturing company. The campaign delivered the AgentTesla infostealer via a multi-layer file masquerading chain designed to evade common email security controls.

### 6.1 Reconstructed Attack Chain

| # | Stage | Action / Method | Evidence |
|---|---|---|---|
| 1 | Target Selection | Manufacturing company identified — routinely receives supplier quotation emails; low suspicion profile | Email subject PURCHASE QUOTATION; lure content matches industry |
| 2 | Infrastructure Setup | Attacker provisioned or used UK-hosted IP 94.141.120.32 via DGTL TECH UK LLP; a small London LIR operating from a virtual office address; subnet DGTL-NETWORK-2024-12-11 registered 7 days post-attack suggesting throwaway infrastructure | RIPE WHOIS — subnet created 2024-12-11; virtual office at 71-75 Shelton Street WC2H 9JQ |
| 3 | Sender Preparation | Email sent from sertan@acronas.com.tr via IP 94.141.120.32 using US Pacific time zone (-0800) while claiming Turkish origin: three-way geographic mismatch — Turkey claimed / US Pacific time zone / UK-hosted IP | SPF softfail; direct single-hop IP; WHOIS country Great Britain vs claimed Turkey |
| 4 | Payload Preparation | AgentTesla compiled same day as delivery (2024-12-04 00:02); packed into RAR and renamed with .TAR extension | Compilation timestamp; file masquerading chain confirmed by file command |
| 5 | Email Delivery | Single-hop delivery to victim, no relay chain anonymization used | Received: header — single hop from 94.141.120.32 |

### 6.2 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Spear Phishing Attachment | T1566.001 | Email with malicious RAR attachment disguised as supplier technical document |
| Execution | User Execution: Malicious File | T1204.002 | Victim required to open the attachment and execute the .exe payload |
| Defense Evasion | Masquerading: Wrong Extension | T1036.008 | .TAR extension on RAR archive; .exe inside, bypasses extension-based email filters |
| Defense Evasion | Obfuscated Files or Information | T1027 | .NET binary likely packed to evade static signature detection |

### 6.3 Confidence Assessment

| Finding | Confidence | Basis |
|---|---|---|
| File masquerading chain and authentication failures | HIGH | Direct evidence from raw .eml file — confirmed by file command and MX Toolbox |
| WHOIS infrastructure intelligence — UK-hosted bulletproof-style provider | HIGH | RIPE NCC WHOIS confirms subnet DGTL-NETWORK-2024-12-11 created 7 days post-attack; virtual office address; three-way geographic mismatch confirmed |
| Payload type (.NET assembly with credential-harvesting strings) | HIGH | Confirmed by static string analysis, no execution required |
| AgentTesla family attribution | HIGH | VirusTotal hash lookup confirms Trojan/AgentTesla and Trojan.msil/Strictor classifications |

---

*Phase 1 — Static Email & Attachment Analysis | Ukah Paul*

---

## Screenshot Index

| Screenshot filename in folder | Used in section |
|---|---|
| Decode the Sender Display Name py | 2.2 — Sender display name decode |
| Decode the Sender Display Name | 2.2 — Sender display name decode |
| Detect True File Type | 3.1 — True File Type Detection |
| Email Body | 2.4 — Email Body |
| email header | 2.2 — Raw .eml header block |
| exfiltrated files from PCAP | Cross-referenced in Network Investigation Report |
| Extract and Read the Email Body | 2.4 — Extracted email body content |
| Extract EXE and Generate Hashes | 3.3 — Hash Generation |
| Extract the Attachmenta | 3.1 — Raw Attachment Extraction |
| Extract the Attachmentb | 3.1 — Raw Attachment Extraction |
| heaader analysis with mxtoolboxa | 2.2 — MX Toolbox SPF/DKIM/DMARC results |
| heaader analysis with mxtoolboxb | 2.2 — MX Toolbox SPF/DKIM/DMARC results |
| list all mime parts | 2.4 — MIME Part Listing |
| List RAR Archive Contents | 3.1 — RAR Archive Contents |
| Malware Indicators | 3.4 — Static String Analysis |
| Malware Indicators1a | 3.4 — Static String Analysis |
| SHA256 Hash Analysis of TAR using Virus Total Trojan Agent T... | 3.5 — VirusTotal RAR result |
| SHA256 Hash Analysis on Virus Total on EXE file | 3.5 — VirusTotal EXE result |
| whois output 1 | 2.3 — WHOIS Output |
| whois output 2 | 2.3 — WHOIS Output |


