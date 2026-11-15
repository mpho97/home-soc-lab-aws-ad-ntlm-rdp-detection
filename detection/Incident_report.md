# Incident Report - Active Directory NTLM Bruteforce -> RDP Compromise
**Date:** 2026-05-10
**Analyst:** Mpho Johannes Tema - SOC L1
**Lab:** AWS EC2 - AD Lab (af-south-1)
**Severity:** High
**Status:** Closed - Contained & Remediated
**MITRE:** T1110.001, T1021.001, T1003.002

## Executive Summary
Simulated attacker from Kali (192.168.1.50) performed NTLM bruteforce against AD account `AD\administrator` via RDP (3389) on domain-joined Windows 10. Splunk on Ubuntu 22.04 detected 47 failed Type 10 logons followed by successful compromise and RDP session establishment. Validated detection rule.

## Architecture
- DC: Windows Server 2019 AD (ad.lab.local) - 10.0.1.10
- Client: Windows 10 Domain Joined RDP Enabled - 10.0.1.20
- SIEM: Ubuntu 22.04 Splunk Enterprise - 10.0.1.30
- Attacker: Kali Linux - 192.168.1.50
- Security Groups: Allow 3389 from attacker IP only for test

## Timeline (SAST UTC+2)

| Time | Event ID | Description | Source IP | Account |
|------|----------|-------------|-----------|---------|
| 12:00:05 | 4625 | Failed Logon Type 10, NTLM, 0xC000006A Bad Pwd | 192.168.1.50 | administrator |
| 12:00-12:05 | 4625 x15 | Burst continues - Hydra running | 192.168.1.50 | administrator |
| 12:10:22 | 4625 x10 | Burst - 10 more failed | 192.168.1.50 | administrator |
| 12:15:10 | 4625 x7 | Slowing - password near end of list | 192.168.1.50 | administrator |
| 12:20:30 | 4625 x3 | Final attempts | 192.168.1.50 | administrator |
| 12:25:13 | 4624 | SUCCESS Logon Type 10, NTLM, Elevated Token | 192.168.1.50 | administrator |
| 12:25:15 | 4778 | Session Reconnected - RDP Session ID 2 | 192.168.1.50 | administrator |
| 12:25:18 | 4672 | Special Privileges Assigned - SeDebug etc | - | administrator |
| 12:25:25 | 4648 | Explicit Credential Logon - mstsc -> cmd.exe | - | administrator |
| 12:26:00 | Alert | Splunk Correlation Alert: bruteforce_to_rdp_success triggered | - | - |

**Time to Compromise:** 25 min 8 sec, 47 attempts

## IOCs

- **Src IP:** 192.168.1.50 (Kali)
- **Target Account:** ADLAB\administrator (AD user)
- **Target Host:** WIN10-CLIENT.ad.lab.local (10.0.1.20)
- **Logon Type:** 10 - RemoteInteractive (RDP)
- **Auth Package:** NTLM
- **Failure Code:** 0xC000006A (STATUS_WRONG_PASSWORD), 0xC000006E (Account restriction - after lockout test)
- **Process Chain:** mstsc.exe -> cmd.exe -> whoami / net user (simulated)
- **Splunk Index:** wineventlog

## Detection Logic (SOC L1)

**SPL Query:**
