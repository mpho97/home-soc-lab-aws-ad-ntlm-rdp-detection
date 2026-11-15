# Home SOC Lab on AWS - Active Directory (NTLM Bruteforce -> RDP Compromise)

**SOC Analyst L1 Project | Splunk SIEM | AWS EC2 | Active Directory | MITRE ATT&CK**
> Simulated NTLM bruteforce against AD account via RDP, detected with Splunk Enterprise on Ubuntu 22.04

Author: **Mpho Johannes Tema** | mphotema97@gmail.com | Security+ SY0-701

## Architecture
- AWS EC2 - af-south-1
    - Windows Server 2019 - AD Domain Controller (ad.lab.local)
    - Windows 10 Pro - Domain Joined, RDP Enabled 3389, Sysmon + UF
    - Ubuntu 22.04 LTS - Splunk Enterprise Free + Windows TA
    - Kali Linux - Attacker
- Security Groups: RDP 3389, Splunk 8000/8089, SSH 22
- Pipeline: Security Logs -> UF -> index=wineventlog

## Attack Path (AD Focus)
- Hydra: hydra -l administrator -P rockyou.txt rdp://<EC2_WIN_IP>
- MITRE: T1110.001 Brute Force, T1021.001 RDP, T1003.002 NTLM Hash

## Detection (SOC L1)
Logs: 4625 Failed Type10, 4624 Success Type10, 4778 Session, 4672 Privileges, 4768/4776 NTLM Auth

SPL:
index=wineventlog EventCode=4625 Logon_Type=10 Authentication_Package=NTLM
| stats count by Src_IP, Target_Account_Name
| where count > 10

Correlation: 4625 burst (47 failed 0xC000006A) -> 4624 success -> 4778 session -> 4672 admin

## Incident Response
Contain: SG block IP, disable AD account
Eradicate: Reset AD pwd, enforce NLA, LSA Protection
Recover: Account lockout policy, MFA

## Tools
AWS EC2, AD DS, Ubuntu 22.04, Splunk SPL, Sysmon, MITRE Navigator, Wireshark, Hydra

Screenshots: See /screenshots folder
