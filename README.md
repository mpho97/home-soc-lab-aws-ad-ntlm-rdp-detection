#home SOC Lab active Directory (NTML BRUTEFORCE Attack -> RDP COMPROMISE 
## Real Lab Evidence - MYDFIR.local (10/26/2026)

**Domain:** MYDFIR.local
**AD User:** Mpho Johannes MJ Tema - MTema@MYDFIR.local
**Region:** eu-north-1 (Stockholm)
**Splunk:** 16.170.40.157:8000 / 16.170.40.157:8000 - Splunk 10.6.1

**EC2 Instances:**
- ADDC-01: EC2AMAZ-6HLNKC8 - Public 13.49.41.220, Private 172.31.11.8, m7i.large, SG launch-wizard-2 (3389 TCP)
- WIN-10-TARGET: EC2AMAZ-LNLLFTL - Public 13.53.159.18, Private 172.31.3.111, m7i.large

**Splunk Detection:**
- Index mydfir-ad: 2,643 events ingested
- Index mydfir-sysmon: 154 x EventCode 4625 (Failed), 9 x EventCode 4624 (Success)
- Target: EC2AMAZ-LNLLFTL.MYDFIR.local - Logon Type 5, Elevated Token Yes
- MITRE: T1110.001 (Brute Force), T1021.001 (RDP), T1003.002 (NTLM)

**Attack Path:** Hydra RDP bruteforce to 13.53.159.18:3389 targeting MYDFIR.local user MTema

Screenshots: /screenshots/01-07
