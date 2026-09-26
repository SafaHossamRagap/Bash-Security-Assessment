# Bash Security Assessment Tool

A simple Bash-based security assessment tool developed as a practical
security project.

## Project Description

This project is a mini automated security assessment framework written
in Bash.

The tool performs reconnaissance, TCP port and service enumeration,
and automatically runs service-specific security checks based on the
services discovered on the target.

The project is designed for authorized lab environments and security
testing on machines that the user owns or has permission to assess.

## Features

- Target reachability check
- Hostname and basic network information
- TCP port scanning
- Service and version detection using Nmap
- Automatic service-based decision making
- FTP anonymous login check
- SSH banner check
- SMB share enumeration
- SMTP relay and user enumeration checks
- DNS zone transfer check
- HTTP header and robots.txt enumeration
- Evidence-based security findings
- Risk explanation and recommendations
- Automatic report generation

## Project Workflow

The tool follows these steps:

1. Check command-line arguments
2. Check required dependencies
3. Check target reachability
4. Perform reconnaissance
5. Scan TCP ports and detect services
6. Identify discovered services
7. Run the appropriate security check
8. Record findings and evidence
9. Generate reports

## Requirements

- Linux / Kali Linux
- Bash
- Nmap
- Curl
- Netcat
- SMBClient
- Dig

Some service-specific checks require their related tools to be installed.

## Usage

Make the script executable:

```bash
chmod +x securityscan.sh
./securityscan.sh 192.168.58.132
```
##Generated Reports

The tool generates three main reports:

scan.txt

Contains reconnaissance information, open ports, detected services,
and raw Nmap results.

findings.txt

Contains security findings with:

Finding title
Evidence
Risk
Recommendation
summary.txt

Contains a short summary of the scan, discovered services, and the
total number of findings.

Example Findings

During testing in an authorized vulnerable lab environment, the tool
was able to identify examples such as:

SSH banner information disclosure
SMTP user enumeration
Web server information disclosure
SMB shares accessible without authentication
Security Notice

This tool is intended only for:

Systems owned by the user
Authorized penetration-testing environments
Local virtual machines
Educational labs and CTF environments

Do not use this tool against systems without permission.

Technologies
Bash
Nmap
Curl
Netcat
SMBClient
Dig
Linux command-line utilities

Academic Project

Bash Security Assessment Tool
Security / Cybersecurity Practical Project


