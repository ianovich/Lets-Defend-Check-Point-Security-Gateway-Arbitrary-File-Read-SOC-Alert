# Lets-Defend-Check-Point-Security-Gateway-Arbitrary-File-Read-SOC-Alert
## Overview

**CVE-2024-24919** is a zero-day vulnerability affecting Check Point Security Gateways. This security flaw allows for arbitrary file reads, potentially exposing sensitive system files to unauthorized users. The issue is due to improper handling of HTTP requests by the affected devices, which can be exploited by an attacker to gain access to restricted files.

## Alert Triggered
![trigger](https://github.com/user-attachments/assets/1e1b52ff-4475-4508-9cd7-43cf6c5b52bc)

- At first I searched the suspicious traversal file execution request made by the attacker and discovered that it was from an external IP address directed to a target machine in the internal network
  
![traversal 1](https://github.com/user-attachments/assets/bb87d202-a3cd-496a-8455-3d0229eaece2)

- On June 6, 2024, at 15:12:45 UTC, a POST request was made to the /clients/MyCRL endpoint. The request included a payload with a path traversal attempt: aCSHELL/../../../../../../../../../../etc/passwd. The server responded with an HTTP 200 status code, indicating that the request was processed successfully. This log entry suggests that the server may be vulnerable to path traversal attacks, potentially exposing sensitive files such as /etc/passwd.

![injection2](https://github.com/user-attachments/assets/caef81c7-6480-40ba-9656-8b250983882b)

- Additionally, the IP address 203.160.68.12 involved in this request has been flagged as malicious by VirusTotal. This raises significant concerns about the potential exploitation of a path traversal vulnerability and the involvement of a known malicious actor. Immediate investigation and remediation are recommended to address the security risk and mitigate potential threats.
  
![virus total](https://github.com/user-attachments/assets/b0c0212c-5448-413c-b031-0343329f74c6)

 - To ensure comprehensive analysis, I also cross-checked the IP address on AbuseIPDB. This multi-platform verification confirmed the malicious nature of the IP, reinforcing the need for urgent action.It was confirmed that the IP had been reported twice as malicious with attack types of web attack and non authorized port scanning
   
 ![abuseip](https://github.com/user-attachments/assets/900f73ca-874f-4b5e-b9e0-9b0d4271e85c)
 
- Upon investigating the security incident, I found that the attacker's IP address, 203.160.68.12, was active within our network at the time of the attack, which occurred on June 6, 2024, at 15:12:45 UTC.

![process1](https://github.com/user-attachments/assets/b4413211-a1f9-40df-a462-7662a99330ff)

- The affected server was identified with the hostname CP-Spark-Gateway-01, with  the IP address 172.16.20.146 which was the attacker's target was immediately contained to prevent further damage and further investigation by tier 2 to be done.
   
![contain](https://github.com/user-attachments/assets/3714fd38-4189-4cfa-8f29-1d8cda6ef9d4)

## Resolving the case in the Playbook

- It was confirmed that the traffic was indeed malicious
  
![malicious](https://github.com/user-attachments/assets/b7b30c71-0cc2-4ef3-aecf-0ed8a4c6b997)

- The attack was confirmed to be under LFI/RFI attack.

![LFI](https://github.com/user-attachments/assets/2bbbdc5f-d8fc-4146-af17-01363393724f)

- The attack was not planned as there was no email regarding a penetration test that was supposed to be done.

![not planned](https://github.com/user-attachments/assets/10775612-bfd8-43f1-ba0b-45c8aaf3c881)

- The attack was from an external IP address directed to the company network.

![net to com](https://github.com/user-attachments/assets/24890344-208e-45cf-af62-a0a02fe6ea47)

- The attack was successful due to the fact that the server responded with an HTTP 200 status code, indicating that the request was processed successfully.
  
![Attack](https://github.com/user-attachments/assets/bde4c7e4-90e7-401d-8e13-9910974b0a01)

The attack requires escalation to the Tier2 and incidence resposne team so as to block the malicious IP address and conduct further investigation.

![escalate](https://github.com/user-attachments/assets/6d1841c2-4d01-40be-9362-2fa2dc21d885)


- The IOC's were jotted down
  
![artifacts](https://github.com/user-attachments/assets/bbcd1c36-6a0b-4ed9-a5df-12e4d28a59e1)

- The final results indicating that it was a true positive and indeed the target machine was compromised.

![results](https://github.com/user-attachments/assets/441626b4-6e92-45dd-b3f6-08aaf4a45b8b)

















