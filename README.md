# Suricata IDS Home-Lab

## ℹ️Overview

The goal of setting up a Suricata home-lab is to gain practical experience in deploying and configuring an Intrusion Detection System (IDS) for network security monitoring. Suricata is an open-source IDS capable of detecting and preventing various network-based threats. This home-lab provides individuals with hands-on experience in setting up, configuring, and utilizing Suricata to enhance network security.  
![Blue Sand White Beach Simple Watercolor Etsy Shop Banner (2)](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab/assets/40385860/328b7120-7f15-4436-9885-de6ffbcb8063)

In this home-lab, we will cover:
- [Requirement](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab?tab=readme-ov-file#requirements)
- [Lab Diagram](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab?tab=readme-ov-file#%EF%B8%8Flab-diagram)
- [Setting up the Suricata Home-Lab](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab?tab=readme-ov-file#-setting-up-the-suricata-home-lab)
- [Excercises- Network-based attacks](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab?tab=readme-ov-file#excercises--network-based-attacks)
- [Excercises- Web-based attacks](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab?tab=readme-ov-file#excercises--web-based-attacks)
- Need Training?


## 🧮Requirements

- **Hardware**:
  - Computer with at least 16GB RAM and dual-core processor
- **VM/ISO Image**:
  - Windows Machine(Victim Machine)
  - Kali Linux(Attacker Machine)

## 🖼️Lab Diagram

![Home-Lab (3)](https://github.com/0xrajneesh/Home-Lab/assets/40385860/f7891499-7a73-4f03-99dc-df2a2720904c)



## </> Setting up the Suricata Home-Lab

- **Setting up Suricata IDS Server**
  -  Import Ubuntu Server 22.04 OVA file in Virtualbox
  -  Install Suricata IDS package
 
- **Setting up Victim Server-1**
  -  Import Ubuntu Server 22.04 OVA file in Virtualbox
  -  Install DVWA(Damn Vulnerable Web Application)

- **Setting up Victim Server-2**
  -  Import Metasploitable 2 OVA Image
 
- **Setting up Victim Server-3**
  -  Import Typhoon OVA image
 


## 🧑‍💻Excercises- Network-based attacks
-  **Nmap Stealth Scan Detection**: Create a Suricata rule to detect TCP SYN packets sent to multiple ports within a short time frame, indicative of Nmap stealth scans.
  ```yaml
alert tcp any any -> any any (msg:"Nmap Stealth Scan Detected"; flags:S; threshold: type threshold, track by_src, count 5, seconds 10; sid:100001;)
```        
-  **Nmap OS Fingerprinting Detection**: Develop a Suricata rule to detect ICMP echo requests and responses with specific TTL values, characteristic of Nmap OS fingerprinting activities.
  ```yaml
alert icmp any any -> any any (msg:"Nmap OS Fingerprinting Detected"; ttl: 64; content:"ECHO REQUEST"; sid:100002;)   
alert icmp any any -> any any (msg:"Nmap OS Fingerprinting Detected"; ttl: 128; content:"ECHO REPLY"; sid:100003;)
```
-  **Nmap Service Version Detection Detection**: Formulate a Suricata rule to detect Nmap service version detection probes based on unique HTTP GET requests or TCP SYN/ACK packets.
  ```yaml
alert tcp any any -> any any (msg:"Nmap Service Version Detection Probe Detected"; content:"GET"; http_method; sid:100004;)
alert tcp any any -> any any (msg:"Nmap Service Version Detection Probe Detected"; flags:SA; sid:100005;)
```
-  **Metasploit Exploit Payload Detection**: Craft a Suricata rule to detect Metasploit exploit payload traffic based on unique signatures or payloads commonly used in exploits.
  ```yaml
alert tcp any any -> any any (msg:"Metasploit Exploit Payload Detected"; content:"<metasploit_payload>"; sid:100006;)
```
-  **Metasploit Reverse Shell Detection**: Develop a Suricata rule to detect Metasploit reverse shell connections by monitoring for outbound TCP connections to known attacker IP addresses.
```yaml
alert tcp any any -> <attacker_ip> any (msg:"Metasploit Reverse Shell Connection Detected"; sid:100007;)
```
-  **Metasploit Meterpreter Communication Detection**: Create a Suricata rule to detect Meterpreter communication activities by analyzing HTTP or TCP traffic with characteristic Meterpreter payloads.
  ```yaml
alert tcp any any -> any any (msg:"Meterpreter Communication Detected"; content:"<meterpreter_payload>"; sid:100008;)
```
- **Metasploit Credential Harvesting Detection**: Formulate a Suricata rule to detect Metasploit credential harvesting activities by monitoring for specific LDAP or SMB traffic patterns indicative of credential theft.
  ```yaml
  alert tcp any any -> any any (msg:"Metasploit Credential Harvesting Activity Detected"; content:"LDAP" content:"SMB"; sid:100009;)
  ```

## 🧑‍💻Excercises- Web-based attacks

-  **Web Server Enumeration Detection**: Develop a Suricata rule to detect Nmap web server enumeration attempts by monitoring for excessive HTTP GET requests to various URIs.
```yaml
alert http any any -> any any (msg:"Web Server Enumeration Attempt Detected"; urilen:>100; threshold: type threshold, track by_src, count 10, seconds 60; sid:100010;)
```
-  **Web Application Vulnerability Scan Detection**: Create a Suricata rule to detect Nmap vulnerability scanning activities against web applications by monitoring for specific HTTP requests targeting common vulnerabilities (e.g., SQL injection, XSS).
  ```yaml
alert http any any -> any any (msg:"Web Application Vulnerability Scan Detected"; content:"SQL Injection" content:"XSS"; sid:100011;)
```
-  **Metasploit Web Application Exploitation Detection**: Formulate a Suricata rule to detect Metasploit web application exploitation attempts by monitoring for HTTP requests containing known exploit payloads (e.g., SQL injection, remote code execution).
  ```yaml
alert http any any -> any any (msg:"Metasploit Web Application Exploitation Attempt Detected"; content:"<exploit_payload>"; sid:100012;)
```
-  **Metasploit Command Injection Detection**: Develop a Suricata rule to detect Metasploit command injection attacks by monitoring for HTTP requests with suspicious command injection payloads in URI parameters or POST data.
```yaml
alert http any any -> any any (msg:"Metasploit Command Injection Attempt Detected"; content:";"; sid:100013;)
```
-  **Metasploit Directory Traversal Detection**: Create a Suricata rule to detect Metasploit directory traversal attempts by monitoring for HTTP requests with traversal patterns in URI paths.
```yaml
alert http any any -> any any (msg:"Metasploit Directory Traversal Attempt Detected"; content:"../"; sid:100014;)
```
-  **Metasploit Cross-Site Scripting (XSS) Detection**: Formulate a Suricata rule to detect Metasploit XSS attacks by monitoring for HTTP responses containing characteristic XSS payloads or script injection patterns.
```yaml
alert http any any -> any any (msg:"Metasploit XSS Attack Detected"; content:"<script>"; sid:100015;)
```
- **Metasploit SQL Injection Detection**: Develop a Suricata rule to detect Metasploit SQL injection attacks by monitoring for SQL injection payloads in HTTP requests or SQL error messages in HTTP responses.
```yaml
alert http any any -> any any (msg:"Metasploit SQL Injection Attempt Detected"; content:"SQL Error"; sid:100016;)
```
- **Metasploit File Inclusion Detection**: Create a Suricata rule to detect Metasploit file inclusion attacks by monitoring for HTTP requests with suspicious file inclusion payloads in URI parameters or POST data.
```yaml
  alert http any any -> any any (msg:"Metasploit File Inclusion Attempt Detected"; content:"../../"; sid:100017;)
  ```
- **Metasploit Cross-Site Request Forgery (CSRF) Detection**: Formulate a Suricata rule to detect Metasploit CSRF attacks by monitoring for unexpected or unauthorized HTTP requests originating from victim hosts.
```yaml
alert http any any -> any any (msg:"Metasploit CSRF Attack Detected"; content:"CSRF Token"; sid:100018;)
```
- **Metasploit Authentication Bypass Detection**: Develop a Suricata rule to detect Metasploit authentication bypass attempts by monitoring for HTTP requests with bypass techniques (e.g., parameter manipulation, session fixation).
```yaml
  alert http any any -> any any (msg:"Metasploit Authentication Bypass Attempt Detected"; content:"Admin=true"; sid:100019;)
  ```

## Need Training




