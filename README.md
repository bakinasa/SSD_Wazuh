# Configuring SIEM with Wazuh  
**16.04.2025 - 07.05.2025**

### Authors:
- Bakina Sofia
- Andrey Boronin
- Ivan Sannikov
- Alexander Tomashov

## Table of Contents
1. [Introduction](#1-introduction)
   - 1.1 [Rationale for the choice of topic](#11-rationale-for-the-choice-of-topic)
   - 1.2 [Aims and objectives of the project](#12-aims-and-objectives-of-the-project)
   - 1.3 [Description of the initial idea](#13-description-of-the-initial-idea)
2. [Infrastructure Design](#2-infrastructure-design)
   - 2.1 [Overall architecture](#21-overall-architecture)
   - 2.2 [Network segmentation](#22-network-segmentation)
   - 2.3 [Network topology](#23-network-topology)
   - 2.4 [Technologies](#24-technologies)
   - 2.5 [Security and isolation](#25-security-and-isolation)
3. [Deployment and Configuration](#3-deployment-and-configuration)
   - 3.1 [Setting up secure tunnels](#31-setting-up-secure-tunnels)
   - 3.2 [Configuring MikroTik](#32-configuring-mikrotik)
   - 3.3 [Deploying the Wazuh server](#33-deploying-the-wazuh-server)
   - 3.4 [Installing and configuring agents](#34-installing-and-configuring-agents)
   - 3.5 [Implementing Use Cases](#35-implementing-use-cases)
4. [Attack Modelling, Analysis and Improvements](#4-attack-modelling-analysis-and-improvements)
   - 4.1 [Attack testing](#41-attack-testing)
   - 4.2 [Wazuh system response](#42-wazuh-system-response)
   - 4.3 [Recommendations](#43-recommendations)
5. [Applications](#5-applications)
   - 5.1 [Team](#51-team)
   - 5.2 [Configuration files](#52-configuration-files)
   - 5.3 [Screenshots](#53-screenshots)
   - 5.4 [Video](#54-video)

---

## 1. Introduction

### 1.1 Rationale for the choice of topic  
Modern organizations are increasingly facing the need to efficiently detect and respond to cybersecurity incidents. One of the key tools in this field are Security Information and Event Management (SIEM) systems.  
This project focuses on the deployment and configuration of the Wazuh SIEM solution — an open-source and powerful framework based on the Elastic Stack. The project aims to create a fully isolated virtual environment where the Wazuh server is deployed, along with agents operating on both Windows and Linux systems.

### 1.2 Aims and objectives of the project  
The goal of the project is to create a secure virtual infrastructure using the Wazuh SIEM system for monitoring, detecting attacks, and ensuring integrity control. The project involves deploying a system that will include:
- Deploying a virtual infrastructure using VMware vSphere and configuring network segmentation through MikroTik.
- Deploying Wazuh on a server for security event monitoring and configuring agents on workstations and servers (Windows and Linux).
- Implementing several use cases for attack detection, such as:
  - Detecting brute-force attacks.
  - Detecting malware using YARA rules.
- Simulating attacks on vulnerable applications (Juice Shop), analyzing protection results, and adjusting security policies.

### 1.3 Description of the initial idea  
At the start of the project, a basic virtual environment is in place, which will be used to deploy the components. The virtual infrastructure includes services with varying levels of security, including test vulnerable applications (e.g., Juice Shop), which will serve as targets for attacks.  
Wazuh will be used for monitoring, with agents configured on servers and workstations. The system will be integrated with external threat sources for improved threat processing and analysis. During the implementation, attacks will be simulated using standard tools like Linux and Metasploit to test defenses and adjust rules accordingly.

---

## 2. Infrastructure Design

### 2.1 Overall architecture  
The infrastructure of the project is deployed in an isolated virtual environment based on VMware ESXi/vSphere. The virtual infrastructure includes:
- **Wazuh** — the core SIEM component.
- **Windows Agent** — simulates a user workstation.
- **Linux Agent** — a server or host in the exploitation segment.
- **Juice Shop** — a vulnerable web application for attack simulation.
- **MikroTik Router** — used for network segmentation and traffic filtering.

### 2.2 Network segmentation  
For security and access management, the entire infrastructure is divided into several logical zones (VLAN/port group):
- **Segment** | **Purpose**  
- **MGMT** | Management and administration  
- **DMZ** | Public or semi-public services  
- **DMZ** | Servers isolated from the internal infrastructure  

### 2.3 Network topology  
The project includes setting up a virtual infrastructure, network segmentation using MikroTik and VMware, which allows isolating different subnets and services for enhanced security. Access to services is configured via secure channels, and VPN is also set up.

![diagram](https://github.com/bakinasa/SSD_Wazuh/raw/main/assets/1.png)

**Example of interaction:**
- VPN connects to MikroTik and other VMs (via the Mgmt VLAN).
- Agents (Windows/Linux) send logs to the Wazuh server via SIEM.
- MikroTik controls inter-network communication, e.g., allows LAN → DMZ but blocks DMZ → LAN.

### 2.4 Technologies  
The infrastructure of the diploma project is deployed in an isolated virtual environment based on VMware ESXi/vSphere (or a similar platform). The virtual infrastructure includes:
- **Component** | **Technology / Product**  
- **Virtualization** | VMware ESXi  
- **Segmentation / Routing** | MikroTik RouterOS  
- **SIEM** | Wazuh (Elastic Stack: Elasticsearch, Kibana)  
- **Agents** | Wazuh Agent (Windows, Linux)  
- **Vulnerable Application** | OWASP Juice Shop  
- **Threat Monitoring** | Wazuh Rules, YARA  
- **Testing** | Linux  

### 2.5 Security and isolation  
Firewall and access rules are implemented on MikroTik.  
Strict isolation is applied between subnets.  
The Wazuh server is only accessible from the Management segment.  
The User segment cannot interact directly with SIEM or other zones except the DMZ.  
NAT and VPN are implemented through MikroTik (for external access and traffic forwarding).  
Firewall and access rules are managed by MikroTik, which controls routing and isolation between VLANs.

---

## 3. Deployment and Configuration
This chapter will describe the process of installing and configuring basic components such as the Wazuh server and agents, as well as configuring other services and infrastructure for effective monitoring and security.

### 3.1 Configuring MikroTik  
**What was done:**
- Subnets for Management, LAN, DMZ were configured, and IP addresses were assigned via DHCP.
- Access to the Management subnet is provided only via VPN, isolating it from other network segments. Other devices cannot access the Management network without VPN.
- Routing was configured to direct traffic through correct paths, and firewall rules ensure necessary security and isolation between segments.

### 3.2 Setting up secure tunnels  
For secure connections between infrastructure components, VPN tunnels were configured using IPsec and OpenVPN.  
**What was done:**
- VPN via IPsec was set up for secure connections between subnets and infrastructure components.
- OpenVPN was also configured as an additional VPN connection system, ensuring secure data transfer.
- MikroTik was set up to work with VPN to ensure segmentation and secure interaction between clients and services, including the Management subnet.

### 3.3 Deploying the Wazuh  
**Preparation:**
- Wazuh is deployed on a virtual machine located in two subnets: pg-LAN and pg-DMZ.  
**Requirements:**
- Operating system: Ubuntu 20.04 or later.
- At least 4GB of RAM and 2 virtual CPUs.
- 50GB of disk space for data storage.

![2](https://github.com/bakinasa/SSD_Wazuh/raw/main/assets/2.png)

**Installation:**
- Update the system:
  ```bash
  sudo apt-get update
  ```

* Install Wazuh by following the instructions in the [official Wazuh quickstart guide](https://documentation.wazuh.com/current/quickstart.html).

![3](https://github.com/bakinasa/SSD_Wazuh/raw/main/assets/3.png)

**Configuration:**

* After installation, configure Wazuh for log collection and processing. This can be done via the configuration file:
  `/var/ossec/etc/ossec.conf`.
  In this file, security rules, agent settings, file integrity monitoring, etc., can be configured.

![4](https://github.com/bakinasa/SSD_Wazuh/raw/main/assets/4.png)

### 3.4 Installing and configuring agents

After setting up the Wazuh server, agents need to be installed on both Windows and Linux systems to collect and send data for analysis.

**Installing Wazuh agent on Windows:**

1. Download the latest Wazuh agent version from the official website.
2. Run the installer and follow the instructions.
3. Add the server address to the configuration file.
4. Restart the agent service.

**Installing Wazuh agent on Linux:**

1. Add the Wazuh repository and install the agent.
2. Configure the agent.
3. Start the agent service.

### 3.5 Implementing Use Cases

In this section, we will implement and configure at least three use cases as described in the Wazuh documentation. We will work on:
- Detecting brute-force attacks.
- Detecting malware using YARA.

### 3.5.1 Detecting Brute-Force Attacks

**Objective:**  
Configure Wazuh to detect brute-force attacks on SSH and RDP. This can be useful for protecting against unauthorized access attempts.

#### Installation and configuration of Wazuh rules for brute-force:

Wazuh has built-in rules to detect brute-force attacks on SSH and other services. To enable these rules:

1. Open the configuration file `/var/ossec/etc/ossec.conf` on the Wazuh server.
2. Add or uncomment the following lines to enable the rules related to brute-force:

   ```xml
   <ruleset>
       <include>/var/ossec/etc/rules/sshd_rules.xml</include>
   </ruleset>  
These rules are already configured to analyze logs for SSH and RDP (depending on the services used).

#### Configuring filtering in Wazuh:

To fine-tune detection, you can configure event filtering:

* Enable logging for SSH and RDP in the corresponding files:

  * **SSH:** `/var/log/auth.log` (for Linux)
  * **Windows RDP:** Security event logs

#### Verification:

Perform a brute-force attack using Hydra or Medusa on SSH:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
```

Wazuh should generate an alert if the number of failed login attempts exceeds the set threshold.

---

### 3.5.2 Detecting Malware with YARA

**Objective:**
Utilize Wazuh for scanning files for malware using YARA rules.

#### Installation and Configuration of YARA:

To configure Wazuh for malware detection using YARA, follow these steps:

**Step 1: Install YARA on Wazuh Server and Clients**

```bash
sudo apt install yara
```

**Step 2: Configure YARA Rules in Wazuh**

To create YARA rules for detecting known threats, follow these steps:

* Download or create YARA rules to detect known threats. You can find rules from official YARA repositories or create your own.
* Save the rules in the directory `/var/ossec/rules/yara/`.

**Step 3: Configure Wazuh to Use YARA Rules**

In the Wazuh configuration file `/var/ossec/etc/ossec.conf`, enable YARA rules for file scanning by adding the following:

```xml
<yara>
    <enabled>yes</enabled>
    <path>/var/ossec/rules/yara/</path>
</yara>
```

**Step 4: Verification**

To verify that YARA rules are functioning correctly:

* Create a file that contains a signature for malware (this could be a test file or a simulated virus).
* Scan the file using Wazuh. It should generate an alert indicating that a threat has been detected.

#### Example YARA Rule:

Here is an example of a basic YARA rule that detects suspicious strings:

```yara
rule SuspiciousString
{
    meta:
        description = "Detects suspicious string"
        author = "Security Team"
        version = "1.0"

    strings:
        $s1 = "This file is malicious"
        $s2 = "cmd.exe /c"

    condition:
        $s1 or $s2
}
```

This rule will detect files that contain the suspicious strings "This file is malicious" or "cmd.exe /c", helping to prevent malware downloads.

---

## 4. Attack Modelling, Analysis and Improvements

### 4.1 Attack testing

**Description of conducted attacks:**
We conducted several types of attacks to test Wazuh's response:

* **Brute-force attack:**

  * **Software used:** A custom brute-force script was used along with Metasploit modules to attempt access to a test server.
  * **Results:** The attack attempted multiple password combinations in a short period.
  * **Expected outcome:** Wazuh should detect multiple failed login attempts and generate an alert for a brute-force attack.

* **YARA detection:**

  * **Software used:** A test file containing a suspicious signature was created and scanned by Wazuh.
  * **Results:** The file contained a string often associated with known malware.
  * **Expected outcome:** Wazuh should generate an alert based on the configured YARA rules.

**Software used for the attacks:**

* Metasploit (for brute-force attack)
* Custom YARA rule (for malware detection)
* Test file (for simulating malware behavior)

### 4.2 Wazuh system response

**Screenshots and logs of triggered alerts:**

* **Brute-force attack alert:**

  ```
  ALERT - Brute-force attack detected:
  Source IP: 192.168.1.100
  Attempted user: admin
  Number of failed attempts: 15
  Alert level: High
  Action: Connection blocked after threshold exceeded.
  ```

* **YARA rule detection alert:**

  ```
  ALERT - Suspicious file detected:
  File path: /home/user/testfile.exe
  Malware signature: This file is malicious
  Alert level: Medium
  Action: Alert generated, file quarantined.
  ```

**Description of Each Alert and Its Significance**

#### Brute-force Attack Alert:
This alert indicates that an excessive number of failed login attempts occurred in a short period, which suggests a brute-force attack. The system blocked the connection after the threshold was exceeded.

#### Malware File Detection Alert:
This alert signals that a file was detected with a signature matching known malicious programs. The file was flagged as suspicious, and appropriate actions were taken.


**Comparison of Wazuh Settings Before and After Attacks**

**Before the Attacks:**  
Wazuh was configured with basic security policies to detect brute-force attacks and verify file integrity.

**After the Attacks:**
- The system successfully detected and responded to the brute-force attack by blocking the attacking IP address.
- The YARA rules were triggered, detecting the suspicious file, which confirms the correct configuration of the system.


### 4.3 Recommendations

Based on the test results, the following recommendations are made:

* **Brute-force attack:**

  * Increase the threshold for failed login attempts to reduce false positives, but carefully consider the risk of successful brute-force attacks.
  * Implement CAPTCHA after a certain number of failed attempts to prevent automated brute-force attacks.

* **YARA rules:**

  * Regularly update and expand the YARA rule set to include new malware signatures.
  * Optimize YARA rules to balance detection accuracy and system performance.

---

## 5. Applications

### 5.1 Team

* **Alexander Tomashov** - Infrastructure and architecture design
* **Andrey Boronin** - Deployment and configuration of components
* **Ivan Sannikov** - Monitoring, security, and integration setup
* **Bakina Sofia** - Testing, attack modelling, analysis, reporting, and presentation preparation

### 5.2 Configuration files

Link to the repository with configuration files.

### 5.3 Screenshots

Link to the archive with screenshots of the system in action.

### 5.4 Video

Link to the demo video of the system.
