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
  - Detecting suspicious processes using Sysmon.
  - Detecting process creation and termination events.
- Simulating attacks on vulnerable applications (Juice Shop), analyzing protection results, and adjusting security policies.

### 1.3 Description of the initial idea  
At the start of the project, a basic virtual environment is in place, which will be used to deploy the components. The virtual infrastructure includes services with varying levels of security, including test vulnerable applications (e.g., Juice Shop), which will serve as targets for attacks.  
Wazuh will be used for monitoring, with agents configured on servers and workstations. The system will be integrated with external threat sources for improved threat processing and analysis. During the implementation, attacks will be simulated using standard tools like Linux to test defenses and adjust rules accordingly.

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

![5](https://github.com/bakinasa/SSD_Wazuh/raw/main/assets/5.png)

### 3.5 Implementing Use Cases
In this section, we will implement and configure at least three use cases as described in the Wazuh documentation. We will work on:
- Detecting suspicious processes using Sysmon.
- Detecting process creation and termination events.

### 3.5.1 Detecting Suspicious Processes

**Objective:**  
Configure Wazuh to detect suspicious processes such as unauthorized or unusual processes (e.g., **lsass.exe**, **svchost.exe**, etc.).

#### Sysmon Rules Installation and Configuration:

1. To monitor processes such as **lsass.exe** and others, rules have been added to the Wazuh configuration.

   Example configuration for detecting suspicious processes:
   ```xml
   <group name="windows,sysmon,sysmon_process-anomalies,">
      <rule id="61625" level="12">
         <if_group>sysmon_event1</if_group>
         <field name="win.eventdata.image">lsass.exe</field>
         <description>Sysmon - Suspicious Process - lsass</description>
         <mitre>
            <id>T1055</id>
         </mitre>
         <group>pci_dss_10.6.1,pci_dss_11.4,gdpr_IV_35.7.d,</group>
      </rule>

      <rule id="61626" level="0">
         <if_sid>61625</if_sid>
         <field name="win.eventdata.parentImage">wininit.exe</field>
         <description>Sysmon - Legitimate Parent Image - lsass.exe</description>
      </rule>
   </group>

2. To ensure Sysmon logs are collected, the following configuration has been added to the Windows configuration:

   ```xml
   <localfile>
      <location>Microsoft-Windows-Sysmon/Operational</location>
      <log_format>eventchannel</log_format>
   </localfile>
   ```

#### Verification:

To verify the rule, create a copy of **lsass.exe** (or another suspicious process) and check Wazuh logs. If the process is suspicious, Wazuh should generate an alert indicating the process and its parent (e.g., `wininit.exe`).

---

### 3.5.2 Detecting Process Creation and Termination Events

**Objective:**
Monitor process creation and termination events, such as the starting and stopping of critical system processes.

#### Sysmon Event Rules for Process Creation and Termination:

1. Additional rules for monitoring process creation and termination have been added in the Wazuh configuration:

   ```xml
   <rule id="61603" level="5">
      <if_sid>61600</if_sid>
      <field name="win.system.eventID">^1$</field>
      <description>Sysmon - Event 1: Process creation $(win.eventdata.description)</description>
   </rule>

   <rule id="61605" level="0">
      <if_sid>61600</if_sid>
      <field name="win.system.eventID">^5$</field>
      <description>Sysmon - Event 5: Process terminated $(win.eventdata.image)</description>
   </rule>
   ```

2. These rules help to track processes that are created or terminated and ensure that no unauthorized processes are running or exiting without notification.

#### Verification:

To verify this use case, simulate the creation and termination of a process and check the Wazuh alerts:

* For a suspicious process like **csrss.exe**, Wazuh should trigger an alert.
* Similarly, on process termination, Wazuh should log an event indicating the process was terminated.

---

## 4. Attack Modelling, Analysis and Improvements

### 4.1 Attack Testing

**Description of conducted attacks:**

* **Detecting Suspicious Processes:**

  * A **process hacker** was used to simulate the launching of suspicious processes such as **lsass.exe**.
  * Result: Wazuh detected the suspicious process and identified the parent process (`wininit.exe`).

  ![7](https://github.com/bakinasa/SSD_Wazuh/raw/main/assets/7.png)


* **Detecting Process Creation and Termination Events:**

  * The creation and termination of processes were simulated using **Sysmon**.
  * Result: Wazuh detected the creation and termination events correctly.

**Software used for attacks:**

* **Process Hacker** (for simulating process creation)
* **Sysmon** (for event logging)
* **Test files** (for process termination events)

### 4.2 Wazuh System Response

**Screenshots and logs of triggered alerts:**

* **Suspicious Process Alert:**

![6](https://github.com/bakinasa/SSD_Wazuh/raw/main/assets/6.png)


**Description of Each Alert and Its Significance:**

* **Suspicious Process Alert:**
  This alert indicates that an unauthorized or suspicious process was detected. Wazuh flagged the process and identified the legitimate parent process.

---

### 4.3 Recommendations

Based on the test results, the following recommendations are made:

* **Suspicious Process Detection:**

  * Regularly update the list of processes to track and ensure that new threats are detected.
  * Consider adding more specific rules for new suspicious processes that may emerge.

* **Process Creation and Termination Events:**

  * Enable automatic actions based on alert levels (e.g., terminate processes with a high-level alert).
  * Optimize the balance between alert accuracy and system performance.

---

### Conclusion

This section demonstrates how to configure Wazuh to detect suspicious processes, such as **lsass.exe**, and monitor process creation and termination events using **Sysmon**. With these configurations in place, Wazuh can effectively monitor for unusual behavior in the system, providing enhanced security and monitoring capabilities.

---

## 5. Applications

### 5.1 Team

* **Alexander Tomashov** - Infrastructure and architecture design
* **Andrey Boronin** - Deployment and configuration of components
* **Ivan Sannikov** - Monitoring, security, and integration setup
* **Bakina Sofia** - Testing, attack modelling, analysis, reporting, and presentation preparation

### 5.2 Configuration files

[Link to the repository with configuration files.](https://github.com/bakinasa/SSD_Wazuh/tree/main)

### 5.3 Screenshots

[Link to the archive with screenshots of the system in action.](https://disk.yandex.ru/client/disk/SSD)

### 5.4 Video

[Link to the demo video of the system.](https://disk.yandex.ru/client/disk/SSD)

### 5.5 Settings that were also made

![8](https://github.com/bakinasa/SSD_Wazuh/raw/main/assets/8.png)

