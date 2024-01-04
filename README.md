# Azure Honeynet: Simulating Real-World Cyber Attacks

![Project Overview](https://github.com/AngelPerales10/Azure-Honeynet-SOC/assets/108242721/fb7b03bd-b241-4915-9921-46f499128554)

## Introduction

To earn hands-on experience dealing with real attacks and learning how to defend against them, I decided to create a Honeynet utilizing Azure and the cloud platform's technologies.
## Objective

The goal of this lab is to use Azure to create intentionally vulnerable virtual machines, with the intention of attracting and analyzing cyber attacks.
## Technologies, Regulations, and Azure Components Employed:

- Azure Virtual Network (VNet)
- Azure Network Security Group (NSG)
- Virtual Machines (2x Windows, 1x Linux)
- Log Analytics Workspace with Kusto Query Language (KQL) Queries
- Azure Key Vault for Secure Secrets Management
- Azure Storage Account for Data Storage
- Microsoft Sentinel for Security Information and Event Management (SIEM)
- Microsoft Defender for Cloud to Protect Cloud Resources
- Windows Remote Desktop for Remote Access
- Command Line Interface (CLI) for System Management
- PowerShell for Automation and Configuration Management
- [NIST SP 800-53 Revision 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) for Security Controls
- [NIST SP 800-61 Revision 2](https://www.nist.gov/privacy-framework/nist-sp-800-61) for Incident Handling Guidance

## Methodology

### **Creating the Honeynet:**
Deployment of three virtual machines would be needed.

2x Windows and 1x Linux:
- First Window and Linux machine will be configured to allow all incoming traffic from any port and protocol.
- Second Window machine will be used as our attacker VM to test configurations and alerts. 

The Windows Firewall within the Windows VM had been turned off, and the Network Security Groups (NSG) for both machines in Azure were configured to allow unrestricted traffic from the internet.

### **Setting up Logging and Security Alerts:**
Using Log Analytic Workspace, Azure was able to ingested logs from our lab resources. 

Microsoft Sentinel was employed soon after to construct attack maps, generate and trigger alerts, and create incidents based on the data planned to be collected. 

### **Launching Vulnerable Virtual Machines:**
For 24 hours, the Windows and Linux machines were exposed to the public internet.

### **Incident Response and Remediation:**
Incidents were triggered during these 24 hours through Sentinel. The incidents were observed, and the environment was hardened through the implementation of Azure-specific security recommendations.

Additional security implementations include:

[NIST SP 800-53 Revision 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) for Security Controls

[NIST SP 800-61 Revision 2](https://www.nist.gov/privacy-framework/nist-sp-800-61) for Incident Handling Guidance
### **Post-remediation Analysis:**
For 24 hours, the Windows and Linux machines ran once again after implementing Azure and NIST security controls.

Comparison of the two using attack maps are illustrated below.
## Attack Maps Before Hardening / Security Controls

### NSG Set To Allow All Inbound Traffic:
---
![NSGMaliciousAllowedIn](https://github.com/AngelPerales10/Azure-Honeynet-SOC/assets/108242721/0aa88867-009f-4232-aa46-e39c81bf5b1d)

### Windows RDP / SMB Authorization Attempts:
---
![Windows24hours_exposed](https://github.com/AngelPerales10/Azure-Honeynet-SOC/assets/108242721/6586dc85-4866-497b-8ac2-4471fdfa0def)

### Linux SSH Authorization Attempts:
---
![Linux24hours_exposed](https://github.com/AngelPerales10/Azure-Honeynet-SOC/assets/108242721/5ad9da25-e2eb-40c6-ab21-f6bba170945f)

### MySQL Server Authorization Attempts:
---
![MySQL_exposed](https://github.com/AngelPerales10/Azure-Honeynet-SOC/assets/108242721/8ee029e2-0d59-44a0-8bcd-7fd5bf1721d7)

## Attack Maps After Hardening / Security Controls

All map queries returned no results due to zero instances of malicious activity for the 24 hour period after hardening.

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours: Start Time 2023-12-29 21:03:00 PM Stop Time 2023-12-29 21:03:00 PM

|Metric|Count|
|---|---|
|SecurityEvent (Windows VM)|22421|
|Syslog (Linux VM)|2345|
|SecurityAlert (Microsoft Defender for Cloud|4|
|SecurityIncident (Sentinel Incidents)|237|
|NSG Inbound Malicious Flows Allowed|4060|

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls: Start Time 2023-12-31 10:00:00 Stop Time 2023-01-01 10:00:00

| Metric                                      | Count |
| ------------------------------------------- | ----- |
| SecurityEvent (Windows VM)                  | 10235 |
| Syslog (Linux VM)                           | 5     |
| SecurityAlert (Microsoft Defender for Cloud | 0     |
| SecurityIncident (Sentinel Incidents)       | 0     |
| NSG Inbound Malicious Flows Allowed         | 0     | 

## Conclusion

To conclude, I created a simple but effective Honeynet environment using Azure and it's resources to allow me to study the behavior of threat actors when they identify an unsecure network.

Microsoft Sentinel was used to trigger alerts and create incidents. This was done using the watch list that was added so Sentinel can query the data generated from the vulnerable virtual machines.  If the query generated a result, an alert was made.

Following the alerts, baseline data was recorded and Azure and NIST security controls were implemented on the vulnerable network. 

The machines ran again to test the new fortification of our lab's resources, and then a comparison was made at the impact of enforcing security measures on a vulnerable environment.
