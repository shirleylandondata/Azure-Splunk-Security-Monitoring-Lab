
# Azure Splunk SIEM: Windows Security Monitoring & Detection

**Deploying a free-tier SIEM on Azure to centralize Windows logging, build detections, and operationalize a SOC workflow**

![Splunk](https://img.shields.io/badge/Splunk-Enterprise%20Free-000000?logo=splunk&logoColor=white)
![Azure](https://img.shields.io/badge/Microsoft%20Azure-VM-0078D4?logo=microsoftazure&logoColor=white)
![Windows](https://img.shields.io/badge/Windows%20Server-Event%20Logs-0078D4?logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [The Business Problem](#the-business-problem-this-lab-solves)
- [Relevance to Security Roles](#relevance-to-security-roles)
- [Key Concepts](#key-concepts)
- [Skills Demonstrated](#skills-demonstrated)
- [Lab Environment](#lab-environment)
- [Implementation Summary](#implementation-summary)
  - [1. Splunk Enterprise Deployment](#1-splunk-enterprise-deployment)
  - [2. Data Input Configuration](#2-data-input-configuration)
  - [3. SPL Searches](#3-spl-searches)
  - [4. Security Dashboard](#4-security-dashboard)
  - [5. Automated Security Detection](#5-automated-security-detection)
- [Build Notes — Troubleshooting & Real-World Fixes](#build-notes--troubleshooting--real-world-fixes)
- [Appendix — Extended Detections](#appendix--extended-detections)
- [Security Notes](#security-notes)

---

## Overview

| Field | Value |
|---|---|
| **Certifications aligned** | CompTIA Security+ · CySA+ · Splunk Core Certified User |
| **Tooling** | Splunk Enterprise (60-day trial → permanently free, 500MB/day) |
| **Time to complete** | 4–6 hours across multiple sessions |
| **Cost** | $0 — Splunk Free license covers everything in this lab |
| **Career relevance** | SOC Analyst (Tier 1–3) · Security Engineer · Incident Responder |

This lab stands up a self-hosted Splunk SIEM on an Azure VM, forwards Windows Security/System/Application event logs from a domain controller (built in a prior lab) over the Splunk Universal Forwarder, and operationalizes that data through SPL searches, a security monitoring dashboard, and a tuned privileged-logon detection — the same core workflow used in production SOC environments.

Because the Splunk VM and the Windows Server/domain controller VM were provisioned into two separate Azure VNets, this build also required actual VNet peering and several rounds of real network and service troubleshooting — documented in [Build Notes](#build-notes--troubleshooting--real-world-fixes) below — rather than a clean, uneventful walkthrough.

---

## Architecture

The diagram below shows the full data path: Windows Server generates event logs → Universal Forwarder ships them encrypted over port 9997 → Splunk indexer parses and stores them → Splunk Web UI exposes search/dashboards/alerts → the SOC analyst investigates through a browser.

<img width="1201" height="881" alt="Splunk-architecture-diagram" src="https://github.com/user-attachments/assets/7119fa12-feee-46ff-9f88-713e1e167572" />


**Design decisions baked into this architecture:**
- **Least-privilege NSG scoping** — port 8000 (Web UI) and 22 (SSH) are restricted to a single admin IP; port 9997 (forwarder ingestion) is restricted to the peered VNet address range only, never exposed to the public internet.
- **Separation of roles** — the Windows Server VM (log source / domain controller) and the Splunk VM (indexer + search head) are distinct hosts, mirroring how forwarders and indexers are separated in real deployments.
- **Static IP addressing** recommended on the Splunk VM to avoid NSG/bookmark drift across VM restarts.
- **Cross-VNet reality:** the two VMs in this build landed in separate Azure VNets (`Lab1-VM-vnet` for the domain controller, `vnet-eastus2-1` for Splunk). Rather than rebuilding into a single VNet, **VNet peering** (`Splunk-to-Lab1` / `Lab1-to-Splunk`) was configured to connect them privately — a realistic scenario, since production environments frequently need to bridge resources that were provisioned independently. For a *new* multi-VM lab, a single shared VNet with one subnet per VM is still simpler and avoids peering entirely.

---

## The Business Problem This Lab Solves

A medium-sized organization generates millions of log events every day — Windows Event Logs from workstations, authentication logs from Active Directory, firewall logs, web server access logs, cloud resource logs. Without a SIEM, that data sits siloed across systems: nobody can search across it, correlate events, or spot patterns that indicate an attack.

The SIEM is the SOC's primary tool. When an alert fires, an analyst opens the SIEM to understand what happened, when, from where, and what was affected. Splunk is the most widely deployed commercial SIEM — building real, demonstrable experience with it maps directly onto job requirements across nearly every security operations role.

## Relevance to Security Roles

| Role | How this lab applies |
|---|---|
| **SOC Analyst Tier 1** | Monitoring dashboards for alerts, searching logs for suspicious activity, escalating findings |
| **SOC Analyst Tier 2–3** | Building detection rules, correlating events across data sources, threat hunting |
| **Cloud Security Engineer** | Microsoft Sentinel and AWS Security Hub use the same SIEM concepts — this lab builds the underlying mental model |
| **Incident Responder** | Searching logs during an active incident, building a timeline, identifying scope of compromise |

---

## Key Concepts

<details>
<summary><strong>SIEM (Security Information and Event Management)</strong></summary>

Collects log data from across the environment and makes it centrally searchable. Two core jobs: **correlation** (connecting events across systems to reveal patterns no single system would show) and **alerting** (notifying analysts automatically when suspicious conditions are met).
</details>

<details>
<summary><strong>SPL — Splunk Processing Language</strong></summary>

A pipeline query language: start with a search, then pipe results through commands that filter, transform, and visualize. Example:

```spl
index=windows_logs EventCode=4624 | stats count by Account_Name | sort -count
```
</details>

<details>
<summary><strong>Splunk Index</strong></summary>

A named storage bucket for events — conceptually similar to a database table. Separate indexes per data source (Windows, firewall, web) allow independent retention and permission control. This lab uses a single index: `windows_logs`.
</details>

<details>
<summary><strong>Universal Forwarder</strong></summary>

A lightweight, free agent installed on any machine whose logs need shipping to Splunk. Monitors log files/Windows Event Logs, compresses and encrypts data, and forwards it to the indexer over port 9997. Low CPU/RAM footprint, designed to run invisibly on production hosts.
</details>

<details>
<summary><strong>Key Windows Event IDs used in this lab</strong></summary>

| Event ID | Meaning |
|---|---|
| `4624` | Successful logon |
| `4625` | Failed logon |
| `4648` | Explicit credential logon (lateral movement / credential abuse indicator) |
| `4672` | Privileged (admin-rights) logon |
| `4688` | New process created |
| `4697` | New service installed (persistence indicator) |
| `4740` | Account lockout |
</details>

<details>
<summary><strong>inputs.conf</strong></summary>

Configuration file on the forwarder host that defines what data to collect. Each `[section]` in square brackets defines one log source (e.g. `[WinEventLog://Security]`), with settings like `disabled=0` (enabled) and `index=windows_logs` controlling routing.
</details>

---

## Skills Demonstrated

| Skill | Real-world application |
|---|---|
| Deploy Splunk and configure a data input | Every Splunk deployment starts with getting data in — the Universal Forwarder is how most enterprise environments feed logs to Splunk |
| Navigate the Splunk interface | Search, dashboards, alerts, reports — understanding the layout is table stakes for any SOC role |
| Write SPL searches | The skill that separates analysts who find threats from analysts who stare at dashboards |
| Build security dashboards | Visualizing login failures over time, top source IPs, failed authentication by user |
| Identify failed login patterns | Distinguishing normal user error from a brute-force attack |
| Build an automated alert | Tuned a scheduled detection by filtering noisy system/machine accounts and setting a threshold based on observed data, rather than using a default value |
| Search for account lockout events | A trail of lockouts can indicate a password-spray attack in progress |

---

## Lab Environment

| VM Setting | Value |
|---|---|
| OS | Ubuntu 24.04 LTS (Azure free-tier eligible) |
| Size | `Standard_B2s` — 2 vCPU / 4GB RAM minimum (Splunk requires ≥ 4GB) |
| Disk | 30GB minimum |
| Splunk VM network | `vnet-eastus2-1`, private IP `172.16.0.4` |
| Domain controller VM network | `Lab1-VM-vnet`, private IP `10.0.0.4` — peered to the Splunk VNet |
| Inbound NSG ports | `8000` (Splunk Web UI, my-IP only) · `9997` (forwarder input, peered VNet only) · `22` (SSH, my-IP only) |
| Authentication | SSH public-key (`.pem` from Azure, converted to PuTTY `.ppk`) — not password-based |
| Log source | Windows Server VM from prior Active Directory lab, also serving as the domain controller for `Lab1VM.local` |

---

## Implementation Summary

### 1. Splunk Enterprise Deployment

- Provisioned an Ubuntu 24.04 Azure VM and downloaded the Splunk Enterprise `.deb` package.
<img width="1403" height="652" alt="01-azure-splunkvm-overview" src="https://github.com/user-attachments/assets/b18889be-5d99-4f55-b2a8-f60c72ae32ae" />

- Installed via `dpkg -i`, started the service with `--accept-license --run-as-root`, and enabled boot-start persistence.

- Connected via SSH public-key authentication rather than a password: converted the Azure-issued `.pem` key to PuTTY's `.ppk` format with PuTTYgen, loaded it under **Connection → SSH → Auth → Credentials**, and set the auto-login username so PuTTY connects non-interactively.


- Scoped NSG rules so the Web UI and SSH are reachable only from an admin IP, and the forwarder-ingest port is reachable only from the peered VNet — never the public internet.

<img width="1420" height="647" alt="02-nsg-inbound-rules" src="https://github.com/user-attachments/assets/f5a4681e-0e9d-4d7d-a175-43c6229a8b83" />

<img width="1259" height="784" alt="03-splunk-web-login" src="https://github.com/user-attachments/assets/05cf9ba1-a65d-4a33-b585-12a7e9c97728" />

```bash
wget -O splunk-10.2.2-linux-amd64.deb "https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb"
sudo dpkg -i splunk-10.2.2-linux-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root
sudo /opt/splunk/bin/splunk enable boot-start
```



### 2. Data Input Configuration

- Enabled receiving on port `9997` and created a dedicated index, `windows_logs`, in the Splunk Web UI.
- Installed the Universal Forwarder on the Windows Server VM, pointing it at the Splunk indexer's **private** IP on port `9997` (no Deployment Server configured).
- Authored `inputs.conf` to forward the `Security`, `System`, and `Application` Windows Event Logs into `windows_logs`:

```ini
# C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf

[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1
index = windows_logs

[WinEventLog://System]
disabled = 0
index = windows_logs

[WinEventLog://Application]
disabled = 0
index = windows_logs
```
**Settings → Forwarding and Receiving → Configure Receiving, showing port 9997 enabled.**
> <img width="899" height="572" alt="06-forwarder-inputs" src="https://github.com/user-attachments/assets/ea27e2d7-b90f-45cd-ab3e-b4c964e8efe4" />

*Used a PowerShell log-generation script to simulate realistic SOC-relevant activity on a fresh VM — failed logons, a successful logon, service restarts, application warnings, and an account lockout — to validate the pipeline end-to-end before searching.*

**Receiving Ports Configuration**
> <img width="918" height="583" alt="04-receiving-port-config" src="https://github.com/user-attachments/assets/e1edbb50-4d95-4015-aec3-bdf2c8f431c1" />

**Index Created**
> <img width="1250" height="631" alt="05-index-created" src="https://github.com/user-attachments/assets/96b1b0eb-638d-43c3-b5a7-0d8e7a565ba0" />

**PowerShell console output from the the log-generation script**
> 
<img width="1068" height="779" alt="07-log-generator-output" src="https://github.com/user-attachments/assets/9c6ff7b5-1128-4963-bfe8-0e8a601f1429" />



### 3. SPL Searches

| Purpose | Search |
|---|---|
| Confirm data is flowing | `index=windows_logs \| head 100` |
| Successful logins by account | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4624 \| stats count by Account_Name \| sort -count` |
| After-hours logins | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4624 \| eval hour=strftime(_time,"%H") \| where hour<7 OR hour>19 \| table _time, Account_Name, Account_Domain, ComputerName \| sort -_time` |

**Actual results from this environment:**
- The successful-logins search returned **762 Event 4624 records in the last 24 hours**, correctly grouped by `Account_Name` — including 3 successful logons from the `Slandon` user account, alongside high-volume machine and Windows service accounts.
  
<img width="1515" height="808" alt="search-4624" src="https://github.com/user-attachments/assets/ad5136e2-df78-4907-885e-48be67a8a3db" />

- The after-hours search returned **773 events** outside the 7am–7pm window. Most of this volume came from machine/service accounts (e.g. `Lab1-VM$`) rather than human users, so this is documented as an *after-hours authentication monitoring query* rather than a claim that all 773 events were suspicious — an important distinction when presenting this kind of data to a SOC audience.

> 📸 **Screenshot placeholder:** `images/08-data-flowing-confirmed.png` — results of `index=windows_logs | head 100`, proving the pipeline is live.

> <img width="1906" height="913" alt="09-Successful-logins-search" src="https://github.com/user-attachments/assets/dad19939-41ca-4c68-83d0-603b13673130" />

> <img width="1883" height="920" alt="10-After-hours-search" src="https://github.com/user-attachments/assets/9de98722-7fb5-4d8a-8d92-781227d47d16" />



### 4. Security Dashboard

Built a **Windows Security Monitoring Dashboard** with three KPI cards and four panels, extending beyond the base lab requirements:

| Panel | Visualization |
|---|---|
| Total Security Events (KPI) | Single value |
| Failed Logons (KPI) | Single value |
| Account Lockouts (KPI) | Single value |
| Account Activity — Last 24h (EventCode 4624, by account) | Bar chart |
| Top Processes — Last 24h (EventCode 4688, by creator process) | Events list |
| Login Activity Over Time (EventCode 4624, `timechart`) | Line chart |
| After-Hours Logins | Events list |

<img width="1620" height="1186" alt="Windows Security Monitoring Dashboard" src="https://github.com/user-attachments/assets/f6635051-467c-475d-9236-cb3db80b9881" />


### 5. Automated Security Detection

After reviewing Event ID 4672 activity, I created a scheduled Splunk detection for excessive privileged logons.

The initial search showed that Windows system accounts and computer accounts generated large volumes of Event ID 4672 events. These represented expected system activity and would have created significant alert noise.

To improve detection quality, I filtered those accounts from the search and focused the detection on human user accounts.

```spl
index="windows_logs" source="WinEventLog:Security" EventCode=4672
| where NOT like(Account_Name, "%$")
    AND Account_Name!="SYSTEM"
    AND Account_Name!="LOCAL SERVICE"
    AND Account_Name!="NETWORK SERVICE"
| stats count as privilege_logons by Account_Name, ComputerName
| where privilege_logons > 5
| sort -privilege_logons
```

#### Detection Logic

The alert identifies user accounts generating more than five privileged logon events during the search window. Filtering out known Windows service and machine accounts reduced false positives and made the detection more useful for identifying unusual administrative activity.

During testing, the detection identified the `Slandon` account with six privileged logon events.

#### Alert Configuration

| Setting | Configuration |
|---|---|
| Alert name | Excessive Privileged Logons |
| Windows Event ID | 4672 |
| Schedule | Every 15 minutes |
| Cron expression | `*/15 * * * *` |
| Trigger condition | Number of results > 0 |
| Trigger mode | Once |
| Action | Add to Triggered Alerts |

The alert was successfully validated through Splunk's Trigger History, confirming that the scheduled detection executed and generated alerts when the threshold was exceeded.

> This is stronger portfolio evidence than simply using the lab's default threshold, since it shows the process of reviewing real data, identifying noisy system accounts, filtering them out, tuning a threshold appropriate for the environment, and verifying the detection worked.

<img width="1333" height="555" alt="13-alert-seach-results" src="https://github.com/user-attachments/assets/14330311-7289-41ab-8492-73e2287052b9" />

> <img width="1350" height="646" alt="14-alert-enbabled" src="https://github.com/user-attachments/assets/88bab94c-2196-41b6-a4cb-fe81839e5fe8" />

> <img width="1345" height="659" alt="15-alert-search-results" src="https://github.com/user-attachments/assets/210bc4bf-ad95-48f6-981c-a03d26d05e70" />


---

## Build Notes — Troubleshooting & Real-World Fixes

A lab environment rarely comes together on the first attempt, and the value of this build is as much in the troubleshooting as in the final dashboard. The issues below were each root-caused and resolved rather than worked around.

**1. Lab documentation error — PuTTY steps mixed with Universal Forwarder steps**
The lab instructions' "Installing PuTTY" section actually described Splunk Universal Forwarder installer screens (Deployment Server, Receiving Indexer, port 9997) — not PuTTY. Recognized the mismatch, installed PuTTY correctly using its actual configuration screens, and used the lab's original PDF as a reference for the *later* section where those Universal Forwarder steps genuinely belonged.

**2. SSH key format — PEM vs. PPK**
Azure issues SSH keys in OpenSSH `.pem` format; PuTTY requires its native `.ppk` format. Converted the key with PuTTYgen (Load → select "All Files" to see the `.pem` → Save private key), then pointed PuTTY at the `.ppk` file under **Connection → SSH → Auth → Credentials**, with `azureuser` set as the auto-login username. This turned an "Unable to use key file (OpenSSH SSH-2 private key)" error into a clean connection.

**3. NSG source-IP scoping mismatch**
The port 8000 (Web UI) rule was initially scoped to the IP used for RDP into the Windows VM — but that isn't necessarily the same IP Azure sees for *outbound* browser traffic from that VM. This produced an `ERR_CONNECTION_TIMED_OUT`. Diagnosed by confirming Splunk was actually listening (`sudo ss -tlnp | grep 8000` → `0.0.0.0:8000`), which isolated the problem to Azure networking rather than Splunk itself, then corrected the rule's source IP.

**4. Splunk service failed to start after enabling boot-start**
After configuring boot-start, `sudo systemctl start splunk` failed silently. `journalctl`-style diagnosis (`systemctl status splunk.service --no-pager -l`) surfaced the real cause: Splunk 10.2 deprecated running as root via `/etc/init.d/splunk`, and the boot-start script was still trying to start it that way. Fixed by disabling the root-based boot-start config, re-assigning ownership of `/opt/splunk` to the dedicated `splunk` service account (`chown -R splunk:splunk /opt/splunk`), and re-enabling boot-start under that account (`splunk enable boot-start -user splunk --run-as-root`, where `--run-as-root` only affects the *administrative* command modifying systemd, not the running service).

**5. Cross-VNet forwarder connectivity**
The Windows Server/domain controller VM and the Splunk VM were provisioned into two separate VNets, so the Universal Forwarder had no private path to the indexer on port 9997 by default. Resolved with bidirectional VNet peering (`Splunk-to-Lab1` / `Lab1-to-Splunk`), followed by an NSG rule scoping port 9997 to the peered subnet's CIDR rather than "Any." Verified end-to-end connectivity with `Test-NetConnection 172.16.0.4 -Port 9997` (`TcpTestSucceeded : True`) *before* installing the forwarder, to isolate networking from application-level issues.

**6. Missing Event ID 4740 (account lockout) — root cause in AD policy, not Splunk**
After generating test failed-logon activity, Event 4625 (failed logon) appeared in Splunk immediately, but Event 4740 (account lockout) never did. Rather than assume a forwarding problem, checked for the event directly on the Windows side first (`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740}`), which came back empty — proving Windows itself never generated the event, so nothing was missing on the Splunk side. Traced this to the domain's default password policy: `Get-ADDefaultDomainPasswordPolicy` showed `LockoutThreshold : 0`, meaning account lockout was disabled domain-wide. Set a real threshold (`Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:10:00 -LockoutObservationWindow 00:10:00`), created a dedicated test account rather than risking the admin account, deliberately failed 5 logons against it, and confirmed both the AD lockout (`LockedOut : True`) and the resulting Splunk-side Event 4740 — validating the complete pipeline: **failed logons → AD lockout → Event 4740 → Universal Forwarder → Splunk index → SPL detection.**

> This kind of "the tool is fine, the policy is the problem" diagnosis — checking assumptions at the source before troubleshooting downstream — is a core SOC/IR skill, and arguably better portfolio evidence than a lab that worked flawlessly the first time.

---

## Verification Checklist

| Check | How to verify |
|---|---|
| Data is flowing into Splunk | `index=windows_logs \| head 10` returns recent events |
| Login activity search works | The `EventCode=4624` search returns results as logons are generated |
| Dashboard displays data | Windows Security Monitoring Dashboard shows populated KPI cards and panels |
| Alert is active | **Settings → Searches, Reports, and Alerts** shows *Excessive Privileged Logons* as *Enabled* |

> 📸 **Screenshot placeholder:** `images/15-alert-trigger-history.png` — Trigger History showing multiple successful firings of the *Excessive Privileged Logons* alert.

---

## Appendix — Extended Detections

Reference queries for richer/longer-running environments (not required for base lab completion):

**Explicit credential logon — lateral movement indicator**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4648
| table _time, Account_Name, Target_Server_Name, Process_Name
| sort -_time
```

**Process creation — endpoint detection foundation**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4688
| stats count by Creator_Process_Name
| sort -count
| head 20
```

**Service installation — persistence indicator**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4697
| table _time, Account_Name, Service_Name, Service_File_Name
| sort -_time
```

---

## Security Notes

- **Network exposure:** Web UI (8000) and SSH (22) are restricted by NSG to a single admin source IP; forwarder ingestion (9997) is restricted to the peered VNet CIDR — the indexer is never directly reachable from the public internet.
- **Key handling:** SSH authentication uses public-key auth (`.pem`/`.ppk`) rather than passwords. Any private key shared with a third-party tool (including an AI assistant) during troubleshooting should be treated as exposed and rotated in Azure before the environment is used beyond the lab.
- **Least-privilege config:** the Universal Forwarder's Deployment Server field is intentionally left blank so it cannot be redirected to an unintended management endpoint.
- **Lab data hygiene:** the log-generation script creates a temporary local test account, generates activity against it, and removes it afterward — no persistent accounts are left on the VM. The dedicated Active Directory test account used to validate the account-lockout detection was created separately from, and never used, the domain admin account.

---

*Part of a self-directed home-lab series building demonstrable, portfolio-ready SOC and cloud security skills — Splunk SIEM deployment, log ingestion, detection engineering, and alert tuning on Azure infrastructure.*
