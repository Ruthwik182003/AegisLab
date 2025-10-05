# Wazuh Malware Analysis and SIEM Setup

This repository provides a complete, step-by-step guide to setting up a **Security Information and Event Management (SIEM)** system using **Wazuh**, with integrated **File Integrity Monitoring (FIM)**, **VirusTotal API malware scanning**, and **Active Response** for automated threat removal.

---

## 🧩 About Wazuh

**Wazuh** is an open-source **SIEM (Security Information and Event Management)** platform that provides unified security monitoring, threat detection, and incident response. It helps organizations collect, analyze, and correlate security events across their infrastructure — from servers and endpoints to cloud environments.

### 🔑 Key Features

* **File Integrity Monitoring (FIM):** Detects file modifications, creations, and deletions in real-time.
* **Log Data Analysis:** Centralized log collection and correlation from multiple endpoints.
* **Intrusion Detection:** Detects abnormal behavior and policy violations.
* **Vulnerability Detection:** Scans systems for known vulnerabilities and configuration weaknesses.
* **Active Response:** Automates responses to security threats (e.g., blocking IPs, deleting malware).
* **Cloud Security Monitoring:** Integrates with AWS, Azure, and Google Cloud for cloud-native threat detection.

### 🌍 Contributions to Cybersecurity

Wazuh’s open-source ecosystem empowers security teams and researchers to:

* Build **cost-effective SOC environments** without relying on proprietary SIEM tools.
* Enhance visibility into security events across hybrid or multi-cloud infrastructures.
* Integrate with external tools such as **VirusTotal**, **ELK Stack**, **OSQuery**, and **MITRE ATT&CK** for advanced analysis.
* Contribute new rules, decoders, and modules to the global cybersecurity community.

Wazuh is not only a tool but a **collaborative framework** that strengthens detection and response capabilities for organizations of all sizes.

---

## 🚀 What This Project Does

This setup demonstrates how to:

* **Deploy Wazuh** as a SIEM platform on Ubuntu.
* **Monitor file integrity** using Wazuh FIM to detect real-time file changes.
* **Integrate with VirusTotal API** to automatically scan newly created or modified files for known malware signatures.
* **Trigger Active Response** to automatically remove files identified as malicious.
* **Visualize and investigate threats** through the Wazuh Dashboard.

This makes it an excellent hands-on project for understanding malware analysis, SIEM architecture, and automated incident response.

---

## 🧠 Wazuh Workflow Overview

1. **File Integrity Monitoring (FIM):** Wazuh tracks changes in monitored directories (e.g., `/tmp/Malware`).
2. **VirusTotal Integration:** When a new file appears, its hash is sent to VirusTotal for malware scanning.
3. **Alert Generation:** If VirusTotal reports a match, Wazuh generates an alert in the dashboard.
4. **Active Response:** A custom script automatically deletes the malicious file.
5. **Investigation:** Analysts can view detection details and logs through the Wazuh web interface.

---

## ⚙️ Tech Stack

* **Operating System:** Ubuntu (Server & Agent)
* **SIEM Tool:** Wazuh (Manager, Indexer, and Dashboard)
* **API Integration:** VirusTotal Public API
* **Automation:** Wazuh Active Response scripts
* **Virtualization:** VirtualBox / VMware

---

## 🧠 Use Cases

* Malware detection and automated mitigation
* Demonstrating SIEM configuration and incident response workflows
* Hands-on cybersecurity or SOC training lab
* Real-world malware analysis automation project

---

## 📘 Documentation

Full setup and implementation guide is available in the main markdown file:

> [Malware Analysis and SIEM Setup Guide](./Malware%20Analysis.md)

---

## 🛡️ Disclaimer

This project uses the **EICAR test file**, which is **not real malware**, to simulate detections safely. Do **not** use real malicious files in production or educational labs.

---

## 💡 Author

**Ruthwik S Ramesh**
Cybersecurity Enthusiast | SIEM & Malware Analysis Projects
