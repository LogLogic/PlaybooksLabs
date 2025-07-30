# Phishing Email Investigation Playbook

## Overview  
This repository contains a comprehensive playbook for investigating phishing emails, designed to guide SOC analysts through detailed steps for analyzing suspicious messages. It covers:

- Email header analysis to detect spoofing  
- Malicious link identification and reputation checks  
- Attachment inspection and malware detection  
- Extraction and enrichment of Indicators of Compromise (IOCs)  
- Final verdict formulation and response recommendations

The playbook is based on real-world phishing investigations, including spoofed sender emails and malware-laced attachments.

---

## Contents  
- [`Phishing_Playbook.md`](Phishing_Playbook.md): Step-by-step investigation guide  
- `/screenshots/`: Folder containing referenced screenshots illustrating each step

---

## How to Use  
1. Review the playbook to understand the investigation workflow  
2. Follow the steps during SOC exercises or real phishing incidents  
3. Reference screenshots for visual support during analysis  
4. Adapt the procedures to fit your organization's incident response plan

---

## Tools Used  
- Email header analyzers and text editors  
- VirusTotal and URLscan for threat intelligence  
- Safe attachment analysis via hash generation and VirusTotal lookups  
- Command-line utilities (e.g., `certutil`) for generating file hashes

---
