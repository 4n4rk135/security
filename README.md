# **🛡️ Windows Security Audit Script**


A comprehensive PowerShell-based security audit script for Windows systems.

Designed to help administrators and security professionals assess system configuration, detect weak settings, and improve security posture.

## **📌 Overview**

windows_audit_security.ps1 performs a structured security audit of a Windows machine, collecting configuration and security-related information for review.

This tool is intended for:
* System Administrators,
* Security Engineers,
* IT Auditors,
* Blue Team Professionals.

## **✨ Features**

🔐 Windows Defender status check

🔥 Windows Firewall configuration

👥 Local user & administrator enumeration

🔑 Password and account policy review

🧾 Installed software listing

🌐 Open ports and network configuration

📦 Windows Update status

🛠️ Running services inspection

🗂️ Startup program analysis

📜 Security event log summary

## 🚀 Getting Started

1️⃣ Clone the Repository

* git clone https://github.com/4n4rk135/simplescript.git, cd windows-security-audit

2️⃣ Run the Script

* Run PowerShell as Administrator:

* powershell -ExecutionPolicy Bypass -File windows_audit_security.ps1

Or:

* .\windows_audit_security.ps1

## 🔒 Requirements

* Windows 10 / 11 / Windows Server,

* PowerShell 5.1 or higher,

* Administrator privileges (recommended for full audit coverage).

## 📄 Simple Output

[✔] Firewall Status : Enabled

[✔] Defender Status : Running

[!] Local Admin Accounts : 2 Found

[✔] Windows Updates : Up to Date

## ⚠️ Legal Disclaimer

This script is intended for authorized security auditing and administrative purposes only.

Do NOT use this script on systems without proper authorization.

The author is not responsible for misuse or unauthorized activities.

## 🛠️ Customization

You may modify the script to:
* Export results to CSV or JSON,
* Generate HTML security reports,
* Integrate with SIEM tools,
* Automate periodic audits via Task Scheduler.

## 📌 Roadmap

* HTML Report Export,
* CIS Benchmark comparison,
* Risk scoring system,
* Logging improvements,
* Modular architecture.

## 📜 License

* This project is licensed under the MIT License.

## 👤 Author

**aguskb**

* Security & Automation Enthusiast
* i love my wife 🙂 and 2 daughters (k4li, 3nigma)
