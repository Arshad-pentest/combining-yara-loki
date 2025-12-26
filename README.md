# Combining YARA and LOKI – Malware Scanning Platform

A **containerized malware scanning and risk assessment tool** that integrates **YARA** and **LOKI** for static file analysis, correlation, and risk-based prioritization.  
Built with **Flask**, hardened for **secure execution**, and designed to reflect **real SOC / DFIR workflows**.

---

## 🚀 Overview

This project provides a web-based interface for uploading files and scanning them using multiple detection engines. Instead of returning raw alerts, the tool correlates results and assigns a **numeric risk score (0–100)** to support faster and more accurate decision-making.

The platform is **Dockerized**, runs scanners in an isolated environment, and follows **defensive security best practices**.

---

## ✨ Key Features

- 🔍 **Multi-Engine Detection**
  - YARA rule-based pattern matching
  - LOKI IOC-based detection

- 📊 **Risk Scoring Engine**
  - Numeric risk score (0–100)
  - Severity levels: Low, Medium, High, Critical
  - Correlation-aware scoring (YARA + LOKI)

- 🌐 **Web-Based UI**
  - File upload & scan
  - Results visualization
  - Configuration panel

- 🧾 **PDF Report Generation**
  - Scan summary
  - Detection details
  - Risk score and classification

- 🐳 **Dockerized & Hardened**
  - Non-root execution
  - Isolated runtime
  - Production-ready WSGI server (Gunicorn)

---

## 🏗️ Architecture

Flask UI
|
├── Routes (scan / config / report)
|
├── Engines
| ├── YARA Engine
| ├── LOKI Engine
| └── Risk Scoring Engine
|
├── uploads/ (quarantined files)
├── yara_rules/ (read-only rules)
├── loki_iocs/ (IOC definitions)
└── reports/ (PDF outputs)


---

## 🛡️ Security Design Principles

- Static analysis only (no execution of samples)
- Read-only rule directories
- No global Python installations
- Docker isolation from host OS
- No outbound network dependency for scans
- Clear separation of UI, logic, and execution layers

---

## 📦 Technology Stack

- **Language:** Python 3
- **Backend:** Flask
- **Detection:** YARA, LOKI
- **Reporting:** reportlab (PDF)
- **WSGI Server:** Gunicorn
- **Containerization:** Docker
- **OS:** Linux (tested on Kali Linux)

---

## ⚙️ Installation (Docker – Recommended)

### 1️⃣ Clone the repository
```bash
git clone https://github.com/Arshad-pentest/combining-yara-loki.git
cd combining-yara-loki

2️⃣ Build the Docker image

docker build -t yara-loki-scanner .

3️⃣ Run the container

docker run -p 5000:5000 yara-loki-scanner

4️⃣ Open the application

http://localhost:5000

🧪 Local Development (Without Docker)

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py

📊 Risk Scoring Model (Summary)
Score Range	Severity
0–19	Low
20–39	Medium
40–69	High
70–100	Critical

Risk is calculated using:

    Engine detections (YARA / LOKI)

    Rule severity metadata

    Detection correlation

⚠️ Disclaimer

This project is intended only for educational, research, and defensive security purposes.
Do not upload or analyze malware samples without proper authorization.
🚧 Future Enhancements

    MITRE ATT&CK mapping

    Asynchronous scan workers

    Scan history & trend analysis

    Artifact extraction (URLs, IPs, hashes)

    Authentication & role-based access

    External threat intelligence integration

👤 Author

Arshad
Cybersecurity | CTF Player
