# 🛡️ ThreatNexus 1.0

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green?logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Beta-orange)

ThreatNexus 1.0 is a **web-based cybersecurity analysis tool** that consolidates **open-source threat intelligence data** from multiple APIs into a single, easy-to-read interface.  
This tool is designed to help analysts quickly **investigate files, IP addresses, and domains**, reducing the need to manually query multiple services.

---

## 📑 Table of Contents

- [Features](#-features)
- [Technology Stack](#%EF%B8%8F-technology-stack)
- [Installation](#%EF%B8%8F-installation)

---

##  Features

- **File Analysis**
  - Upload and scan files via **VirusTotal API**.
  - Optional analysis via **ANY.RUN** (requires a paid API key).
- **IP/Domain Analysis**
  - Retrieves data from:
    - VirusTotal
    - AbuseIPDB
    - URLScan.io
  - Displays WHOIS info, threat scores, categories, and report links.
- **Country Flags**
  - Automatically shows a **flag icon** for IP geolocation results.
- **Screenshot Capture**
  - URLScan.io screenshots displayed in results.
- **Lightweight UI**
  - Simple and responsive **HTML/CSS frontend** for ease of use.
- **Fast Backend**
  - Powered by **FastAPI** for quick API requests.

---

##  Technology Stack

- **Backend:** Python 3.11, FastAPI  
- **Frontend:** HTML5, CSS3  
- **APIs Used:**  
  - [VirusTotal](https://www.virustotal.com/)  
  - [ANY.RUN](https://any.run/) *(optional)*  
  - [AbuseIPDB](https://www.abuseipdb.com/)  
  - [URLScan.io](https://urlscan.io/)  

---

##  Installation

### 1️⃣ Clone the repository
bash
git clone https://github.com/Sarjala/ThreatNexus_1.0.git
cd ThreatNexus_1.0

2️⃣ Configure API keys

Create a .env file in the project root:

VIRUSTOTAL_API_KEY=your_virustotal_api_key
ANYRUN_API_KEY=your_anyrun_api_key    # Optional
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
URLSCAN_API_KEY=your_urlscan_api_key

3️⃣Run the application

uvicorn main:app --reload

The app will be available at: http://127.0.0.1:8000
