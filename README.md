# 🛡️ Smart SIEM Risk Engine

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.13-blue.svg?style=flat-square" alt="Python Version"/>
  <img src="https://img.shields.io/badge/FastAPI-0.103.1-009688.svg?style=flat-square" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/SQLite-Database-yellow.svg?style=flat-square" alt="SQLite"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Integrated-red.svg?style=flat-square" alt="MITRE ATT&CK"/>
  <img src="https://img.shields.io/badge/WebSockets-Real--Time-green.svg?style=flat-square" alt="WebSockets"/>
</div>

## 📖 Overview
The **Smart SIEM Risk Engine** is an advanced, automated security information and event management (SIEM) pipeline designed to ingest, normalize, dynamically score, and actively respond to network threats in real-time.

Built with an **enterprise-grade scoring heuristic** and powered by a highly visual **real-time WebSocket dashboard**, this project demonstrates how pure code logic and automated playbooks can replace manual SOC (Security Operations Center) triaging, achieving **over 96% accuracy** in threat band classification and response action initiation.

## 🌟 Key Features

### 1. 🔄 Multi-Source Threat Ingestion & Normalization
- Extracts raw network and IDS alerts from massive datasets (supports **Suricata/ISCX** and **Zeek** formats).
- Unifies disparate data structures into a clean, strictly typed `NormalizedAlert` schema using Pydantic.

### 2. 🎯 Dynamic Risk Scoring System
- Calculates precise risk scores (0-100) using a multi-factor weighting engine.
- Evaluates:
  - **Base Severity** derived from the raw logs.
  - **Exploitability & Impact** of the network signature.
  - **Entity Targeting** (evaluating source vs destination anomalies).
- Classifies the score into specific **Risk Bands** (Critical, High, Medium, Low).

### 3. 🗺️ MITRE ATT&CK Integration
- Automatically parses and extracts MITRE TTPs (Tactics, Techniques, and Procedures) from the raw signature metadata.
- Evaluated pure code logic against Dataset Ground Truth with **100% accuracy**.

### 4. ⚡ Automated Response & Playbooks
- Translates the calculated risk score into instant, automated defensive actions:
  - `block_and_report` for Critical threats (updates the active IP blocklist in SQLite).
  - `alert_team` for High anomaly scenarios.
  - `store_only` for benign/low-risk background noise.

### 5. 📊 Real-Time Glassmorphism Dashboard
- A sleek, single-page UI built with pure CSS, HTML, and Vanilla JS, served via FastAPI.
- **WebSocket Streaming:** Injects Live Threat Feeds and updates metrics seamlessly without page reloads.
- **Active MITRE Matrix:** Visually flashes MITRE TTP tags (e.g., *Lateral Movement*, *Defense Evasion*) in real-time as the engine detects them.
- **Interactive Triage:** Clickable threat rows open detailed modals, and SOC analysts can manually "Unblock" auto-banned Target IPs with one click.
- **Dark/Light Theme:** Fully responsive, variable-driven UI logic.

---

## 🏗️ Architecture & Component Flow
1. `run.py` acts as the engine driver, iterating through the raw JSON logs.
2. `ingestion/`: Validates and loads raw alerts.
3. `normalization/`: Cleans and extracts the exact `category`, `source_ip`, `signature`, and `mitre_ids`.
4. `scoring/`: The heuristics core that evaluates the normalized alert to spit out a `risk_score`.
5. `response/`: Automates the playbook action based on the `risk_score` band, altering the internal `BlockedIPDB` and broadcasting via REST to the WebSocket hub.
6. `app.main / app.api`: The FastAPI web server acting as the REST backend and WebSocket manager for the frontend Dashboard.
7. `scripts/`: Development and evaluation utilities like `extract_logs.py` to generate the test cases and `verify_mitre_mapping.py` to validate mapping accuracy.

---

## 🚦 Getting Started

### Prerequisites
- Python 3.10+
- `pip`

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/smart-siem-risk-engine.git
   cd smart-siem-risk-engine
   ```
2. Create and activate a Virtual Environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the System
1. **Start the Dashboard Server (Terminal 1):**
   ```bash
   uvicorn app.main:app --reload
   ```
   *The dashboard will be available at [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)*.

2. **Run the SIEM Risk Engine (Terminal 2):**
   ```bash
   # This will process the alerts in data/raw_alerts and stream them via WebSocket to your live dashboard!
   python run.py
   ```

3. **Verify MITRE Mapping Accuracy:**
   ```bash
   python scripts/verify_mitre_mapping.py
   ```
   *Watch the engine achieve a perfect mapping match against the ISCX / Zeek dataset ground truth!*

---

## 📈 Evaluation & Results
The engine was tested against a subset of **2,252** deeply complex network logs spanning both ISCX Network datasets and Zeek-generated malicious traffic. 
- **TTP Mapping Accuracy:** 100.00%
- **Risk Band Accuracy:** 96.35%
- **Automated Action Precision:** 96.35%

This effectively proves that well-architected heuristics combined with highly normalized data schemas can successfully automate initial SOC triage responsibilities, freeing up security analysts to focus on active threat hunting.
