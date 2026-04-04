# 🛡️ AegisCore SOC Dashboard

**AI-Powered Security Operations Center Alert Classification Engine**

AegisCore is a high-performance, real-time SOC monitoring platform that utilizes AI (via OpenRouter/Gemini) to classify network traffic, analyze forensic metadata, and provide actionable security intelligence. It features a modern, reactive dashboard with live WebSocket updates and an interactive attack simulator for testing detection capabilities.

---

## 🚀 Execution Steps

Follow these steps to set up and run the AegisCore SOC environment:

### 1. Install Dependencies
Ensure you have Python 3.10+ installed. Install the required libraries using `pip`:
```bash
pip install -r requirements.txt
```

### 2. Start the Backend Server
Launch the FastAPI backend. This serves the dashboard and handles log classification.
```bash
python app.py
```
*The server will be available at `http://127.0.0.1:8000`.*

### 3. Launch the Attack Simulator
In a separate terminal, run the interactive simulator to generate normal and malicious traffic.
```bash
python attack_simulator.py
```
*Follow the on-screen menu to trigger various attack vectors (SQLi, XSS, Brute Force, etc.).*

### 4. Access the Dashboard
Open your web browser and navigate to:
**[http://127.0.0.1:8000/login](http://127.0.0.1:8000/login)**

**Default Credentials:**
- **Username:** `admin`
- **Password:** `password123`

---

## 👥 Team Information

**Team Name:** Vidhit Technologies (SIH-2025 · PS0202)

**Team Members:**
- Ayush Madavi
- Guneshwari Bondre
- Pooja Nanhe
- Sarthak Makhe

---

## 🛠️ Key Components
- **`app.py`**: FastAPI backend with WebSocket manager and traffic interceptor.
- **`index.html`**: Premium Tailwind CSS dashboard with Chart.js integration.
- **`classifier.py`**: Heuristic and AI-driven classification logic.
- **`attack_simulator.py`**: Multi-threaded traffic generator for SOC stress testing.
- **`intelligence.py`**: Deep forensic analysis engine powered by Gemini AI.

---
*Developed for IGNITION HACKVERSE 2026- Problem Statement PS0202*
