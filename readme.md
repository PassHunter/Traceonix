🛡️ AegisCore SOC Dashboard
AI-Powered Security Operations Center Alert Classification Engine
AegisCore is a high-performance, real-time SOC monitoring platform that utilizes AI (via OpenRouter/Gemini) to classify network traffic, analyze forensic metadata, and provide actionable security intelligence. It features a modern, reactive dashboard with live WebSocket updates and an interactive attack simulator for testing detection capabilities.

Developed for IGNITION HACKVERSE 2026 — Problem Statement PS0202


👥 Team Information
FieldDetailsTeam NameTraceonixMembersAyush Madavi · Guneshwari Bondre · Pooja Nanhe · Sarthak MakheProblem StatementPS0202 — AI-Powered SOC Alert Classification & Prioritization

⚙️ Configuration
AegisCore uses environment variables for sensitive data. Create a .env file in the root directory before starting:
envOPENROUTER_API_KEY=your_key_here
SOC_ADMIN_USER=admin
SOC_ADMIN_PASS=password123

🚀 Execution Steps
1. Install Dependencies
Ensure you have Python 3.10+ installed. Install all required libraries:
bashpip install -r requirements.txt
2. Start the Backend Server
Launch the FastAPI backend. This serves the dashboard and handles log classification.
bashpython app.py
The server will be available at http://127.0.0.1:8000
3. Launch the Attack Simulator
Open a separate terminal and run the interactive simulator to generate normal and malicious traffic:
bashpython attack_simulator.py
4. Access the Dashboard
Open your browser and navigate to: http://127.0.0.1:8000/login
FieldValueUsernameadminPasswordpassword123

🛠️ Key Components
FileDescriptionapp.pyFastAPI backend with WebSocket manager and traffic interceptorindex.htmlPremium Tailwind CSS dashboard with Chart.js integrationclassifier.pyHeuristic and AI-driven classification logicattack_simulator.pyMulti-threaded traffic generator for SOC stress testingintelligence.pyDeep forensic analysis engine powered by Gemini AI

ttack Simulator — Full Command Reference
The attack simulator (attack_simulator.py) runs an interactive terminal UI. Normal background traffic streams continuously, and you can trigger specific attacks on demand or let it run autonomously.
How It Works
1. Normal traffic streams continuously in the background (INFO-level).
2. The attack menu appears — pick an attack type by number.
3. A 10-second animated countdown runs (judges can see what's coming).
4. The selected attack fires (normal traffic pauses during the attack).
5. Attack ends → "Attack Stopped" banner → normal traffic automatically resumes.
6. The menu reappears. Repeat as many times as needed.

🎮 Menu Commands
InputAction1 – 15Launch a specific attack by its number (see attack list below)RStart Continuous Random Mode — auto-triggers a random attack every 10 secondsSStop Continuous Random Mode0 / q / quit / exitExit the simulator cleanly

⚠️ You cannot select a numbered attack while Random Mode is running. Press S first to stop it, then select manually.

AegisCore — Built for speed, designed for clarity, powered by AI