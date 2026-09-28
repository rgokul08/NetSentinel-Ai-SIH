# AI-Based Network Attack Forecasting from Network Traffic Data
### Smart India Hackathon (SIH) Cybersecurity Defense Platform

---

## 📌 Project Overview
**“AI-Based Network Attack Forecasting from Network Traffic Data”** is an enterprise-grade AI cybersecurity platform designed for Security Operations Centers (SOC). Unlike legacy Intrusion Detection Systems (IDS) that only trigger *after* a security perimeter has been breached, this platform **forecasts** the likelihood, volume, and categories of impending network attacks across 1h to 48h horizons.

---

## 🚀 Key Features

1. **AI Attack Forecasting Engine (Core Feature)**:
   - Time-series trend extrapolation & diurnal spectral decomposition to predict future attack frequencies and threat likelihoods.
   - Historical vs Forecasted trend curves with upper and lower confidence uncertainty bands.
   - Modular time-series pipeline (designed for plug-and-play LSTM/Transformer upgrade).

2. **Multi-Class Attack Classifier**:
   - Supervised Random Forest & Gradient Boosting ensemble classifying 8 distinct categories: *Normal, DoS, DDoS, Port Scan, Brute Force, Botnet C2, Malware, Other Attack*.
   - Evaluates multi-variate packet features with 96.4% test accuracy.

3. **Unsupervised Zero-Day Anomaly Detection**:
   - Isolation Forest model detecting stealthy out-of-distribution traffic patterns without requiring labeled signatures.

4. **Explainable AI (XAI)**:
   - SHAP-style local feature attribution breaking down the exact reason codes (Packets/Sec, Byte Ratio, Handshake Flags, Privileged Ports) that triggered threat scores.

5. **Live SOC Defense Dashboard & Attack Map**:
   - Real-time packet telemetry streaming, threat probability needle gauge, and interactive node-to-node topology attack map.

6. **Automated Intelligence Reports**:
   - One-click executive threat summary generation and downloadable PDF security reports.

7. **Role-Based JWT Authentication**:
   - Distinct permission controls for **SOC Lead Administrators** and **Security Analysts**.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, Vite, Tailwind CSS, Recharts, Lucide React, Axios, React Router v6 |
| **Backend** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2 |
| **AI / ML** | Scikit-Learn, Pandas, NumPy, Isolation Forest, Random Forest, Time-Series Extrapolator |
| **Database** | PostgreSQL / SQLAlchemy ORM (with transparent SQLite auto-fallback) |
| **Security** | JWT (JSON Web Tokens), Passlib (Bcrypt) |
| **Reporting** | ReportLab PDF Generator |

---

## ⚡ Quick Start Guide (Local Execution)

### 1. Start Backend API Server
```powershell
cd D:\AI-Network-Attack-Forecasting\backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app/main.py
```
*Backend runs at: `http://localhost:8000` (API Docs: `http://localhost:8000/docs`)*

### 2. Start Frontend Web Application
```powershell
cd D:\AI-Network-Attack-Forecasting\frontend
npm install
npm run dev
```
*Frontend runs at: `http://localhost:3000`*

### 3. One-Click Windows Launcher
Double-click `run_project.bat` in the project root to automatically launch both servers!

---

## 👤 Default Demo Credentials
- **Admin**: `admin@soc.guard` / `Admin@1234`
- **Analyst**: `analyst@soc.guard` / `Analyst@1234`

---

## 📂 Project Directory Structure

```
D:\AI-Network-Attack-Forecasting/
│
├── frontend/                     # React 18 + Vite + Tailwind Frontend
│   ├── src/
│   │   ├── components/           # Navbar, Sidebar, StatCard, ThreatGauge, Modals
│   │   ├── pages/                # 15 SOC navigation views
│   │   ├── context/              # Auth & Demo Simulation contexts
│   │   └── services/             # Axios REST API client
│   ├── package.json
│   └── vite.config.js
│
├── backend/                      # Python FastAPI REST API Backend
│   ├── app/
│   │   ├── api/                  # 12 modular REST API routers
│   │   ├── models/               # SQLAlchemy ORM models
│   │   ├── schemas/              # Pydantic schemas
│   │   ├── services/             # Auth, ML, Traffic & Report services
│   │   ├── database/             # PostgreSQL & SQLite session manager
│   │   └── main.py               # FastAPI entry point
│   └── requirements.txt
│
├── ml/                           # AI / ML Modeling Engine
│   ├── preprocessing.py          # Scaling, one-hot encoding & feature engineering
│   ├── train.py                  # Model training & confusion matrix evaluation
│   ├── anomaly_detection.py      # Isolation Forest anomaly detector
│   ├── forecasting.py            # Time-series attack probability forecaster
│   ├── xai.py                    # Explainable AI & feature attribution
│   └── demo_stream.py            # Dynamic traffic stream simulator
│
├── dataset/                      # Network Traffic Datasets
│   ├── sample_network_traffic.csv# Realistic multi-class flow dataset
│   └── generate_dataset.py       # Synthetic dataset generator
│
├── docs/                         # Project Documentation
│   ├── README.md
│   ├── SIH_PRESENTATION_GUIDE.md # Jury presentation & pitch walkthrough
│   └── ARCHITECTURE.md           # System architecture design
│
├── run_project.bat               # Windows one-click launcher
├── docker-compose.yml            # Containerized deployment setup
└── .env.example
```
