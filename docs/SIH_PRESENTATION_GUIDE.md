# Smart India Hackathon (SIH) Presentation & Demo Guide

## Project Title:
**AI-Based Network Attack Forecasting from Network Traffic Data**

---

## 🎯 1. 30-Second Elevator Pitch
> *"Respected Jury Members, traditional cybersecurity tools only alert security teams AFTER an attack has breached network defenses. In modern volumetric DDoS attacks or automated botnets, by the time alerts ring, critical servers are already down.*
>
> *Our solution, **ChainTrace AI**, introduces **Proactive Attack Forecasting**. By combining statistical time-series forecasting, unsupervised anomaly detection, and ensemble machine learning on live network telemetry, we predict threat likelihoods, attack volume surges, and expected intrusion vectors hours in advance—giving SOC analysts time to pre-emptively mitigate attacks before servers fail."*

---

## 🖥️ 2. Step-by-Step Live Demonstration Script

### Step 1: The Landing Page (`/`)
- Show the problem statement and the **8-stage AI/ML pipeline**.
- Highlight that the system is ready for enterprise deployment.
- Click **"Launch Security Dashboard"**.

### Step 2: The Security Dashboard (`/dashboard`)
- Explain the key questions answered in seconds:
  1. *"What is happening right now?"* ➔ Total Monitored Flows & Live Feed.
  2. *"What attacks were detected?"* ➔ Multi-class attack cards & percentages.
  3. *"How serious is the threat?"* ➔ **Threat Probability Needle Gauge (Low / Medium / High / Critical)**.
  4. *"What is likely to happen next?"* ➔ 6-12 Hour Attack Trajectory Preview.
- Use the **"Inject Threat"** button on the top-right navbar to trigger a live DDoS attack and show how the threat gauge, alert queue, and charts react in real-time.

### Step 3: Attack Forecasting Engine (`/forecast`) — THE STAR FEATURE
- Emphasize the **Historical vs. Forecasted Attack Trajectory Chart**.
- Switch horizons (+6h, +12h, +24h, +48h).
- Point out the **Confidence Uncertainty Band** (Upper and Lower bounds).
- Show the **Expected Attack Vector Pie Chart** (e.g. DoS 28%, DDoS 24%, Port Scan 20%).
- Show the **Hourly Threat Projection Schedule Table**.

### Step 4: Explainable AI (`/xai`) & Attack Detection (`/detection`)
- Show that this is not a black-box AI.
- In the Explainable AI page, click on **"DDoS Scenario"** or **"Port Scan Scenario"**.
- Point out the SHAP-style **Feature Contributions** (e.g., *"+38% Packets/Sec surge"*, *"+30% Privileged Destination Port probes"*).
- In the Attack Detection page, demonstrate how entering custom packet telemetry gives instant predictions with contributing factors.

### Step 5: Unsupervised Zero-Day Anomaly Detection (`/anomalies`)
- Explain to judges: *"Even if an attacker uses a brand-new zero-day exploit without an existing signature, our **Isolation Forest** unsupervised algorithm flags it as an outlier based on statistical flow deviations."*
- Show the scatter plot distribution.

### Step 6: Topology Threat Map (`/attack-map`) & Downloadable PDF (`/reports`)
- Open the visual attack map showing WAN sources assaulting internal DMZ subnets.
- Go to Reports and click **"Download PDF Report"** to show a complete executive dossier ready for senior CISOs and management.

---

## 💡 3. Anticipated Jury Questions & Winning Answers

### Q1: *"How does Forecasting differ from simple Detection?"*
**Answer**:
> *"Detection analyzes a packet in the present and says 'This packet is a DoS attack.' Forecasting analyzes chronological sequence trends over time (diurnal volume shifts, reconnaissance probing frequency, and connection rate gradients) and predicts: 'Based on the past 24 hours of traffic, there is an 84% probability of a volumetric DDoS flood between 02:00 and 05:00 UTC.' This allows automated firewall rule staging and bandwidth provisioning in advance."*

### Q2: *"Can this pipeline support Deep Learning like LSTMs or Transformers?"*
**Answer**:
> *"Yes! We designed the ML architecture with modular preprocessor interfaces (`ml/forecasting.py`). Currently, it utilizes an Ensemble Time-Series Regressor with Diurnal Spectral Decomposition for ultra-low latency inference, but it can be seamlessly switched to a PyTorch LSTM or Temporal Fusion Transformer without altering the API contracts or frontend."*

### Q3: *"How does it integrate with real enterprise networks?"*
**Answer**:
> *"The backend accepts standard NetFlow/IPFIX, Zeek logs, Suricata EVE JSON, and PCAP CSV exports via our `/api/dataset/upload` endpoint and real-time socket ingestion layer (`ml/demo_stream.py`)."*
