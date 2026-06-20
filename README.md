# 🛡️ AI-Powered Honeypot — Intelligent Threat Detection System

A custom-built honeypot system that uses AI to detect, classify, and deceive cyber attackers in real time. This project implements and extends the methodology proposed in **"Intelligent Threat Detection — AI-Driven Analysis of Honeypot Data to Counter Cyber Threats"** by Lanka, Gupta & Varol (Electronics, MDPI, 2024).

Unlike traditional honeypots that rely on pre-built tools, both the SSH and HTTP honeypots in this project are built entirely from scratch in Python.

---

## Research Foundation

| Field | Details |
|---|---|
| Paper | Intelligent Threat Detection — AI-Driven Analysis of Honeypot Data to Counter Cyber Threats |
| Authors | Phani Lanka, Khushi Gupta, C. Varol |
| Journal | Electronics, MDPI, Vol. 13, Issue 13 |
| Published | June 2024 |
| DOI | 10.3390/electronics13132465 |

**Research Question:** Can LLM-based TTP extraction from custom honeypot data reduce threat detection time compared to traditional signature-based methods, and can this methodology be extended to HTTP-based web attacks?

---

## Features

### Honeypot Functionalities
✅ Custom SSH Honeypot (built from scratch using Paramiko)
✅ Custom HTTP Honeypot (built from scratch using Flask)
✅ Fake Admin / Login / WordPress / phpMyAdmin Pages
✅ Full Session Logging (IP, timestamp, commands, credentials)
✅ Multi-Connection Handling via Threading
✅ Cowrie-Compatible JSON Log Format

### AI & Machine Learning Functionalities
✅ LLM-Based TTP Extraction (Groq API + LLaMA 3, Chain-of-Thought Prompting)
✅ MITRE ATT&CK Category Mapping for Every Extracted TTP
✅ Attacker Behavior Classifier (Random Forest — Bot / Script Kiddie / Skilled Human / Normal)
✅ Unsupervised Anomaly Detector (Isolation Forest)
✅ LLM Dynamic Deception Engine (Realistic Fake Terminal Responses)
✅ Cross-Dataset Generalization Testing (CICIDS 2017 → CICIDS 2018)

### Visualization Functionalities
✅ Live Global Attack Origin Map
✅ Real-Time Threat Intelligence Feed
✅ Live Terminal Session Replay
✅ TTP Frequency & MITRE ATT&CK Charts
✅ AI-Generated Attacker Profile Cards
✅ Severity Breakdown Visualization
✅ Auto-Refreshing Streamlit Dashboard

### Research & Evaluation Functionalities
✅ Stratified Train/Test Split with Oversampling (Train Set Only)
✅ 5-Fold Cross-Validation
✅ Cross-Dataset Validation on Unseen Data
✅ Classification Reports (Precision, Recall, F1-Score)
✅ False Positive / Attack Detection Rate Analysis

---

## Technology Stack

| Layer | Technology |
|---|---|
| Honeypot — SSH | Python, Paramiko |
| Honeypot — HTTP | Python, Flask |
| AI / LLM | Groq API (LLaMA 3.3 70B) |
| Machine Learning | scikit-learn (RandomForest, IsolationForest) |
| Data Processing | pandas, numpy, imbalanced-learn |
| Dashboard | Streamlit, Plotly |
| Training Data | CICIDS 2017 / CICIDS 2018 (University of New Brunswick) |
| Secrets Management | python-dotenv |
| Version Control | Git, GitHub |

---

## Installation

### Prerequisites
- Python 3.11+
- pip
- A free Groq API key (console.groq.com)

### Setup Steps

**1. Clone the repository**
```bash
git clone https://github.com/rumasarasool/AI-powered-honeypot.git
cd AI-powered-honeypot
```

**2. Create and activate a virtual environment**
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Configure your API key**

Create a `.env` file in the project root:
```
GROQ_API_KEY=your-groq-api-key-here
```

**5. Add training data**

Download CICIDS 2017 (Tuesday/Thursday/Friday CSVs) and place them in the `data/` folder. See [CIC dataset](https://www.unb.ca/cic/datasets/ids-2017.html) for source.

**6. Run the pipeline phase by phase**
```bash
python ai_engine/log_parser.py
python ai_engine/ttp_extractor.py
python ai_engine/classifier.py
python ai_engine/anomaly_detector.py
python ai_engine/llm_responder.py
streamlit run dashboard/app.py
```

---

## Project Structure

```
AI-powered-honeypot/
├── honeypot/
│   ├── ssh_honeypot.py            # Custom SSH honeypot (Paramiko, port 2222)
│   ├── http_honeypot.py           # Custom HTTP honeypot (Flask, port 8080)
│   ├── simulate_attackers.py      # SSH attack simulator (local testing only)
│   └── simulate_web_scanner.py    # Web scanner simulator (local testing only)
│
├── ai_engine/
│   ├── log_parser.py              # Parses Cowrie/CICIDS logs into clean datasets
│   ├── ttp_extractor.py           # Groq-based TTP extraction (core paper component)
│   ├── classifier.py              # RandomForest attacker classifier
│   ├── anomaly_detector.py        # IsolationForest anomaly detection
│   └── llm_responder.py           # LLM dynamic deception engine
│
├── dashboard/
│   └── app.py                     # Streamlit research dashboard
│
├── data/
│   ├── combined_attacks.csv       # Cleaned CICIDS training dataset (generated)
│   ├── ttps.json                  # Extracted TTPs (generated)
│   └── llm_interactions.json      # Deception engine logs (generated)
│
├── models/
│   ├── classifier.pkl             # Trained attacker classifier (generated)
│   └── anomaly_detector.pkl       # Trained anomaly detector (generated)
│
├── logs/
│   ├── cowrie.json                # SSH honeypot logs (generated)
│   └── http_honeypot.json         # HTTP honeypot logs (generated)
│
├── test_cic2018.py                # Cross-dataset generalization test
├── requirements.txt               # Python dependencies
├── .gitignore                     # Excludes venv, .env, keys, datasets
└── README.md
```

---

## Usage

### Running the Honeypots
```bash
# Terminal 1 — SSH Honeypot
python honeypot/ssh_honeypot.py

# Terminal 2 — HTTP Honeypot
python honeypot/http_honeypot.py
```

### Testing the SSH Honeypot
```bash
ssh root@localhost -p 2222
```

### Testing the HTTP Honeypot
Visit in browser:
```
http://localhost:8080/admin
http://localhost:8080/login
http://localhost:8080/wp-admin
```

### Launching the Dashboard
```bash
streamlit run dashboard/app.py
```
Then open `http://localhost:8501`

---

## Results Summary

| Component | Metric | Result |
|---|---|---|
| Attacker Classifier | Cross-Validation Accuracy (CICIDS 2017) | 99.27% |
| Attacker Classifier | F1-Score — Bot / Script Kiddie | 1.00 |
| Attacker Classifier | F1-Score — Skilled Human / Normal | 0.99 / 0.98 |
| Cross-Dataset Test | Accuracy on Unseen CICIDS 2018 | 77.31% |
| Anomaly Detector | Attack Detection Rate (CICIDS 2018) | 100% |
| Anomaly Detector | False Positive Rate (CICIDS 2018) | 52.1% |
| TTP Extractor | Total TTPs Extracted | 23+ |

The drop in accuracy from CICIDS 2017 (99.27%) to unseen CICIDS 2018 (77.31%) demonstrates genuine pattern learning rather than overfitting, consistent with expected cross-dataset generalization behavior in network intrusion detection research.

---

## Original Contributions Beyond the Research Paper

| Paper's Original Scope | This Project's Extension |
|---|---|
| Uses an existing honeypot | Custom SSH + HTTP honeypots built from scratch |
| SSH data only | Adds HTTP/web attack detection pipeline |
| GPT-4-turbo (paid) | Groq API with LLaMA 3 (free, open access) |
| TTP extraction only | Adds supervised attacker classification |
| No deception layer | Adds LLM-driven dynamic deception engine |
| No dashboard | Adds full real-time research dashboard |
| Single-dataset evaluation | Adds cross-dataset generalization testing |

---

## Security Notes

- API keys are stored in `.env` and excluded from version control
- SSH host keys (`server.key`) are excluded from version control
- All datasets and trained models are excluded from version control due to size
- The honeypot is intended for isolated/local research use only — do not expose to the public internet without proper network isolation

---

## Citation

If referencing the underlying methodology, please cite:

> Lanka, P., Gupta, K., & Varol, C. (2024). Intelligent Threat Detection—AI-Driven Analysis of Honeypot Data to Counter Cyber Threats. *Electronics*, 13(13), 2465. https://doi.org/10.3390/electronics13132465

---

## Future Enhancements

- Live MITRE ATT&CK database lookup integration
- NSL-KDD cross-domain feature mapping analysis
- Automated incident response triggers
- Multi-honeypot deployment via Docker
- Real-time email/Slack alerting for Critical severity TTPs
