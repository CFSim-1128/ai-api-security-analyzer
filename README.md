# 🔐 AI API Security Analyzer

An advanced AI-powered API security analyzer that detects vulnerabilities, analyzes JWT tokens, and evaluates risk levels using rule-based and machine learning techniques.

---

## 🚀 Features

- 🔍 API endpoint scanning (GET, POST, etc.)
- 🧠 AI anomaly detection (Isolation Forest)
- 🔐 JWT security analysis
- ⚠️ Vulnerability detection (headers, exposure, error leaks)
- 📊 Risk scoring engine (low → critical)
- 🌐 FastAPI backend with OpenAPI documentation
- 📈 Streamlit dashboard UI

---

## 🏗 Architecture

Client → FastAPI Backend → Scanner → Rule Engine → AI Model → Risk Scoring → Dashboard

---

## 🛠 Tech Stack

- Python
- FastAPI
- Scikit-learn
- Streamlit
- httpx
- PyJWT

---

## ⚙️ Installation

```bash
git clone https://github.com/CFSim-1128/ai-api-security-analyzer.git
cd ai-api-security-analyzer

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
