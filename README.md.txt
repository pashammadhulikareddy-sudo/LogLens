
# 🔐 LogLens – Security Log Analysis Dashboard

## 📌 Project Overview
LogLens is a web-based security log analysis tool developed using Python and Streamlit. It analyzes Apache and Nginx log files, identifies suspicious activities, detects common cyber attacks, and displays security insights through an interactive dashboard.

## 🚀 Features
- Upload Apache and Nginx log files.
- Analyze HTTP status codes.
- Detect SQL Injection attacks.
- Detect Cross-Site Scripting (XSS).
- Detect Directory Traversal attacks.
- Identify possible Brute Force attacks.
- Classify attacks by severity (HIGH and MEDIUM).
- Display suspicious IP addresses.
- GeoIP-based attacker location lookup.
- Visualize attacks per hour.
- Display security charts and statistics.
- Download security analysis reports.
- Measure processing time and logs processed per second.
- Dark-themed dashboard.

## 🛠️ Technologies Used
- Python
- Streamlit
- Matplotlib
- Regular Expressions (Regex)
- Requests
- IP Address Library

## 📊 Performance Testing

| Log Entries | Processing Time | Logs/Second |
|---|---:|---:|
| 1,000 | 0.0808 seconds | 12,375.75 |
| 10,000 | 0.7443 seconds | 13,435.35 |

*Performance values are from the tests conducted during development.*

## ⚙️ How to Run Locally

1. Clone the repository:
   `git clone https://github.com/pashammadhulikareddy-sudo/loglens.git`

2. Install dependencies:
   `pip install -r requirements.txt`

3. Run the application:
   `streamlit run app.py`

## 🌐 Live Demo
https://loglenssecurity.streamlit.app/

## 👩‍💻 Project Repository
https://github.com/pashammadhulikareddy-sudo/loglens

## 🎯 Objective
The main objective of LogLens is to simplify security log monitoring by automatically identifying suspicious patterns and presenting useful security information in an easy-to-understand dashboard.

---
**Project: LogLens – Simplified Security Log Analysis**
