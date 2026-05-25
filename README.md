# 🛡 Software Police — AI Security Review Board

> An AI-powered application security review tool that helps security teams and individuals make informed decisions about software installations — backed by live threat intelligence from NIST NVD, CISA KEV, and FIRST EPSS.

**🔗 Live Demo:** [softwarepolice.up.railway.app](https://softwarepolice.up.railway.app)

---

## What It Does

Software Police automates the security review process for any application. Submit a software request and get back:

- ✅ A formal **Approve / Deny / Conditional** verdict
- 🔴 **Live CVEs** pulled in real-time from the NIST National Vulnerability Database (newest first)
- 🚨 **CISA KEV alerts** — flags if the software has vulnerabilities being actively exploited right now
- 📊 **EPSS scores** — probability the vulnerability will be exploited in the next 30 days
- 🦠 **Malware intelligence** — known campaigns, trojanized versions, supply chain risks
- ⬇️ **Safe download guidance** — official sources, verification methods, sources to avoid
- 📋 **Remediation recommendations** and regulatory implications (GDPR, SOC 2, ISO 27001)

---

## Why I Built This

I work in Threat and Vulnerability Management and wanted to explore how AI could accelerate the software review process that security teams do manually every day. This tool demonstrates how large language models can be combined with live security data sources to produce actionable, up-to-date risk assessments in seconds rather than hours.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, httpx |
| AI Engine | Anthropic Claude API (claude-sonnet) |
| Vulnerability Data | NIST NVD API v2.0 |
| Exploit Intelligence | CISA KEV Catalog, FIRST.org EPSS |
| Frontend | Vanilla HTML/CSS/JavaScript |
| Deployment | Railway |

---

## Live Data Sources

| Source | What It Provides |
|---|---|
| **NIST NVD** | Official US government CVE database — latest vulnerabilities sorted newest first |
| **CISA KEV** | Known Exploited Vulnerabilities catalog — actively exploited CVEs |
| **FIRST EPSS** | Exploit Prediction Scoring System — probability of exploitation in 30 days |
| **Claude AI** | Synthesises all data with threat intel, malware campaigns, and safe download guidance |

---

## How It Works

```
User submits app name
        ↓
Parallel fetch: NVD CVEs + CISA KEV + EPSS scores
        ↓
Claude AI analyses live data + threat intelligence
        ↓
Returns structured JSON: verdict, CVEs, malware intel, download guidance
        ↓
Frontend renders full security report
```

---

## Screenshots

> Submit any application and receive a full security report in under 15 seconds.

**Key sections in each report:**
- Security verdict with reasoning
- Risk score, CVSS estimate, CVE count, exploit maturity
- Executive summary for non-technical stakeholders
- Live CVE list with NVD links, publication dates, EPSS scores
- CISA KEV red alert banner (if actively exploited)
- Malware and supply chain intelligence
- Safe download guidance
- Risk dimension breakdown across 6 axes
- Remediation actions and regulatory implications

---

## Running Locally

**Requirements:** Python 3.10+, Anthropic API key

```bash
# Clone the repo
git clone https://github.com/yourusername/Software_Police
cd Software_Police

# Install dependencies
pip install fastapi uvicorn httpx python-multipart

# Set your API key
export ANTHROPIC_API_KEY=your-key-here   # Mac/Linux
set ANTHROPIC_API_KEY=your-key-here      # Windows

# Start the server
uvicorn app:app --reload

# Open in browser
http://localhost:8000
```

---

## Project Structure

```
Software_Police/
├── app.py              # FastAPI backend — live data fetching + Claude AI
├── requirements.txt    # Python dependencies
├── Procfile            # Railway deployment config
├── static/
│   └── index.html      # Full frontend (HTML/CSS/JS)
└── README.md
```

---

## Roadmap

- [ ] PDF report export
- [ ] Batch review mode (multiple apps at once)
- [ ] Team review queue with approve/deny workflow
- [ ] Email alerts for new KEV entries matching installed software
- [ ] Integration with ServiceNow / Jira for change management tickets
- [ ] VirusTotal API integration for file hash scanning

---

## Author

Built by a Threat & VM security professional exploring AI applications in cybersecurity.

Connect on LinkedIn: @rehabz

---

## Disclaimer

This tool is for informational purposes only. Always consult your organisation's security policies and conduct your own due diligence before making software approval decisions.
