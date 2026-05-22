# AI Security Review Board

AI-powered application security review tool for Threat & VM teams in banking.

Submit non-standard application requests and receive a formal **Approve / Deny / Conditional** recommendation backed by CVE data, threat intelligence, and regulatory analysis.

## Quick Start

### Local (free with Ollama)
```bash
pip install fastapi uvicorn httpx python-multipart
ollama pull llama3.2
uvicorn app:app --reload
```
Open http://localhost:8000

### Cloud (free with Groq)
```bash
export GROQ_API_KEY=your-free-key-from-console.groq.com
uvicorn app:app --reload
```

### Cloud (paid with Anthropic)
```bash
export ANTHROPIC_API_KEY=sk-ant-your-key
uvicorn app:app --reload
```

## Deploy to Railway (free)
1. Push to GitHub
2. Sign up at railway.com with GitHub
3. New Project → Deploy from GitHub
4. Add variable: `GROQ_API_KEY` (free from console.groq.com)
5. Done — Railway gives you a public URL

## Features
- Approve / Deny / Conditional verdicts
- CVE history and CVSS scoring
- Risk dimension analysis (5 axes)
- Exploit maturity assessment
- Banking regulatory implications (PCI-DSS, GDPR, FCA, SOX)
- Threat intelligence narrative
- Remediation recommendations
- Session review history

## AI Engine Priority
The app auto-selects the best available engine:
1. **Groq** (free, fast, cloud) — if `GROQ_API_KEY` is set
2. **Anthropic** (paid, best quality) — if `ANTHROPIC_API_KEY` is set
3. **Ollama** (free, local) — fallback, no key needed
