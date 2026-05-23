import os
import json
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="AI Security Review Board")

app.mount("/static", StaticFiles(directory="static"), name="static")

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")


class ReviewRequest(BaseModel):
    app_name: str
    app_version: Optional[str] = ""
    app_vendor: Optional[str] = ""
    app_env: Optional[str] = "corporate_endpoint"
    justification: Optional[str] = ""
    data_class: Optional[List[str]] = []
    permissions: Optional[List[str]] = []


def build_prompt(req: ReviewRequest) -> list:
    app_name = req.app_name
    vendor = req.app_vendor or "Unknown"
    version = req.app_version or "latest"
    env = (req.app_env or "corporate endpoint").replace("_", " ")
    justification = req.justification or "Not provided"
    data_class = ", ".join(req.data_class) if req.data_class else "Not specified"
    permissions = ", ".join(req.permissions) if req.permissions else "Not specified"

    system_msg = """You are a senior cybersecurity analyst at a major bank. You review non-standard software requests.

You MUST respond with ONLY a valid JSON object. No markdown. No backticks. No explanation. Just pure JSON.

EVERY text field must contain at least 2-3 detailed sentences. Do NOT leave any field empty or short."""

    user_msg = f"""Review this application for security risks in a banking environment:

- Application: {app_name}
- Version: {version}
- Vendor: {vendor}
- Environment: {env}
- Business Justification: {justification}
- Data Exposure: {data_class}
- Permissions: {permissions}

Return this exact JSON structure with ALL fields filled in with detailed content about {app_name}:

{{
  "verdict": "APPROVE or DENY or CONDITIONAL",
  "verdict_reason": "Write one detailed sentence about why you chose this verdict for {app_name}",
  "risk_score": 65,
  "cvss_estimate": 6.5,
  "cve_count_estimate": 12,
  "exploit_maturity": "Proof of Concept",
  "risk_dimensions": {{
    "vulnerability_history": 70,
    "supply_chain_risk": 55,
    "data_exposure_risk": 60,
    "regulatory_compliance_risk": 65,
    "threat_actor_interest": 50
  }},
  "executive_summary": "Write 3-4 detailed sentences about {app_name} security posture in banking. Mention specific risks. Discuss vulnerability history. Give your professional assessment of whether it should be used in a bank.",
  "known_vulnerabilities": [
    {{
      "cve_id": "CVE-2024-XXXXX",
      "title": "Name of a real vulnerability in {app_name}",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "description": "Write 2 sentences describing this specific vulnerability in {app_name} and its impact on banking systems."
    }},
    {{
      "cve_id": "CVE-2023-XXXXX",
      "title": "Name of another real vulnerability",
      "severity": "MEDIUM",
      "cvss_score": 5.5,
      "description": "Write 2 sentences describing this vulnerability and why it matters for financial institutions."
    }}
  ],
  "threat_intelligence": "Write 3 detailed sentences about how threat actors have targeted {app_name}. Mention any known APT groups or campaigns. Describe supply chain risks or trojanized versions if applicable.",
  "conditions": [
    "First specific condition for approving {app_name} in a bank",
    "Second specific security requirement",
    "Third specific control that must be in place"
  ],
  "remediation_actions": [
    "First specific remediation action for {app_name}",
    "Second specific security control to implement",
    "Third specific monitoring or hardening step"
  ],
  "regulatory_note": "Write 2-3 sentences about how {app_name} affects PCI-DSS, GDPR, FCA, or SOX compliance in a banking environment. Be specific about which requirements are relevant."
}}

CRITICAL RULES:
1. Replace ALL placeholder text with real, specific content about {app_name}
2. Every text field MUST have at least 2 full sentences
3. Include at least 2 real or realistic CVEs for {app_name}
4. Include at least 3 conditions and 3 remediation actions
5. All numbers must be actual numbers not strings
6. Output ONLY the JSON object, nothing else"""

    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg}
    ]


def clean_and_parse(raw: str, app_name: str) -> dict:
    raw = raw.strip()
    if "```json" in raw:
        raw = raw.split("```json", 1)[1]
    if "```" in raw:
        raw = raw.split("```")[0]
    raw = raw.strip()

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1:
        raw = raw[start:end + 1]

    result = json.loads(raw)

    # Validate verdict
    if "verdict" not in result:
        result["verdict"] = "CONDITIONAL"
    result["verdict"] = str(result.get("verdict", "CONDITIONAL")).upper()
    if result["verdict"] not in ("APPROVE", "DENY", "CONDITIONAL"):
        result["verdict"] = "CONDITIONAL"

    # Ensure text fields have content
    defaults = {
        "verdict_reason": f"{app_name} requires careful evaluation due to potential security risks in a banking environment.",
        "executive_summary": f"{app_name} presents moderate security concerns for deployment in a banking environment. The application has a history of vulnerabilities that could expose sensitive financial data. The security team should carefully evaluate the risk-benefit ratio before approval. Additional controls and monitoring would be required if deployment proceeds.",
        "threat_intelligence": f"{app_name} has been observed in various threat landscapes targeting financial institutions. Threat actors have attempted to exploit known vulnerabilities in this software to gain unauthorized access. Security teams should monitor vendor advisories and threat feeds for emerging risks.",
        "regulatory_note": f"Deployment of {app_name} in a banking environment must comply with PCI-DSS requirements for secure software and system hardening. GDPR Article 32 mandates appropriate technical measures for data protection. FCA and PRA guidelines require documented risk assessments for all non-standard software.",
    }
    for key, default_val in defaults.items():
        val = result.get(key, "")
        if not val or len(str(val).strip()) < 20:
            result[key] = default_val

    # Ensure arrays have content
    if not result.get("known_vulnerabilities") or not isinstance(result.get("known_vulnerabilities"), list) or len(result["known_vulnerabilities"]) == 0:
        result["known_vulnerabilities"] = [
            {
                "cve_id": "N/A",
                "title": f"General vulnerability assessment for {app_name}",
                "severity": "MEDIUM",
                "cvss_score": 5.0,
                "description": f"A comprehensive vulnerability scan should be performed on {app_name} before deployment. Historical vulnerability patterns suggest periodic security issues that require patching."
            }
        ]

    if not result.get("conditions") or not isinstance(result.get("conditions"), list) or len(result["conditions"]) == 0:
        result["conditions"] = [
            f"Deploy only the latest patched version of {app_name}",
            "Restrict access to authorized personnel with documented business need",
            "Enable comprehensive logging and monitoring of all activity",
            "Conduct quarterly vulnerability assessments"
        ]

    if not result.get("remediation_actions") or not isinstance(result.get("remediation_actions"), list) or len(result["remediation_actions"]) == 0:
        result["remediation_actions"] = [
            f"Update {app_name} to the latest stable version with all security patches",
            "Implement network segmentation to limit blast radius",
            "Deploy endpoint detection and response monitoring",
            "Establish automated patching schedule for future updates"
        ]

    # Ensure risk dimensions
    if not result.get("risk_dimensions") or not isinstance(result.get("risk_dimensions"), dict) or len(result.get("risk_dimensions", {})) < 3:
        rs = result.get("risk_score", 50)
        if not isinstance(rs, (int, float)):
            rs = 50
        result["risk_dimensions"] = {
            "vulnerability_history": min(100, int(rs + 10)),
            "supply_chain_risk": max(0, int(rs - 5)),
            "data_exposure_risk": int(rs),
            "regulatory_compliance_risk": min(100, int(rs + 5)),
            "threat_actor_interest": max(0, int(rs - 10)),
        }

    # Ensure numeric fields
    for key in ["risk_score", "cvss_estimate", "cve_count_estimate"]:
        try:
            result[key] = float(result.get(key, 0))
        except (ValueError, TypeError):
            result[key] = 0

    if not result.get("exploit_maturity") or result["exploit_maturity"] not in ["None", "Proof of Concept", "Active Exploitation", "Weaponized"]:
        score = result.get("risk_score", 50)
        if score >= 80:
            result["exploit_maturity"] = "Active Exploitation"
        elif score >= 60:
            result["exploit_maturity"] = "Proof of Concept"
        else:
            result["exploit_maturity"] = "None"

    return result


async def call_groq(messages: list) -> str:
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 3000,
            },
        )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=f"Groq error: {response.text}")
    data = response.json()
    return data["choices"][0]["message"]["content"]


async def call_anthropic(messages: list) -> str:
    prompt = messages[-1]["content"]
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 3000,
                "system": messages[0]["content"],
                "messages": [{"role": "user", "content": prompt}],
            },
        )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=f"Anthropic error: {response.text}")
    data = response.json()
    return "".join(b["text"] for b in data.get("content", []) if b.get("type") == "text")


async def call_ollama(messages: list) -> str:
    prompt = messages[0]["content"] + "\n\n" + messages[-1]["content"]
    try:
        async with httpx.AsyncClient(timeout=300) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 3000},
                },
            )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail="Cannot connect to Ollama. Make sure Ollama is running.\n\n"
                   "Download from https://ollama.com, then run: ollama pull llama3.2"
        )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=f"Ollama error: {response.text}")
    return response.json().get("response", "")


@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.post("/api/analyze")
async def analyze(req: ReviewRequest):
    messages = build_prompt(req)

    if GROQ_API_KEY:
        raw = await call_groq(messages)
        engine = "groq"
    elif ANTHROPIC_API_KEY:
        raw = await call_anthropic(messages)
        engine = "anthropic"
    else:
        raw = await call_ollama(messages)
        engine = "ollama"

    try:
        result = clean_and_parse(raw, req.app_name)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse AI response: {str(e)}\n\nRaw: {raw[:500]}")

    result["_engine"] = engine
    return result


@app.get("/api/health")
async def health():
    if GROQ_API_KEY:
        return {"status": "ok", "engine": "groq", "model": "llama-3.3-70b-versatile"}
    elif ANTHROPIC_API_KEY:
        return {"status": "ok", "engine": "anthropic", "model": "claude-sonnet"}
    else:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{OLLAMA_URL}/api/tags")
                models = [m["name"] for m in r.json().get("models", [])]
                return {"status": "ok", "engine": "ollama", "model": OLLAMA_MODEL, "models": models}
        except Exception:
            return {"status": "no_engine", "detail": "Set GROQ_API_KEY, ANTHROPIC_API_KEY, or run Ollama locally."}
