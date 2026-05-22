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

# Engine priority: GROQ_API_KEY (free cloud) > ANTHROPIC_API_KEY (paid cloud) > Ollama (local)
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


def build_prompt(req: ReviewRequest) -> str:
    app_name = req.app_name
    vendor = req.app_vendor or "Unknown"
    version = req.app_version or "latest"
    env = (req.app_env or "corporate endpoint").replace("_", " ")
    justification = req.justification or "Not provided"
    data_class = ", ".join(req.data_class) if req.data_class else "Not specified"
    permissions = ", ".join(req.permissions) if req.permissions else "Not specified"

    return f"""You are a cybersecurity analyst at a bank. Review this application request and respond with ONLY valid JSON.

Application: {app_name}
Version: {version}
Vendor: {vendor}
Environment: {env}
Business Justification: {justification}
Data Exposure: {data_class}
Permissions Needed: {permissions}

You MUST respond with ONLY this JSON (fill in ALL fields with real detailed content about {app_name}):

{{"verdict":"DENY","verdict_reason":"PuTTY has a history of critical vulnerabilities including private key compromise making it high risk for banking endpoints.","risk_score":75,"cvss_estimate":7.5,"cve_count_estimate":15,"exploit_maturity":"Active Exploitation","risk_dimensions":{{"vulnerability_history":80,"supply_chain_risk":60,"data_exposure_risk":70,"regulatory_compliance_risk":65,"threat_actor_interest":75}},"executive_summary":"This is a 3-4 sentence summary about why {app_name} is risky or safe in a banking environment. Mention specific security concerns. Discuss the vulnerability history. Recommend whether the security team should approve or deny.","known_vulnerabilities":[{{"cve_id":"CVE-2024-31497","title":"PuTTY ECDSA Private Key Recovery","severity":"CRITICAL","cvss_score":9.8,"description":"A critical vulnerability allowing recovery of ECDSA private keys due to biased nonce generation in PuTTY versions before 0.81."}},{{"cve_id":"CVE-2023-48795","title":"SSH Terrapin Attack","severity":"HIGH","cvss_score":7.5,"description":"Prefix truncation attack affecting SSH connections that can downgrade connection security."}}],"threat_intelligence":"{app_name} has been targeted by APT groups and state-sponsored actors. Trojanized versions have been distributed through supply chain attacks. Security teams should verify download integrity.","conditions":["Must use latest patched version","Restrict to authorized users only","Enable logging of all sessions","Regular vulnerability scanning required"],"remediation_actions":["Update to the latest version immediately","Implement application whitelisting","Deploy endpoint detection and response","Monitor for unauthorized usage"],"regulatory_note":"Use of {app_name} in a banking environment requires compliance with PCI-DSS requirement 2.2 for hardening standards and GDPR Article 32 for security of processing."}}

IMPORTANT: The example above is for PuTTY. You must change ALL the content to be specifically about {app_name} by {vendor}. Write real, specific, detailed content about {app_name}. Every text field must have at least 2 sentences. Do NOT copy the example - write original analysis for {app_name}.

Respond with ONLY the JSON object. No other text."""


def clean_and_parse(raw: str, app_name: str) -> dict:
    """Clean AI response and parse JSON."""
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

    # Ensure text fields
    defaults = {
        "verdict_reason": f"Review of {app_name} requires further analysis.",
        "executive_summary": f"{app_name} requires careful security evaluation before deployment in a banking environment. The security team should assess the application's vulnerability history, data handling practices, and regulatory compliance before making a decision.",
        "threat_intelligence": f"No specific threat intelligence available for {app_name} at this time. Standard security monitoring and vendor advisories should be followed.",
        "regulatory_note": f"Deployment of {app_name} should comply with PCI-DSS, GDPR, and internal security policies.",
    }
    for key, default_val in defaults.items():
        if not result.get(key) or len(str(result.get(key, ""))) < 5:
            result[key] = default_val

    # Ensure arrays
    for key in ["known_vulnerabilities", "conditions", "remediation_actions"]:
        if not result.get(key) or not isinstance(result.get(key), list):
            result[key] = []

    # Ensure risk dimensions
    if not result.get("risk_dimensions") or not isinstance(result.get("risk_dimensions"), dict):
        rs = result.get("risk_score", 50)
        result["risk_dimensions"] = {
            "vulnerability_history": rs,
            "supply_chain_risk": max(0, rs - 10),
            "data_exposure_risk": rs,
            "regulatory_compliance_risk": rs,
            "threat_actor_interest": max(0, rs - 15),
        }

    # Ensure numeric fields
    for key in ["risk_score", "cvss_estimate", "cve_count_estimate"]:
        try:
            result[key] = float(result.get(key, 0))
        except (ValueError, TypeError):
            result[key] = 0

    return result


async def call_groq(prompt: str) -> str:
    """Call Groq's free API."""
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 2000,
            },
        )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=f"Groq error: {response.text}")
    data = response.json()
    return data["choices"][0]["message"]["content"]


async def call_anthropic(prompt: str) -> str:
    """Call Anthropic API."""
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=f"Anthropic error: {response.text}")
    data = response.json()
    return "".join(b["text"] for b in data.get("content", []) if b.get("type") == "text")


async def call_ollama(prompt: str) -> str:
    """Call local Ollama."""
    try:
        async with httpx.AsyncClient(timeout=300) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 2000},
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
    prompt = build_prompt(req)

    # Pick the best available engine
    if GROQ_API_KEY:
        raw = await call_groq(prompt)
        engine = "groq"
    elif ANTHROPIC_API_KEY:
        raw = await call_anthropic(prompt)
        engine = "anthropic"
    else:
        raw = await call_ollama(prompt)
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
        return {"status": "ok", "engine": "groq", "model": "llama-3.3-70b-versatile",}
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
