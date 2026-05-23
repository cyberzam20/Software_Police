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

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


class ReviewRequest(BaseModel):
    app_name: str
    app_version: Optional[str] = ""
    app_vendor: Optional[str] = ""
    app_env: Optional[str] = "corporate_endpoint"
    justification: Optional[str] = ""
    data_class: Optional[List[str]] = []
    permissions: Optional[List[str]] = []


def build_messages(req: ReviewRequest) -> tuple:
    app_name = req.app_name
    vendor = req.app_vendor or "Unknown"
    version = req.app_version or "latest"
    env = (req.app_env or "corporate endpoint").replace("_", " ")
    justification = req.justification or "Not provided"
    data_class = ", ".join(req.data_class) if req.data_class else "Not specified"
    permissions = ", ".join(req.permissions) if req.permissions else "Not specified"

    system_msg = """You are a senior cybersecurity analyst. You review software installation requests for organizations and provide formal security assessments.

You MUST respond with ONLY a valid JSON object. No markdown. No backticks. No explanation before or after. Just the raw JSON starting with { and ending with }.

EVERY text field must contain at least 2-3 detailed, specific sentences. Do NOT leave any field empty or with placeholder text."""

    user_msg = f"""Perform a formal security review of this application request for an organization:

- Application: {app_name}
- Version: {version}
- Vendor: {vendor}
- Deployment Environment: {env}
- Business Justification: {justification}
- Data Sensitivity: {data_class}
- Required Permissions: {permissions}

Assess using: known CVEs, vulnerability history, threat actor interest, supply chain risk, exploit availability, and regulatory implications (GDPR, SOC 2, ISO 27001, PCI-DSS where applicable).

Return this exact JSON structure. Fill ALL fields with real, detailed, specific content about {app_name}:

{{
  "verdict": "APPROVE or DENY or CONDITIONAL - pick one",
  "verdict_reason": "One detailed sentence explaining why you chose this verdict specifically for {app_name}",
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
  "executive_summary": "Write 3-4 detailed sentences about {app_name} security posture for organizations. Mention specific risks, vulnerability patterns, and your professional recommendation. Be specific - do not use generic language.",
  "known_vulnerabilities": [
    {{
      "cve_id": "CVE-XXXX-XXXXX",
      "title": "Name of a real known vulnerability in {app_name}",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "description": "Write 2 specific sentences about this vulnerability in {app_name}, how it can be exploited, and its impact on organizations."
    }},
    {{
      "cve_id": "CVE-XXXX-XXXXX",
      "title": "Another real vulnerability",
      "severity": "MEDIUM",
      "cvss_score": 5.5,
      "description": "Write 2 specific sentences about this vulnerability and why it matters for organizations handling sensitive data."
    }},
    {{
      "cve_id": "CVE-XXXX-XXXXX",
      "title": "A third vulnerability if applicable",
      "severity": "HIGH",
      "cvss_score": 7.0,
      "description": "Write 2 specific sentences about this vulnerability."
    }}
  ],
  "threat_intelligence": "Write 3 detailed sentences about how threat actors have targeted {app_name}. Mention specific APT groups, campaigns, or attack patterns if known. Describe any supply chain risks, trojanized versions, or targeted attacks against this software.",
  "conditions": [
    "First specific condition required before {app_name} can be approved",
    "Second specific security control or requirement",
    "Third specific condition related to monitoring or access control",
    "Fourth condition if applicable"
  ],
  "remediation_actions": [
    "First specific remediation action the security team should take for {app_name}",
    "Second specific technical control to implement",
    "Third specific monitoring or hardening step",
    "Fourth action if applicable"
  ],
  "regulatory_note": "Write 2-3 specific sentences about how deploying {app_name} affects GDPR, SOC 2, ISO 27001, PCI-DSS, or other regulatory compliance. Reference specific requirements that are relevant."
}}

RULES:
1. Use real CVE IDs you know about for {app_name}. If you dont know exact CVE IDs, use realistic ones and describe real vulnerability types that affect this kind of software.
2. Every text field MUST have at least 2 full detailed sentences - no exceptions.
3. All number fields must be actual numbers, not strings.
4. The verdict must be exactly APPROVE, DENY, or CONDITIONAL.
5. Be thorough and security-focused. Err on the side of caution.
6. Output ONLY the JSON. No other text."""

    return system_msg, user_msg


@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.post("/api/analyze")
async def analyze(req: ReviewRequest):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="ANTHROPIC_API_KEY not set. Add it as a variable in Railway."
        )

    system_msg, user_msg = build_messages(req)

    try:
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-5-20250929",
                    "max_tokens": 4000,
                    "system": system_msg,
                    "messages": [{"role": "user", "content": user_msg}],
                },
            )
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Cannot connect to Anthropic API. Check your internet connection.")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Request timed out. Please try again.")

    if response.status_code != 200:
        error_detail = response.text
        # If model not found, try fallback
        if "not_found" in error_detail.lower() or "model" in error_detail.lower():
            try:
                async with httpx.AsyncClient(timeout=90) as client:
                    response = await client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": ANTHROPIC_API_KEY,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": "claude-3-5-sonnet-20241022",
                            "max_tokens": 4000,
                            "system": system_msg,
                            "messages": [{"role": "user", "content": user_msg}],
                        },
                    )
                if response.status_code != 200:
                    raise HTTPException(status_code=response.status_code, detail=f"Anthropic API error: {response.text}")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Both models failed. Error: {str(e)}")
        else:
            raise HTTPException(status_code=response.status_code, detail=f"Anthropic API error: {error_detail}")

    data = response.json()
    raw = "".join(b["text"] for b in data.get("content", []) if b.get("type") == "text")

    # Clean response
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

    try:
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse response: {str(e)}\n\nRaw: {raw[:500]}")

    # Validate verdict
    result["verdict"] = str(result.get("verdict", "CONDITIONAL")).upper()
    if result["verdict"] not in ("APPROVE", "DENY", "CONDITIONAL"):
        result["verdict"] = "CONDITIONAL"

    # Ensure numeric fields
    for key in ["risk_score", "cvss_estimate", "cve_count_estimate"]:
        try:
            result[key] = float(result.get(key, 0))
        except (ValueError, TypeError):
            result[key] = 0

    return result


@app.get("/api/health")
async def health():
    return {
        "status": "ok" if ANTHROPIC_API_KEY else "no_key",
        "engine": "anthropic",
        "api_key_set": bool(ANTHROPIC_API_KEY)
    }
