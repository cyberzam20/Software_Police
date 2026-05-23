import os
import json
import httpx
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta

app = FastAPI(title="Software Police - AI Security Review")
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


# ============================================================
# LIVE DATA SOURCES
# ============================================================

async def fetch_nvd_cves(keyword: str, max_results: int = 10) -> list:
    """Fetch latest CVEs from NIST NVD API (official US gov database)."""
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, params=params)
        if r.status_code != 200:
            return []
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", [])[:max_results]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            cvss_score = 0
            severity = "MEDIUM"
            metrics = cve.get("metrics", {})
            if metrics.get("cvssMetricV31"):
                m = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = m.get("baseScore", 0)
                severity = m.get("baseSeverity", "MEDIUM")
            elif metrics.get("cvssMetricV30"):
                m = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = m.get("baseScore", 0)
                severity = m.get("baseSeverity", "MEDIUM")
            elif metrics.get("cvssMetricV2"):
                m = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = m.get("baseScore", 0)
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "MEDIUM")
            published = cve.get("published", "")[:10]
            cves.append({
                "cve_id": cve_id,
                "description": desc[:400] if desc else "",
                "cvss_score": float(cvss_score) if cvss_score else 0,
                "severity": severity.upper(),
                "published": published,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return cves
    except Exception as e:
        print(f"NVD fetch error: {e}")
        return []


async def fetch_cisa_kev(keyword: str) -> list:
    """Fetch known exploited vulnerabilities from CISA KEV catalog."""
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url)
        if r.status_code != 200:
            return []
        data = r.json()
        kev = []
        keyword_lower = keyword.lower()
        for item in data.get("vulnerabilities", []):
            vendor = (item.get("vendorProject") or "").lower()
            product = (item.get("product") or "").lower()
            if keyword_lower in vendor or keyword_lower in product or vendor in keyword_lower or product in keyword_lower:
                kev.append({
                    "cve_id": item.get("cveID", ""),
                    "vendor": item.get("vendorProject", ""),
                    "product": item.get("product", ""),
                    "vulnerability_name": item.get("vulnerabilityName", ""),
                    "date_added": item.get("dateAdded", ""),
                    "short_description": item.get("shortDescription", ""),
                    "required_action": item.get("requiredAction", ""),
                    "ransomware_use": item.get("knownRansomwareCampaignUse", "Unknown"),
                })
        return kev[:10]
    except Exception as e:
        print(f"CISA KEV error: {e}")
        return []


async def fetch_epss_scores(cve_ids: list) -> dict:
    """Fetch EPSS (exploit prediction) scores from FIRST.org."""
    if not cve_ids:
        return {}
    try:
        ids = ",".join(cve_ids[:20])
        url = f"https://api.first.org/data/v1/epss?cve={ids}"
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
        if r.status_code != 200:
            return {}
        data = r.json()
        result = {}
        for item in data.get("data", []):
            cve_id = item.get("cve", "")
            score = float(item.get("epss", 0))
            percentile = float(item.get("percentile", 0))
            result[cve_id] = {
                "epss_score": round(score * 100, 2),
                "percentile": round(percentile * 100, 1),
            }
        return result
    except Exception as e:
        print(f"EPSS error: {e}")
        return {}


# ============================================================
# AI ANALYSIS WITH WEB SEARCH
# ============================================================

def build_messages(req: ReviewRequest, live_data: dict) -> tuple:
    app_name = req.app_name
    vendor = req.app_vendor or "Unknown"
    version = req.app_version or "latest"
    env = (req.app_env or "corporate endpoint").replace("_", " ")
    justification = req.justification or "Not provided"
    data_class = ", ".join(req.data_class) if req.data_class else "Not specified"
    permissions = ", ".join(req.permissions) if req.permissions else "Not specified"

    # Format live CVE data for the AI
    nvd_cves = live_data.get("nvd_cves", [])
    kev_entries = live_data.get("kev", [])
    epss_data = live_data.get("epss", {})

    cve_context = ""
    if nvd_cves:
        cve_context = "\n\nLATEST CVE DATA FROM NIST NVD (use this real data in your response):\n"
        for c in nvd_cves[:8]:
            epss_info = epss_data.get(c["cve_id"], {})
            epss_str = f" | EPSS: {epss_info.get('epss_score', 0)}% (top {100-epss_info.get('percentile', 0)}%)" if epss_info else ""
            cve_context += f"- {c['cve_id']} ({c.get('published', '')}) [CVSS {c['cvss_score']} {c['severity']}{epss_str}]: {c['description'][:200]}\n"

    kev_context = ""
    if kev_entries:
        kev_context = f"\n\n🚨 CISA KNOWN EXPLOITED VULNERABILITIES (these are being actively exploited RIGHT NOW):\n"
        for k in kev_entries[:5]:
            kev_context += f"- {k['cve_id']} ({k['date_added']}): {k['vulnerability_name']} - Ransomware use: {k['ransomware_use']}\n"

    system_msg = """You are a senior cybersecurity analyst with access to real-time threat intelligence. You review software installation requests and provide formal security assessments using live data from NIST NVD, CISA KEV, EPSS, and current threat intelligence.

You MUST respond with ONLY a valid JSON object. No markdown. No backticks. No explanation before or after. Just the raw JSON.

EVERY text field must contain at least 2-3 detailed, specific sentences. Use the live CVE and threat data provided to give the most current assessment possible."""

    user_msg = f"""Perform a comprehensive security review of this application using real-time threat intelligence:

- Application: {app_name}
- Version: {version}
- Vendor: {vendor}
- Deployment Environment: {env}
- Business Justification: {justification}
- Data Sensitivity: {data_class}
- Required Permissions: {permissions}
{cve_context}{kev_context}

Use the live data above PLUS your knowledge of:
- Recent breaches or supply chain attacks involving {app_name}
- Malware that targets or impersonates {app_name} (search engines, VirusTotal patterns, etc.)
- Known trojanized versions or fake download sites
- APT groups or threat actors that target this software
- Recent CVE disclosures (use the NVD data above)
- Active exploitation (use the CISA KEV data above)

Return ONLY this JSON:

{{
  "verdict": "APPROVE or DENY or CONDITIONAL",
  "verdict_reason": "One detailed sentence with verdict reasoning",
  "risk_score": 65,
  "cvss_estimate": 6.5,
  "cve_count_estimate": {len(nvd_cves) if nvd_cves else 10},
  "exploit_maturity": "None or Proof of Concept or Active Exploitation or Weaponized",
  "actively_exploited": {str(len(kev_entries) > 0).lower()},
  "kev_count": {len(kev_entries)},
  "risk_dimensions": {{
    "vulnerability_history": 70,
    "supply_chain_risk": 55,
    "data_exposure_risk": 60,
    "regulatory_compliance_risk": 65,
    "threat_actor_interest": 50,
    "malware_distribution_risk": 40
  }},
  "executive_summary": "3-4 detailed sentences about {app_name} current security posture. Reference recent CVEs and active threats from the live data above.",
  "known_vulnerabilities": [
    {{
      "cve_id": "Use REAL CVE IDs from the NVD data above",
      "title": "Vulnerability name",
      "severity": "CRITICAL or HIGH or MEDIUM or LOW",
      "cvss_score": 7.5,
      "epss_score": 5.2,
      "published": "YYYY-MM-DD",
      "description": "2 sentences about this specific vulnerability and impact",
      "actively_exploited": false
    }}
  ],
  "malware_intelligence": {{
    "known_malware_campaigns": "Describe any known malware campaigns that target or impersonate {app_name}. Mention specific malware families, fake download sites, or trojanized installers. Be specific.",
    "supply_chain_incidents": "Describe any past supply chain attacks or compromised distributions of {app_name}. If none, say no known incidents but mention general supply chain best practices.",
    "trojanized_distributions": "Mention any known fake/trojanized versions, suspicious download sources to avoid, or impersonation tactics. Include specific URLs/domains if known."
  }},
  "threat_intelligence": "3 detailed sentences about current threat landscape for {app_name}, including APT groups, recent campaigns, and active exploitation trends.",
  "download_recommendations": {{
    "official_source": "The official, verified download URL for {app_name}",
    "verification_method": "How to verify download integrity (checksums, signatures, etc.)",
    "avoid_sources": "Specific third-party sources to AVOID and why"
  }},
  "conditions": [
    "Specific condition 1",
    "Specific condition 2",
    "Specific condition 3",
    "Specific condition 4"
  ],
  "remediation_actions": [
    "Specific action 1",
    "Specific action 2",
    "Specific action 3",
    "Specific action 4"
  ],
  "regulatory_note": "2-3 sentences on GDPR, SOC 2, ISO 27001, PCI-DSS implications.",
  "data_freshness": "Data sourced from NIST NVD, CISA KEV, EPSS, and current threat intelligence as of {datetime.now().strftime('%Y-%m-%d')}"
}}

CRITICAL: Use the REAL CVE IDs and data from the live sources above. Do not make up CVEs when real ones are provided."""

    return system_msg, user_msg


@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.post("/api/analyze")
async def analyze(req: ReviewRequest):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not set.")

    # Determine search keyword (prefer vendor, fallback to app name)
    search_keyword = req.app_name

    # Fetch live data in parallel
    nvd_task = fetch_nvd_cves(search_keyword, max_results=10)
    kev_task = fetch_cisa_kev(search_keyword)

    nvd_cves, kev_entries = await asyncio.gather(nvd_task, kev_task)

    # Fetch EPSS for the CVEs we found
    cve_ids = [c["cve_id"] for c in nvd_cves[:10]]
    epss_data = await fetch_epss_scores(cve_ids) if cve_ids else {}

    live_data = {
        "nvd_cves": nvd_cves,
        "kev": kev_entries,
        "epss": epss_data,
    }

    system_msg, user_msg = build_messages(req, live_data)

    # Call Claude API
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
        raise HTTPException(status_code=503, detail="Cannot connect to Anthropic API.")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Request timed out.")

    if response.status_code != 200:
        # Try fallback model
        if "not_found" in response.text.lower() or "model" in response.text.lower():
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
            raise HTTPException(status_code=response.status_code, detail=f"API error: {response.text}")

    data = response.json()
    raw = "".join(b["text"] for b in data.get("content", []) if b.get("type") == "text")

    # Parse JSON
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
        raise HTTPException(status_code=500, detail=f"Parse error: {str(e)}")

    # Validate
    result["verdict"] = str(result.get("verdict", "CONDITIONAL")).upper()
    if result["verdict"] not in ("APPROVE", "DENY", "CONDITIONAL"):
        result["verdict"] = "CONDITIONAL"

    for key in ["risk_score", "cvss_estimate", "cve_count_estimate"]:
        try:
            result[key] = float(result.get(key, 0))
        except (ValueError, TypeError):
            result[key] = 0

    # Attach raw live data for the frontend to display
    result["_live_data"] = {
        "nvd_cve_count": len(nvd_cves),
        "kev_count": len(kev_entries),
        "kev_entries": kev_entries[:5],
        "latest_cves": nvd_cves[:8],
        "epss_data": epss_data,
        "fetched_at": datetime.now().isoformat(),
    }

    return result


@app.get("/api/health")
async def health():
    return {
        "status": "ok" if ANTHROPIC_API_KEY else "no_key",
        "engine": "anthropic",
        "data_sources": ["NIST NVD", "CISA KEV", "FIRST.org EPSS", "Claude AI"],
        "api_key_set": bool(ANTHROPIC_API_KEY)
    }
