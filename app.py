import os
import json
import re
import httpx
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

app = FastAPI(title="Software Police")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL_PRIMARY   = "claude-opus-4-5-20251101"
MODEL_FALLBACK  = "claude-sonnet-4-5-20250929"
MODEL_FALLBACK2 = "claude-3-5-sonnet-20241022"


class ReviewRequest(BaseModel):
    app_name: str
    app_version: Optional[str] = ""
    app_vendor: Optional[str] = ""
    app_env: Optional[str] = "corporate_endpoint"
    justification: Optional[str] = ""
    data_class: Optional[List[str]] = []
    permissions: Optional[List[str]] = []


# ──────────────────────────────────────────────
# LIVE DATA SOURCES
# ──────────────────────────────────────────────

async def fetch_nvd_cves(keyword: str, max_results: int = 15) -> list:
    """Fetch CVEs from NIST NVD sorted newest first."""
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "sortBy": "published",
            "sortOrder": "dsc",   # newest first
        }
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, params=params)
        if r.status_code != 200:
            return []
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve   = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc  = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            cvss_score, severity = 0.0, "MEDIUM"
            if metrics.get("cvssMetricV31"):
                m = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score, severity = m.get("baseScore", 0), m.get("baseSeverity", "MEDIUM")
            elif metrics.get("cvssMetricV30"):
                m = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score, severity = m.get("baseScore", 0), m.get("baseSeverity", "MEDIUM")
            elif metrics.get("cvssMetricV2"):
                m = metrics["cvssMetricV2"][0]
                cvss_score = m["cvssData"].get("baseScore", 0)
                severity   = m.get("baseSeverity", "MEDIUM")
            published = cve.get("published", "")[:10]
            cves.append({
                "cve_id":    cve_id,
                "description": desc[:500],
                "cvss_score": float(cvss_score),
                "severity":  severity.upper(),
                "published": published,
                "nvd_url":   f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        # Sort newest first explicitly (NVD sometimes ignores sortOrder)
        cves.sort(key=lambda x: x["published"], reverse=True)
        return cves
    except Exception as e:
        print(f"NVD error: {e}")
        return []


async def fetch_cisa_kev(keyword: str) -> list:
    """Check CISA Known Exploited Vulnerabilities catalog."""
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url)
        if r.status_code != 200:
            return []
        kl = keyword.lower()
        kev = []
        for item in r.json().get("vulnerabilities", []):
            vp  = (item.get("vendorProject") or "").lower()
            pr  = (item.get("product") or "").lower()
            if kl in vp or kl in pr or vp in kl or pr in kl:
                kev.append({
                    "cve_id":           item.get("cveID", ""),
                    "vendor":           item.get("vendorProject", ""),
                    "product":          item.get("product", ""),
                    "vulnerability_name": item.get("vulnerabilityName", ""),
                    "date_added":       item.get("dateAdded", ""),
                    "short_description": item.get("shortDescription", ""),
                    "required_action":  item.get("requiredAction", ""),
                    "ransomware_use":   item.get("knownRansomwareCampaignUse", "Unknown"),
                })
        # Sort most recently added first
        kev.sort(key=lambda x: x["date_added"], reverse=True)
        return kev[:10]
    except Exception as e:
        print(f"CISA KEV error: {e}")
        return []


async def fetch_epss(cve_ids: list) -> dict:
    """Fetch EPSS exploit-prediction scores from FIRST.org."""
    if not cve_ids:
        return {}
    try:
        url = f"https://api.first.org/data/v1/epss?cve={','.join(cve_ids[:20])}"
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
        if r.status_code != 200:
            return {}
        return {
            item["cve"]: {
                "epss_score":  round(float(item.get("epss", 0)) * 100, 2),
                "percentile":  round(float(item.get("percentile", 0)) * 100, 1),
            }
            for item in r.json().get("data", [])
        }
    except Exception as e:
        print(f"EPSS error: {e}")
        return {}


# ──────────────────────────────────────────────
# PROMPT BUILDER
# ──────────────────────────────────────────────

def build_prompt(req: ReviewRequest, live: dict) -> tuple:
    name      = req.app_name
    vendor    = req.app_vendor or "Unknown"
    version   = req.app_version or "latest"
    env       = (req.app_env or "").replace("_", " ")
    just      = req.justification or "Not provided"
    data_cls  = ", ".join(req.data_class)  if req.data_class  else "Not specified"
    perms     = ", ".join(req.permissions) if req.permissions else "Not specified"

    nvd_cves  = live.get("nvd_cves", [])
    kev       = live.get("kev", [])
    epss      = live.get("epss", {})

    cve_block = ""
    if nvd_cves:
        lines = []
        for c in nvd_cves[:10]:
            ep = epss.get(c["cve_id"], {})
            ep_str = f" EPSS:{ep['epss_score']}%" if ep else ""
            lines.append(f"  {c['cve_id']} {c['published']} CVSS:{c['cvss_score']} {c['severity']}{ep_str} — {c['description'][:180]}")
        cve_block = "\n\nLIVE CVE DATA (newest first, use these IDs in your response):\n" + "\n".join(lines)

    kev_block = ""
    if kev:
        lines = [f"  {k['cve_id']} added:{k['date_added']} ransomware:{k['ransomware_use']} — {k['vulnerability_name']}" for k in kev[:5]]
        kev_block = "\n\nCISA KEV (actively exploited RIGHT NOW):\n" + "\n".join(lines)

    system = (
        "You are a senior cybersecurity analyst. Review software requests using live threat data. "
        "Respond with ONLY a raw JSON object — no markdown, no backticks, no text outside the JSON. "
        "All string values must use straight double-quotes. Never use smart/curly quotes. "
        "Never use apostrophes inside strings — rewrite to avoid them. "
        "Keep descriptions under 200 characters each to avoid truncation. "
        "All text fields must be fully written — no placeholders."
    )

    user = f"""Review this software for security risks:
- App: {name}
- Version: {version}
- Vendor: {vendor}
- Environment: {env}
- Justification: {just}
- Data sensitivity: {data_cls}
- Permissions: {perms}
{cve_block}{kev_block}

Return ONLY this JSON (use the live CVE IDs above, newest first):

{{
  "verdict": "APPROVE",
  "verdict_reason": "One sentence explaining the verdict for {name}.",
  "risk_score": 55,
  "cvss_estimate": 5.5,
  "cve_count_estimate": {len(nvd_cves) or 5},
  "exploit_maturity": "Proof of Concept",
  "actively_exploited": {str(len(kev) > 0).lower()},
  "kev_count": {len(kev)},
  "risk_dimensions": {{
    "vulnerability_history": 60,
    "supply_chain_risk": 50,
    "data_exposure_risk": 55,
    "regulatory_compliance_risk": 50,
    "threat_actor_interest": 45,
    "malware_distribution_risk": 35
  }},
  "executive_summary": "Two to three sentences about {name} security posture and key risks.",
  "known_vulnerabilities": [
    {{
      "cve_id": "CVE-YYYY-NNNNN",
      "title": "Short vulnerability title",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "epss_score": 3.2,
      "published": "YYYY-MM-DD",
      "description": "One sentence describing the vulnerability and its impact.",
      "actively_exploited": false
    }}
  ],
  "malware_intelligence": {{
    "known_malware_campaigns": "One or two sentences about malware campaigns targeting {name}.",
    "supply_chain_incidents": "One or two sentences about supply chain risks for {name}.",
    "trojanized_distributions": "One or two sentences about fake or trojanized versions."
  }},
  "threat_intelligence": "Two sentences about current threat landscape for {name}.",
  "download_recommendations": {{
    "official_source": "Official download URL for {name}",
    "verification_method": "How to verify the download integrity",
    "avoid_sources": "Sources to avoid when downloading {name}"
  }},
  "conditions": ["Condition one.", "Condition two.", "Condition three."],
  "remediation_actions": ["Action one.", "Action two.", "Action three."],
  "regulatory_note": "One or two sentences on GDPR, SOC 2, or ISO 27001 implications."
}}

RULES:
1. Use real CVE IDs from the live data above. Show newest CVEs first.
2. Keep all string values SHORT (under 200 chars) to avoid JSON truncation.
3. No apostrophes in strings — use alternative wording.
4. No trailing commas. Valid JSON only.
5. Output ONLY the JSON object."""

    return system, user


# ──────────────────────────────────────────────
# JSON CLEANER
# ──────────────────────────────────────────────

def clean_json(raw: str) -> dict:
    raw = raw.strip()
    for fence in ["```json", "```"]:
        if fence in raw:
            raw = raw.split(fence, 1)[-1].split("```")[0]
    raw = raw.strip()
    s, e = raw.find("{"), raw.rfind("}")
    if s != -1 and e != -1:
        raw = raw[s:e+1]

    # Fix common AI JSON mistakes
    raw = re.sub(r',(\s*[}\]])', r'\1', raw)          # trailing commas
    raw = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', raw)  # control chars
    raw = raw.replace('\u2019', "'").replace('\u2018', "'")   # smart quotes -> straight
    raw = raw.replace('\u201c', '"').replace('\u201d', '"')

    return json.loads(raw)


# ──────────────────────────────────────────────
# CLAUDE API CALL
# ──────────────────────────────────────────────

async def call_claude(system: str, user: str, model: str) -> str:
    async with httpx.AsyncClient(timeout=90) as client:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 3500,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
    if r.status_code != 200:
        raise Exception(f"Claude API {r.status_code}: {r.text[:300]}")
    return "".join(b["text"] for b in r.json().get("content", []) if b.get("type") == "text")


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.post("/api/analyze")
async def analyze(req: ReviewRequest):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(500, "ANTHROPIC_API_KEY not set in Railway Variables.")

    # Fetch live data in parallel
    nvd_cves, kev_entries = await asyncio.gather(
        fetch_nvd_cves(req.app_name, 15),
        fetch_cisa_kev(req.app_name),
    )
    epss_data = await fetch_epss([c["cve_id"] for c in nvd_cves[:15]])

    live = {"nvd_cves": nvd_cves, "kev": kev_entries, "epss": epss_data}
    system, user = build_prompt(req, live)

    # Try models in order
    raw = None
    for model in [MODEL_PRIMARY, MODEL_FALLBACK, MODEL_FALLBACK2]:
        try:
            raw = await call_claude(system, user, model)
            break
        except Exception as e:
            print(f"Model {model} failed: {e}")
            continue

    if not raw:
        raise HTTPException(503, "All Claude models failed. Please try again.")

    # Parse with fallback
    result = None
    try:
        result = clean_json(raw)
    except json.JSONDecodeError:
        # Ask Claude to fix it
        try:
            fix_raw = await call_claude(
                "You are a JSON repair tool. Return ONLY valid JSON, nothing else.",
                f"Fix this malformed JSON and return only the corrected JSON:\n{raw[:3000]}",
                MODEL_FALLBACK2,
            )
            result = clean_json(fix_raw)
        except Exception:
            pass

    # Ultimate fallback
    if result is None:
        result = {
            "verdict": "CONDITIONAL",
            "verdict_reason": f"Manual review required for {req.app_name} — automated analysis encountered an issue.",
            "risk_score": 50, "cvss_estimate": 5.0,
            "cve_count_estimate": len(nvd_cves),
            "exploit_maturity": "Active Exploitation" if kev_entries else "Proof of Concept",
            "actively_exploited": len(kev_entries) > 0,
            "kev_count": len(kev_entries),
            "risk_dimensions": {"vulnerability_history":60,"supply_chain_risk":50,"data_exposure_risk":55,"regulatory_compliance_risk":50,"threat_actor_interest":45,"malware_distribution_risk":40},
            "executive_summary": f"Live vulnerability data retrieved for {req.app_name}. Manual review of the CVE list below is recommended.",
            "known_vulnerabilities": [],
            "malware_intelligence": {"known_malware_campaigns": "See threat intelligence sources for current campaigns.", "supply_chain_incidents": "Verify download integrity before installation.", "trojanized_distributions": "Download only from official vendor sources."},
            "threat_intelligence": "Review CISA KEV and NVD entries below for current threat status.",
            "download_recommendations": {"official_source": f"Visit the official {req.app_name} website.", "verification_method": "Check checksums/signatures provided by the vendor.", "avoid_sources": "Avoid third-party download sites and unofficial mirrors."},
            "conditions": ["Apply latest security patches", "Restrict to authorised users", "Enable audit logging"],
            "remediation_actions": ["Update to latest version", "Enable endpoint monitoring", "Review access controls"],
            "regulatory_note": "Standard GDPR, SOC 2, and ISO 27001 compliance review recommended.",
        }

    # Validate & coerce types
    result["verdict"] = str(result.get("verdict", "CONDITIONAL")).upper()
    if result["verdict"] not in ("APPROVE", "DENY", "CONDITIONAL"):
        result["verdict"] = "CONDITIONAL"
    for k in ["risk_score", "cvss_estimate", "cve_count_estimate"]:
        try:
            result[k] = float(result.get(k, 0))
        except (ValueError, TypeError):
            result[k] = 0.0

    # Attach live data (already sorted newest-first)
    result["_live_data"] = {
        "nvd_cve_count": len(nvd_cves),
        "kev_count":     len(kev_entries),
        "kev_entries":   kev_entries[:5],
        "latest_cves":   nvd_cves[:12],   # already sorted newest-first
        "epss_data":     epss_data,
        "fetched_at":    datetime.now().isoformat(),
    }
    return result


@app.get("/api/health")
async def health():
    return {
        "status":       "ok" if ANTHROPIC_API_KEY else "no_key",
        "engine":       "anthropic",
        "data_sources": ["NIST NVD", "CISA KEV", "FIRST EPSS", "Claude AI"],
        "api_key_set":  bool(ANTHROPIC_API_KEY),
    }
