import boto3
import json
import re
import time
from botocore.exceptions import ClientError
from rich.console import Console
from config import (
    AWS_REGION, BEDROCK_SONNET, BEDROCK_HAIKU,
    BEDROCK_RETRY_ATTEMPTS, BEDROCK_RETRY_DELAY
)

console = Console()
_client = None


def _get_client():
    global _client
    if _client is None:
        _client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    return _client


def _invoke(prompt: str, model_id: str = None, max_tokens: int = 1500) -> str:
    """Core invoke with exponential backoff retry."""
    model_id = model_id or BEDROCK_HAIKU
    client   = _get_client()

    for attempt in range(BEDROCK_RETRY_ATTEMPTS):
        try:
            resp = client.invoke_model(
                modelId=model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            result = json.loads(resp["body"].read())
            return result["content"][0]["text"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ThrottlingException", "ServiceUnavailableException"):
                wait = BEDROCK_RETRY_DELAY * (2 ** attempt)
                console.print(f"[yellow]Bedrock throttle — retry {attempt+1} in {wait}s[/yellow]")
                time.sleep(wait)
            else:
                console.print(f"[red]Bedrock error ({code}): {e}[/red]")
                return ""
    return ""


def _parse_json(text: str) -> dict | list:
    """Parse JSON from model output; fallback to regex extraction."""
    text = text.strip()
    # Strip markdown fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to extract first JSON object or array
        m = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
    return {}


# ── Analysis functions ─────────────────────────────────────────────────────────

def analyze_js(js_content: str, js_url: str) -> dict:
    """
    Analyze a JS file for security-relevant patterns.
    Uses Haiku for cost; returns structured dict.
    """
    prompt = f"""You are a security researcher doing bug bounty recon. Analyze this JavaScript file.

URL: {js_url}

Find:
1. Hidden/undocumented API endpoints (REST paths, GraphQL operations)
2. Hardcoded secrets (API keys, tokens, passwords, AWS keys)
3. Client-side authorization checks bypassable by JS manipulation
4. Internal hostnames, S3 bucket names, cloud resource identifiers
5. Debug/admin routes conditionally rendered in JS
6. IDOR patterns: user IDs, UUIDs, object references in requests
7. Interesting function names hinting at sensitive operations (deleteUser, adminPanel, etc.)

Return ONLY valid JSON (no markdown):
{{
  "endpoints": ["list of discovered paths"],
  "secrets": [{{"type": "api_key|token|password", "value_hint": "first 8 chars...", "context": "variable name"}}],
  "auth_bypasses": ["description of each"],
  "interesting_functions": ["functionName: brief reason"],
  "idor_patterns": ["description"],
  "risk_summary": "high|medium|low|none",
  "notable_notes": "brief overall observation"
}}

JS Content (truncated):
{js_content}"""

    raw = _invoke(prompt, model_id=BEDROCK_HAIKU, max_tokens=1200)
    result = _parse_json(raw)
    if not result:
        return {"risk_summary": "none", "endpoints": [], "secrets": []}
    return result


def triage_http(url: str, request_snippet: str, response_snippet: str) -> dict:
    """
    Triage an HTTP exchange for vulnerability indicators.
    Uses Haiku for bulk; high-risk results get re-analyzed with Sonnet.
    """
    prompt = f"""You are a bug bounty analyst. Triage this HTTP exchange.

URL: {url}

Flag for:
- IDOR / BOLA (accessing other users' resources via predictable IDs)
- Broken auth (sensitive data returned without Authorization header)
- SSRF (URL, redirect, webhook, or import parameters)
- Mass assignment (API accepts unexpected sensitive fields)
- Missing rate-limiting on sensitive endpoints
- Sensitive data exposure (PII, keys, internal IPs in response)
- CORS misconfiguration (permissive Access-Control-Allow-Origin)
- Missing security headers (HSTS, X-Frame-Options, CSP)
- Server errors exposing stack traces / internal paths
- Unauthenticated access to privileged functionality

REQUEST:
{request_snippet}

RESPONSE:
{response_snippet}

Return ONLY valid JSON (no markdown):
{{
  "risk": "critical|high|medium|low|none",
  "vuln_class": "IDOR|SSRF|AuthBypass|MassAssignment|InfoDisclosure|CORS|etc or null",
  "title": "short finding title",
  "description": "what exactly is suspicious",
  "recommended_test": "next manual step to confirm",
  "confidence": "high|medium|low"
}}"""

    raw = _invoke(prompt, model_id=BEDROCK_HAIKU, max_tokens=600)
    result = _parse_json(raw)
    if not isinstance(result, dict):
        return {"risk": "none"}

    # Escalate high/critical to Sonnet for deeper analysis
    if result.get("risk") in ("critical", "high"):
        console.print(f"  [bold red]↑ Escalating to Sonnet:[/bold red] {result.get('title')}")
        detailed_prompt = prompt + f"\n\nPrevious Haiku assessment: {json.dumps(result)}\n\nProvide deeper analysis. Same JSON format, same fields."
        raw2 = _invoke(detailed_prompt, model_id=BEDROCK_SONNET, max_tokens=1000)
        result2 = _parse_json(raw2)
        if result2:
            result = result2

    return result


def generate_nuclei_template(title: str, endpoint: str, description: str) -> str:
    """Generate a Nuclei v3 YAML template from a finding description."""
    prompt = f"""Generate a production-ready Nuclei v3 YAML template.

Finding title: {title}
Target endpoint pattern: {endpoint}
Description: {description}

Requirements:
- Valid Nuclei v3 YAML syntax
- id, info (name, author, severity, tags, description)
- Appropriate HTTP request with safe detection payload (no destructive payloads)
- Matchers (status code + word/regex on response body or headers)
- If applicable, include extractors to capture interesting values

Return ONLY raw YAML, no markdown fences, no explanation."""

    return _invoke(prompt, model_id=BEDROCK_SONNET, max_tokens=1500)


def draft_report(finding: dict) -> str:
    """
    Draft a HackerOne-quality bug report from a finding dict.
    Uses Sonnet for quality.
    """
    prompt = f"""Draft a professional HackerOne bug report from this finding.

Finding data:
{json.dumps(finding, indent=2)}

Structure the report as:
## Summary
One-paragraph executive summary.

## Vulnerability Details
Technical explanation (type, root cause, affected component).

## Steps to Reproduce
Numbered, exact, reproducible steps. Include sample curl or HTTP request.

## Proof of Concept
Minimal PoC demonstrating the vulnerability.

## Impact
Concrete business/security impact (data exposure, account takeover, etc.).

## Remediation
Specific, actionable fix recommendation.

## CVSS v3.1
Score and vector string.

Write in clear, professional English. Be precise and concise."""

    return _invoke(prompt, model_id=BEDROCK_SONNET, max_tokens=2000)
