import asyncio
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import bedrock
import db
from config import (
    MAX_JS_CHARS, MAX_HTTP_CHARS, MAX_JS_FILES,
    MAX_CONCURRENT_FETCH
)

console = Console()

FETCH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
    "Accept": "*/*",
}


# ── JS Analysis ────────────────────────────────────────────────────────────────

async def _fetch_js(client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore) -> tuple[str, str]:
    """Fetch JS file content; return (url, content). Empty string on failure."""
    async with sem:
        try:
            resp = await client.get(url, headers=FETCH_HEADERS, timeout=15, follow_redirects=True)
            if resp.status_code == 200:
                return url, resp.text[:MAX_JS_CHARS]
        except Exception:
            pass
        return url, ""


async def _fetch_all_js(js_urls: list[str]) -> list[tuple[str, str]]:
    """Concurrently fetch all JS files."""
    sem = asyncio.Semaphore(MAX_CONCURRENT_FETCH)
    async with httpx.AsyncClient(verify=False, http2=True) as client:
        tasks = [_fetch_js(client, url, sem) for url in js_urls]
        return await asyncio.gather(*tasks)


def analyze_js_files(js_urls: list[str], program_id: str, target_id: str = None) -> list[dict]:
    """
    Fetch and analyze JS files with Bedrock.
    Returns list of findings extracted from JS.
    """
    if not js_urls:
        return []

    # Cap to limit
    if len(js_urls) > MAX_JS_FILES:
        console.print(f"  [yellow]Capping JS analysis: {len(js_urls)} → {MAX_JS_FILES}[/yellow]")
        js_urls = js_urls[:MAX_JS_FILES]

    console.print(f"  Fetching [bold]{len(js_urls)}[/bold] JS files...")
    fetched = asyncio.run(_fetch_all_js(js_urls))

    findings = []
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("{task.completed}/{task.total}"),
        console=console
    ) as progress:
        task = progress.add_task("  Analyzing JS...", total=len(fetched))

        for url, content in fetched:
            progress.advance(task)
            if not content:
                continue

            result = bedrock.analyze_js(content, url)
            db.store_js_finding(program_id, url, result)

            risk = result.get("risk_summary", "none")
            if risk in ("high", "medium"):
                # Convert JS finding into BB finding record
                endpoints = result.get("endpoints", [])
                secrets   = result.get("secrets", [])
                bypasses  = result.get("auth_bypasses", [])

                if secrets:
                    finding = {
                        "finding_type": "js_exposure",
                        "vuln_class":   "SecretLeakage",
                        "risk":         "high",
                        "title":        f"Hardcoded secrets in JS: {url.split('/')[-1]}",
                        "description":  f"Found {len(secrets)} potential secret(s) in client-side JS.",
                        "endpoint":     url,
                        "evidence":     str(secrets)[:2000],
                        "ai_reasoning": result.get("notable_notes", ""),
                    }
                    fid = db.store_finding(program_id, target_id, finding)
                    findings.append({**finding, "id": fid, "source_url": url})

                if bypasses:
                    finding = {
                        "finding_type": "js_exposure",
                        "vuln_class":   "AuthBypass",
                        "risk":         "medium",
                        "title":        f"Client-side auth bypass in JS: {url.split('/')[-1]}",
                        "description":  "\n".join(bypasses),
                        "endpoint":     url,
                        "evidence":     str(bypasses)[:2000],
                        "ai_reasoning": result.get("notable_notes", ""),
                    }
                    fid = db.store_finding(program_id, target_id, finding)
                    findings.append({**finding, "id": fid, "source_url": url})

                if endpoints:
                    console.print(f"  [green]  ✓ {len(endpoints)} hidden endpoints found in {url.split('/')[-1]}[/green]")

    console.print(f"  JS analysis: [bold green]{len(findings)}[/bold green] findings")
    return findings


# ── HTTP Triage ────────────────────────────────────────────────────────────────

async def _fetch_http(
    client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore
) -> tuple[str, str, str]:
    """Fetch URL; return (url, request_repr, response_snippet)."""
    async with sem:
        try:
            req = client.build_request("GET", url, headers=FETCH_HEADERS)
            req_text = f"GET {req.url.path}{'?'+str(req.url.query) if req.url.query else ''} HTTP/1.1\n"
            req_text += f"Host: {req.url.host}\n"
            req_text += "\n".join(f"{k}: {v}" for k, v in req.headers.items())

            resp = await client.send(req, follow_redirects=True, timeout=12)
            resp_text = f"HTTP/1.1 {resp.status_code}\n"
            resp_text += "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            resp_text += "\n\n"
            resp_text += resp.text[:2000]  # body preview

            return url, req_text[:MAX_HTTP_CHARS], resp_text[:MAX_HTTP_CHARS]
        except Exception:
            return url, "", ""


def triage_http_endpoints(
    endpoints: list[str], program_id: str, target_id: str = None
) -> list[dict]:
    """
    Fetch and triage HTTP endpoints with Bedrock Haiku.
    High/critical findings are auto-escalated to Sonnet.
    """
    if not endpoints:
        return []

    console.print(f"  Triaging [bold]{len(endpoints)}[/bold] endpoints...")

    # Fetch all responses concurrently
    async def _fetch_batch():
        sem = asyncio.Semaphore(MAX_CONCURRENT_FETCH)
        async with httpx.AsyncClient(verify=False, http2=True) as client:
            tasks = [_fetch_http(client, url, sem) for url in endpoints]
            return await asyncio.gather(*tasks)

    exchanges = asyncio.run(_fetch_batch())

    findings = []
    skip_count = 0

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("{task.completed}/{task.total}"),
        console=console
    ) as progress:
        task = progress.add_task("  Triaging HTTP...", total=len(exchanges))

        for url, req_text, resp_text in exchanges:
            progress.advance(task)
            if not req_text or not resp_text:
                skip_count += 1
                continue

            result = bedrock.triage_http(url, req_text, resp_text)
            risk = result.get("risk", "none")

            if risk == "none":
                continue

            finding = {
                "finding_type": "http_anomaly",
                "vuln_class":   result.get("vuln_class"),
                "risk":         risk,
                "title":        result.get("title", f"HTTP anomaly at {url}"),
                "description":  result.get("description", ""),
                "endpoint":     url,
                "evidence":     req_text[:1000] + "\n---\n" + resp_text[:1000],
                "ai_reasoning": result.get("recommended_test", ""),
            }
            fid = db.store_finding(program_id, target_id, finding)
            findings.append({**finding, "id": fid})

            color = "red" if risk in ("critical", "high") else "yellow"
            console.print(f"  [[bold {color}]{risk.upper()}[/bold {color}]] {result.get('title', url)}")

    console.print(
        f"  HTTP triage: [bold green]{len(findings)}[/bold green] findings "
        f"({skip_count} unreachable skipped)"
    )
    return findings
