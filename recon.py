import subprocess
import json
import shutil
from urllib.parse import urlparse
from rich.console import Console
from config import (
    MAX_SUBDOMAINS, MAX_ENDPOINTS, SKIP_EXTENSIONS,
    INTERESTING_PATTERNS, JS_SKIP_PATTERNS, HTTPX_BIN
)

console = Console()


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int = 120) -> str:
    """Run a subprocess, return stdout. Warns if tool missing or exits non-zero."""
    if not _tool_available(cmd[0]):
        console.print(f"[yellow]  ⚠ Tool not found: {cmd[0]} — skipping[/yellow]")
        return ""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            stderr_lines = result.stderr.strip().splitlines()
            preview = stderr_lines[0][:200] if stderr_lines else f"exit code {result.returncode}"
            console.print(f"[red]  ✗ {cmd[0]} failed: {preview}[/red]")
        return result.stdout.strip()
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "").strip()
        if partial:
            console.print(
                f"[yellow]  ⚠ Timeout: {cmd[0]} after {timeout}s — "
                f"using {len(partial.splitlines())} line(s) captured before kill[/yellow]"
            )
            return partial
        console.print(f"[yellow]  ⚠ Timeout: {cmd[0]} after {timeout}s — no output captured[/yellow]")
        return ""
    except Exception as e:
        console.print(f"[red]  ✗ {cmd[0]} error: {e}[/red]")
        return ""


# ── Subdomain enumeration ──────────────────────────────────────────────────────

def run_subfinder(domain: str) -> list[str]:
    """Return list of discovered subdomains."""
    console.print(f"  [cyan]subfinder[/cyan] → {domain}")
    # -max-time bounds subfinder's own runtime (minutes) so it exits cleanly
    # and flushes results well before our subprocess timeout would kill it.
    # Dropped -all: with MAX_SUBDOMAINS capping output anyway, the curated
    # default source set is faster and avoids hanging on unconfigured /
    # rate-limited / DNS-blocked sources that -all pulls in.
    out = _run(["subfinder", "-d", domain, "-silent", "-max-time", "2"], timeout=180)
    subs = [s.strip() for s in out.splitlines() if s.strip()]
    if len(subs) > MAX_SUBDOMAINS:
        console.print(f"  [yellow]Capping {len(subs)} → {MAX_SUBDOMAINS} subdomains[/yellow]")
        subs = subs[:MAX_SUBDOMAINS]
    console.print(f"  Found [bold]{len(subs)}[/bold] subdomains")
    return subs


# ── Live host probing ──────────────────────────────────────────────────────────

def run_httpx(hosts: list[str]) -> list[dict]:
    """
    Probe hosts with httpx, return list of live host dicts:
    {url, status_code, title, tech, input}
    """
    if not hosts:
        return []
    console.print(f"  [cyan]httpx[/cyan] → probing {len(hosts)} hosts")

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        tmp = f.name

    try:
        out = _run([
            HTTPX_BIN, "-l", tmp,
            "-json", "-silent",
            "-sc", "-title", "-tech-detect",
            "-follow-redirects", "-timeout", "10",
            "-threads", "50"
        ], timeout=300)
    finally:
        os.unlink(tmp)

    results = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
            results.append({
                "url":         obj.get("url"),
                "status_code": obj.get("status-code"),
                "title":       obj.get("title"),
                "tech":        obj.get("tech", []),
                "input":       obj.get("input"),
            })
        except json.JSONDecodeError:
            continue

    console.print(f"  Found [bold]{len(results)}[/bold] live hosts")
    return results


# ── URL crawling ───────────────────────────────────────────────────────────────

def run_katana(urls: list[str]) -> list[str]:
    """Crawl live URLs with katana, return all discovered endpoints."""
    if not urls or not _tool_available("katana"):
        return []
    console.print(f"  [cyan]katana[/cyan] → crawling {len(urls)} hosts")

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(u for u in urls if u))
        tmp = f.name

    try:
        out = _run([
            "katana", "-list", tmp,
            "-silent", "-jc",          # -jc = JS file crawling
            "-depth", "3",
            "-c", "20",                # concurrency
            "-timeout", "10",
            "-output-format", "url"
        ], timeout=300)
    finally:
        os.unlink(tmp)

    endpoints = [u.strip() for u in out.splitlines() if u.strip()]
    console.print(f"  Crawled [bold]{len(endpoints)}[/bold] endpoints")
    return endpoints


def run_gau(domain: str) -> list[str]:
    """Get historical URLs from Wayback Machine + Common Crawl."""
    if not _tool_available("gau"):
        return []
    console.print(f"  [cyan]gau[/cyan] → {domain}")
    out = _run(["gau", "--blacklist", "png,jpg,gif,css,woff,woff2,ttf,svg,ico", domain], timeout=120)
    urls = [u.strip() for u in out.splitlines() if u.strip()]
    console.print(f"  Found [bold]{len(urls)}[/bold] historical URLs")
    return urls


# ── URL processing helpers ─────────────────────────────────────────────────────

def extract_js_urls(urls: list[str]) -> list[str]:
    """Filter JS file URLs, skip framework noise."""
    js_urls = []
    for url in urls:
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            if not path.endswith(".js"):
                continue
            if any(skip in path for skip in JS_SKIP_PATTERNS):
                continue
            js_urls.append(url)
        except Exception:
            continue
    # Deduplicate preserving order
    seen = set()
    result = []
    for u in js_urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
    console.print(f"  Extracted [bold]{len(result)}[/bold] JS files (framework noise filtered)")
    return result


def prioritize_endpoints(urls: list[str]) -> list[str]:
    """
    Sort endpoints by interest level.
    Interesting patterns → top; static assets → removed.
    """
    filtered = []
    for url in urls:
        try:
            path = urlparse(url).path.lower()
            ext = "." + path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
            if ext in SKIP_EXTENSIONS:
                continue
            filtered.append(url)
        except Exception:
            continue

    def score(url):
        path = urlparse(url).path.lower()
        for i, pattern in enumerate(INTERESTING_PATTERNS):
            if pattern in path:
                return i  # lower index = higher priority
        return len(INTERESTING_PATTERNS)

    sorted_urls = sorted(set(filtered), key=score)
    if len(sorted_urls) > MAX_ENDPOINTS:
        console.print(f"  [yellow]Capping {len(sorted_urls)} → {MAX_ENDPOINTS} endpoints[/yellow]")
        sorted_urls = sorted_urls[:MAX_ENDPOINTS]
    return sorted_urls