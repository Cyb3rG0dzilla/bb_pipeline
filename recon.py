import subprocess
import json
import re
import shutil
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qsl, urlencode
from rich.console import Console
from config import (
    MAX_SUBDOMAINS, MAX_ENDPOINTS, SKIP_EXTENSIONS,
    INTERESTING_PATTERNS, JS_SKIP_PATTERNS, HTTPX_BIN,
    AMASS_TIMEOUT, MAX_ARJUN_TARGETS, ARJUN_THREADS,
    ARJUN_REQUEST_TIMEOUT, ARJUN_TIMEOUT, ARJUN_PARAM_VALUE
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


_FQDN_RE_CACHE: dict[str, re.Pattern] = {}


def _subdomain_pattern(domain: str) -> re.Pattern:
    """Regex matching `domain` or any `*.domain` token, with word boundaries
    so e.g. 'evil-domain.com' or 'notdomain.com' don't false-match 'domain.com'."""
    if domain not in _FQDN_RE_CACHE:
        _FQDN_RE_CACHE[domain] = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            + re.escape(domain) + r'\b',
            re.IGNORECASE
        )
    return _FQDN_RE_CACHE[domain]


def run_amass(domain: str) -> list[str]:
    """
    Passive subdomain enum via OWASP Amass — uses a different source mix than
    subfinder, so it often surfaces additional names. 'amass enum -passive -d'
    is the well-documented base command; everything past that is handled
    defensively (see config.AMASS_TIMEOUT comment): no -silent flag is passed
    (unconfirmed for v4), output is parsed via regex regardless of format
    (v4 prints graph edges, not bare hostnames), and the subprocess timeout
    (with partial-output capture) is the real time bound, not any amass flag.
    """
    if not _tool_available("amass"):
        console.print("  [yellow]  ⚠ amass not found — skipping (optional)[/yellow]")
        return []

    console.print(f"  [cyan]amass[/cyan] → {domain} (passive)")
    out = _run(["amass", "enum", "-passive", "-d", domain], timeout=AMASS_TIMEOUT)
    pattern = _subdomain_pattern(domain)
    subs = sorted({m.group(0).lower() for m in pattern.finditer(out)})
    console.print(f"  Found [bold]{len(subs)}[/bold] subdomains (amass)")
    return subs


def merge_and_cap_subdomains(*lists: list[str]) -> list[str]:
    """Union multiple subdomain lists, dedupe, cap to MAX_SUBDOMAINS."""
    combined = sorted(set().union(*(set(l) for l in lists)))
    if len(combined) > MAX_SUBDOMAINS:
        console.print(f"  [yellow]Combined: capping {len(combined)} → {MAX_SUBDOMAINS}[/yellow]")
        combined = combined[:MAX_SUBDOMAINS]
    return combined


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


# ── Hidden parameter discovery (Arjun) ──────────────────────────────────────────

def run_arjun(urls: list[str]) -> dict[str, list[str]]:
    """
    Discover hidden GET parameters on the highest-priority endpoints via Arjun.
    `urls` should already be prioritized — only the first MAX_ARJUN_TARGETS are
    probed (each costs ~50-60 requests with Arjun's default wordlist).
    Returns {url: [param_name, ...]}. Confirmed -oJ format:
    {"<url>": {"method": "...", "params": [{"name": "...", "reason": "..."}]}}
    """
    if not urls:
        return {}

    if not _tool_available("arjun"):
        console.print("  [yellow]  ⚠ arjun not found — skipping (optional)[/yellow]")
        return {}

    targets = urls[:MAX_ARJUN_TARGETS]
    console.print(f"  [cyan]arjun[/cyan] → {len(targets)} endpoint(s) "
                  f"(~{len(targets) * 60} req budget)")

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp_in = f.name
    tmp_out = tempfile.mktemp(suffix=".json")

    try:
        _run([
            "arjun", "-i", tmp_in, "-oJ", tmp_out,
            "-t", str(ARJUN_THREADS),
            "-T", str(ARJUN_REQUEST_TIMEOUT),
            "--stable",
        ], timeout=ARJUN_TIMEOUT)
    finally:
        os.unlink(tmp_in)

    results: dict[str, list[str]] = {}
    if os.path.exists(tmp_out):
        try:
            with open(tmp_out) as f:
                data = json.load(f)
            for url, info in data.items():
                params = [p.get("name") for p in info.get("params", []) if p.get("name")]
                if params:
                    results[url] = params
        except (json.JSONDecodeError, AttributeError):
            pass
        finally:
            os.unlink(tmp_out)

    console.print(f"  Params found on [bold]{len(results)}[/bold]/{len(targets)} endpoint(s)")
    return results


def build_arjun_augmented_urls(param_map: dict[str, list[str]]) -> list[str]:
    """
    For each discovered hidden param, build a URL with that param appended
    (?param=ARJUN_PARAM_VALUE) so HTTP triage can inspect the *changed*
    response — this is what surfaces e.g. ?debug=1 or ?role=admin behavior.
    """
    augmented = []
    for url, params in param_map.items():
        parts = urlsplit(url)
        existing = dict(parse_qsl(parts.query))
        for p in params:
            if p in existing:
                continue
            new_q = {**existing, p: ARJUN_PARAM_VALUE}
            augmented.append(urlunsplit((
                parts.scheme, parts.netloc, parts.path,
                urlencode(new_q), parts.fragment
            )))
    return augmented