import os
from dotenv import load_dotenv

load_dotenv()

# ── AWS / Bedrock ──────────────────────────────────────────────────────────────
AWS_REGION      = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_SONNET  = "anthropic.claude-3-5-sonnet-20241022-v2:0"   # deep analysis
BEDROCK_HAIKU   = "anthropic.claude-3-haiku-20240307-v1:0"      # bulk triage

# ── Supabase ───────────────────────────────────────────────────────────────────
SUPABASE_URL    = os.getenv("SUPABASE_URL")
SUPABASE_KEY    = os.getenv("SUPABASE_KEY")

# ── External tool binaries ────────────────────────────────────────────────────
# 'httpx' collides with the Python 'httpx' package's own CLI entry point
# (Click-based), which sits ahead of ~/bb_tools on PATH inside the venv.
# Rename the ProjectDiscovery binary to 'pdhttpx' to disambiguate.
HTTPX_BIN       = os.getenv("HTTPX_BIN", "pdhttpx")

# ── Optional alerts ───────────────────────────────────────────────────────────
SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL")

# ── Pipeline limits ───────────────────────────────────────────────────────────
MAX_SUBDOMAINS          = 500   # cap per program to avoid runaway scans
MAX_ENDPOINTS           = 1000  # cap for HTTP triage
MAX_JS_FILES            = 100   # cap for JS analysis per run
MAX_JS_CHARS            = 14000 # ~3.5k tokens — safe Haiku input size
MAX_HTTP_CHARS          = 5000  # per req+resp pair for triage
MAX_CONCURRENT_FETCH    = 5     # async JS fetcher concurrency
BEDROCK_RETRY_ATTEMPTS  = 3
BEDROCK_RETRY_DELAY     = 5     # seconds between retries

# ── Nuclei ────────────────────────────────────────────────────────────────────
NUCLEI_SEVERITY     = "medium,high,critical"
NUCLEI_TEMPLATES    = "cves,misconfigs,exposures,takeovers,default-logins"

# ── Reporting threshold ───────────────────────────────────────────────────────
AUTO_REPORT_RISKS   = {"critical", "high"}

# ── JS file skip patterns (framework noise) ───────────────────────────────────
JS_SKIP_PATTERNS = [
    "jquery", "bootstrap", "angular", "react.", "vue.",
    "lodash", "moment", "polyfill", "webpack-runtime"
]

# ── HTTP endpoints to skip (static assets) ────────────────────────────────────
SKIP_EXTENSIONS = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
    ".pdf", ".zip", ".gz"
}

# ── Interesting endpoint patterns (prioritized for triage) ────────────────────
INTERESTING_PATTERNS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql",
    "/admin", "/internal", "/debug", "/health",
    "/user", "/account", "/profile", "/password",
    "/upload", "/export", "/import", "/download",
    "/token", "/auth", "/oauth", "/callback", "/webhook"
]

# ── Amass (optional passive subdomain source) ─────────────────────────────────
# v4 'enum' prints graph edges, not one-FQDN-per-line, and has no confirmed
# -silent/time-limit flag (and documented hang issues on some setups) — so we
# bound it purely via subprocess timeout (partial output is kept on kill) and
# regex-extract any *.{domain} tokens from whatever it prints.
AMASS_TIMEOUT = 120  # seconds

# ── Arjun (optional hidden-parameter discovery) ───────────────────────────────
# Expensive per-URL (~50-60 requests with the default wordlist) — capped hard
# and run only when 'params' is explicitly included in --phases.
MAX_ARJUN_TARGETS     = 20    # top-N prioritized endpoints to probe
ARJUN_THREADS         = 5     # concurrent requests (-t)
ARJUN_REQUEST_TIMEOUT = 10    # per-HTTP-request timeout, seconds (-T)
ARJUN_TIMEOUT         = 600   # subprocess-level overall timeout, seconds
ARJUN_PARAM_VALUE     = "1"   # value used when re-requesting with a discovered param