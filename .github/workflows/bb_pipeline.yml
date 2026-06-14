#!/usr/bin/env python3
"""
bb_pipeline — AI-powered Bug Bounty recon + analysis pipeline
Uses AWS Bedrock (Claude) + Supabase + ProjectDiscovery toolchain

Usage:
  # Single domain
  python pipeline.py --program "h1/target" --domain target.com

  # Multiple domains (comma-separated)
  python pipeline.py --program "h1/target" --domain "target.com,target.in,target-cdn.com"

  # Multiple domains from a file (one per line, # comments allowed)
  python pipeline.py --program "h1/target" --domains-file scope.txt

  # Specific phases only
  python pipeline.py --program "h1/target" --domain target.com --phases recon,crawl,js,http,nuclei,report
"""

import click
import sys
from rich.console import Console
from rich.rule import Rule

import recon as recon_module
import analyzers
import nuclei as nuclei_module
import reporter
import db

console = Console()

VALID_PHASES = ["recon", "crawl", "js", "http", "nuclei", "report"]


def validate_phases(phases_str: str) -> list[str]:
    phases = [p.strip().lower() for p in phases_str.split(",")]
    invalid = [p for p in phases if p not in VALID_PHASES]
    if invalid:
        console.print(f"[red]Invalid phases: {invalid}. Valid: {VALID_PHASES}[/red]")
        sys.exit(1)
    return phases


def resolve_domains(domain: str | None, domains_file: str | None) -> list[str]:
    """Build a deduplicated, order-preserving domain list from --domain and/or --domains-file."""
    domains: list[str] = []

    if domain:
        domains.extend(d.strip() for d in domain.split(",") if d.strip())

    if domains_file:
        try:
            with open(domains_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.append(line)
        except OSError as e:
            console.print(f"[red]Could not read --domains-file: {e}[/red]")
            sys.exit(1)

    seen = set()
    deduped = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            deduped.append(d)
    return deduped


@click.command()
@click.option("--program",          required=True, help="Program name, e.g. 'hackerone/target'")
@click.option("--domain",           default=None,
              help="Root domain(s) to scan. Comma-separated for multiple, "
                   "e.g. 'target.com,target.in'")
@click.option("--domains-file",     default=None,
              help="Path to .txt file, one domain per line (# comments allowed). "
                   "Combines with --domain if both given.")
@click.option("--platform",         default="hackerone", help="Platform (hackerone/bugcrowd/intigriti)")
@click.option("--phases",           default="recon,crawl,js,http,nuclei,report",
              help="Comma-separated phases to run")
@click.option("--subdomains-file",  default=None,
              help="Optional: pre-built subdomains list (.txt). Single-domain runs only.")
@click.option("--urls-file",        default=None,
              help="Optional: pre-built URLs list (.txt). Single-domain runs only.")
@click.option("--output-dir",       default="reports", help="Directory for report output")
def main(program, domain, domains_file, platform, phases, subdomains_file, urls_file, output_dir):
    phases  = validate_phases(phases)
    domains = resolve_domains(domain, domains_file)

    if not domains:
        console.print("[red]No domains provided. Use --domain and/or --domains-file.[/red]")
        sys.exit(1)

    if len(domains) > 1 and (subdomains_file or urls_file):
        console.print("[red]--subdomains-file / --urls-file are single-domain only "
                       "and cannot be combined with multiple --domain values.[/red]")
        sys.exit(1)

    domain_label = f"{len(domains)} domain" + ("s" if len(domains) != 1 else "")

    console.print()
    console.rule(f"[bold cyan]bb_pipeline[/bold cyan]  |  {program}  |  {domain_label}")
    console.print(f"  Domains: [bold]{', '.join(domains)}[/bold]")
    console.print(f"  Phases:  [bold]{', '.join(phases)}[/bold]")
    console.print()

    # ── Init program in DB ─────────────────────────────────────────────────────
    try:
        program_id = db.get_or_create_program(program, platform)
        console.print(f"  Program ID: [dim]{program_id}[/dim]")
    except Exception as e:
        console.print(f"[red]DB init failed: {e}[/red]")
        console.print("[yellow]Tip: Check SUPABASE_URL/SUPABASE_KEY and run schema.sql first[/yellow]")
        sys.exit(1)

    all_live_hosts: list[str]      = []
    all_target_map: dict[str, str] = {}
    report_paths:   list[str]      = []

    # ──────────────────────────────────────────────────────────────────────────
    # Per-domain phases: recon, crawl, js, http
    # ──────────────────────────────────────────────────────────────────────────
    for i, current_domain in enumerate(domains, 1):
        if len(domains) > 1:
            console.print()
            console.rule(f"[bold magenta]══ {current_domain}  ({i}/{len(domains)}) ══[/bold magenta]")

        live_hosts    = []
        domain_urls   = []
        js_urls       = []
        target_id_map = {}

        # ── PHASE 1: RECON — subfinder + httpx ──────────────────────────────────
        if "recon" in phases:
            console.print(Rule("[bold]Phase 1: Recon[/bold]"))

            if subdomains_file:
                console.print(f"  Using pre-built subdomains: {subdomains_file}")
                with open(subdomains_file) as f:
                    subdomains = [l.strip() for l in f if l.strip()]
            else:
                subdomains = recon_module.run_subfinder(current_domain)

            if not subdomains:
                console.print(f"  [yellow]No subdomains found — using root domain only[/yellow]")
                subdomains = [current_domain]

            host_data  = recon_module.run_httpx(subdomains)
            live_hosts = [h["url"] for h in host_data if h.get("url")]

            for h in host_data:
                tid = db.store_target(
                    program_id,
                    domain=current_domain,
                    subdomain=h.get("input"),
                    url=h.get("url"),
                    status_code=h.get("status_code"),
                    title=h.get("title"),
                    tech_stack=h.get("tech", []),
                )
                if tid and h.get("url"):
                    target_id_map[h["url"]] = tid

            console.print(f"  Live: [bold green]{len(live_hosts)}[/bold green] hosts")

        # ── PHASE 2: CRAWL — katana + gau ────────────────────────────────────────
        if "crawl" in phases:
            console.print(Rule("[bold]Phase 2: Crawl[/bold]"))

            if urls_file:
                console.print(f"  Using pre-built URLs: {urls_file}")
                with open(urls_file) as f:
                    domain_urls = [l.strip() for l in f if l.strip()]
            else:
                if not live_hosts:
                    console.print("  [yellow]No live hosts — load recon phase first[/yellow]")
                else:
                    katana_urls = recon_module.run_katana(live_hosts)
                    gau_urls    = recon_module.run_gau(current_domain)
                    domain_urls = list(set(katana_urls + gau_urls))

            js_urls     = recon_module.extract_js_urls(domain_urls)
            domain_urls = recon_module.prioritize_endpoints(domain_urls)
            console.print(f"  Total unique endpoints: [bold]{len(domain_urls)}[/bold]")

        # ── PHASE 3: JS ANALYSIS — Bedrock Haiku ─────────────────────────────────
        if "js" in phases:
            console.print(Rule("[bold]Phase 3: JS Analysis[/bold]"))
            if not js_urls:
                console.print("  [yellow]No JS URLs collected — run crawl phase first[/yellow]")
            else:
                analyzers.analyze_js_files(js_urls, program_id)

        # ── PHASE 4: HTTP TRIAGE — Bedrock Haiku → Sonnet for high/critical ──────
        if "http" in phases:
            console.print(Rule("[bold]Phase 4: HTTP Triage[/bold]"))
            if not domain_urls:
                console.print("  [yellow]No endpoints — run crawl phase first[/yellow]")
            else:
                analyzers.triage_http_endpoints(domain_urls, program_id)

        all_live_hosts.extend(live_hosts)
        all_target_map.update(target_id_map)

    # ──────────────────────────────────────────────────────────────────────────
    # Combined phases: nuclei, report — run once across all domains
    # ──────────────────────────────────────────────────────────────────────────
    if "nuclei" in phases:
        console.print()
        console.rule("[bold]Phase 5: Nuclei Scan[/bold]")
        if not all_live_hosts:
            console.print("  [yellow]No live hosts across any domain — run recon phase first[/yellow]")
        else:
            nuclei_findings = nuclei_module.run_nuclei(
                all_live_hosts, program_id, all_target_map
            )
            nuclei_module.generate_templates_for_findings(
                nuclei_findings, output_dir=f"{output_dir}/templates"
            )

    if "report" in phases:
        console.print()
        console.rule("[bold]Phase 6: Report Generation[/bold]")
        report_paths = reporter.generate_reports(program_id, output_dir=output_dir)

    # ── Final summary ──────────────────────────────────────────────────────────
    reporter.print_summary(program_id, program)
    if "report" in phases:
        if report_paths:
            console.print(f"\n  {len(report_paths)} report(s) saved to: [bold]{output_dir}/[/bold]")
        else:
            console.print(f"\n  No reports generated — no pending high/critical findings yet")
    console.print()


if __name__ == "__main__":
    main()