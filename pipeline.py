#!/usr/bin/env python3
"""
bb_pipeline — AI-powered Bug Bounty recon + analysis pipeline
Uses AWS Bedrock (Claude) + Supabase + ProjectDiscovery toolchain

Usage:
  python pipeline.py --program "h1/target" --domain target.com
  python pipeline.py --program "h1/target" --domain target.com --phases recon,js,nuclei,report
  python pipeline.py --program "h1/target" --domain target.com --subdomains-file subs.txt
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


@click.command()
@click.option("--program",          required=True, help="Program name, e.g. 'hackerone/target'")
@click.option("--domain",           required=True, help="Root domain to scan, e.g. target.com")
@click.option("--platform",         default="hackerone", help="Platform (hackerone/bugcrowd/intigriti)")
@click.option("--phases",           default="recon,crawl,js,http,nuclei,report",
              help="Comma-separated phases to run")
@click.option("--subdomains-file",  default=None, help="Optional: pre-built subdomains list (.txt)")
@click.option("--urls-file",        default=None, help="Optional: pre-built URLs list (.txt)")
@click.option("--output-dir",       default="reports", help="Directory for report output")
def main(program, domain, platform, phases, subdomains_file, urls_file, output_dir):
    phases = validate_phases(phases)

    console.print()
    console.rule(f"[bold cyan]bb_pipeline[/bold cyan]  |  {program}  |  {domain}")
    console.print(f"  Phases: [bold]{', '.join(phases)}[/bold]")
    console.print()

    # ── Init program in DB ─────────────────────────────────────────────────────
    try:
        program_id = db.get_or_create_program(program, platform)
        console.print(f"  Program ID: [dim]{program_id}[/dim]")
    except Exception as e:
        console.print(f"[red]DB init failed: {e}[/red]")
        console.print("[yellow]Tip: Check SUPABASE_URL/SUPABASE_KEY and run schema.sql first[/yellow]")
        sys.exit(1)

    live_hosts   = []
    all_urls     = []
    js_urls      = []
    target_id_map = {}

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 1: RECON — subfinder + httpx
    # ──────────────────────────────────────────────────────────────────────────
    if "recon" in phases:
        console.print(Rule("[bold]Phase 1: Recon[/bold]"))

        if subdomains_file:
            console.print(f"  Using pre-built subdomains: {subdomains_file}")
            with open(subdomains_file) as f:
                subdomains = [l.strip() for l in f if l.strip()]
        else:
            subdomains = recon_module.run_subfinder(domain)

        if not subdomains:
            console.print(f"  [yellow]No subdomains found — using root domain only[/yellow]")
            subdomains = [domain]

        # Probe for live hosts
        host_data = recon_module.run_httpx(subdomains)
        live_hosts = [h["url"] for h in host_data if h.get("url")]

        # Store targets in Supabase
        for h in host_data:
            tid = db.store_target(
                program_id,
                domain=domain,
                subdomain=h.get("input"),
                url=h.get("url"),
                status_code=h.get("status_code"),
                title=h.get("title"),
                tech_stack=h.get("tech", []),
            )
            if tid and h.get("url"):
                target_id_map[h["url"]] = tid

        console.print(f"  Live: [bold green]{len(live_hosts)}[/bold green] hosts")

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 2: CRAWL — katana + gau
    # ──────────────────────────────────────────────────────────────────────────
    if "crawl" in phases:
        console.print(Rule("[bold]Phase 2: Crawl[/bold]"))

        if urls_file:
            console.print(f"  Using pre-built URLs: {urls_file}")
            with open(urls_file) as f:
                all_urls = [l.strip() for l in f if l.strip()]
        else:
            if not live_hosts:
                console.print("  [yellow]No live hosts — load recon phase first[/yellow]")
            else:
                katana_urls = recon_module.run_katana(live_hosts)
                gau_urls    = recon_module.run_gau(domain)
                all_urls    = list(set(katana_urls + gau_urls))

        js_urls = recon_module.extract_js_urls(all_urls)
        all_urls = recon_module.prioritize_endpoints(all_urls)
        console.print(f"  Total unique endpoints: [bold]{len(all_urls)}[/bold]")

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 3: JS ANALYSIS — Bedrock Haiku
    # ──────────────────────────────────────────────────────────────────────────
    if "js" in phases:
        console.print(Rule("[bold]Phase 3: JS Analysis[/bold]"))
        if not js_urls:
            console.print("  [yellow]No JS URLs collected — run crawl phase first[/yellow]")
        else:
            analyzers.analyze_js_files(js_urls, program_id)

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 4: HTTP TRIAGE — Bedrock Haiku → Sonnet for high/critical
    # ──────────────────────────────────────────────────────────────────────────
    if "http" in phases:
        console.print(Rule("[bold]Phase 4: HTTP Triage[/bold]"))
        if not all_urls:
            console.print("  [yellow]No endpoints — run crawl phase first[/yellow]")
        else:
            analyzers.triage_http_endpoints(all_urls, program_id)

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 5: NUCLEI — automated vuln scanning + custom template gen
    # ──────────────────────────────────────────────────────────────────────────
    if "nuclei" in phases:
        console.print(Rule("[bold]Phase 5: Nuclei Scan[/bold]"))
        if not live_hosts:
            console.print("  [yellow]No live hosts — run recon phase first[/yellow]")
        else:
            nuclei_findings = nuclei_module.run_nuclei(
                live_hosts, program_id, target_id_map
            )
            # Generate custom templates for findings without one
            nuclei_module.generate_templates_for_findings(
                nuclei_findings, output_dir=f"{output_dir}/templates"
            )

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 6: REPORT — draft HackerOne reports for high/critical
    # ──────────────────────────────────────────────────────────────────────────
    if "report" in phases:
        console.print(Rule("[bold]Phase 6: Report Generation[/bold]"))
        reporter.generate_reports(program_id, output_dir=output_dir)

    # ── Final summary ──────────────────────────────────────────────────────────
    reporter.print_summary(program_id, program)
    console.print(f"\n  Reports saved to: [bold]{output_dir}/[/bold]")
    console.print()


if __name__ == "__main__":
    main()
